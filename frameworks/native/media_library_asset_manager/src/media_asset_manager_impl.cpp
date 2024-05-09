/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaAssetManagerImpl"

#include "media_asset_manager_impl.h"

#include <safe_map.h>
#include <securec.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <uuid.h>

#include "directory_ex.h"
#include "file_uri.h"
#include "iservice_registry.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "multistages_capture_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_tracer.h"

namespace OHOS {
namespace Media {
namespace {
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
} // namespace

using Uri = OHOS::Uri;

static const std::string MEDIA_ASSET_MANAGER_CLASS = "MediaAssetManagerImpl";
const std::string API_VERSION = "api_version";
static std::mutex multiStagesCaptureLock;

const int32_t LOW_QUALITY_IMAGE = 1;
const int32_t HIGH_QUALITY_IMAGE = 0;

const uint32_t MAX_URI_SIZE = 384;
const std::string ERROR_REQUEST_ID = "00000000-0000-0000-0000-000000000000";

static std::map<std::string, std::shared_ptr<MultiStagesTaskObserver>> multiStagesObserverMap;
static std::map<std::string, std::map<std::string, AssetHandler*>> inProcessUriMap;
static SafeMap<std::string, AssetHandler*> inProcessFastRequests;

static std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;

MediaLibraryManager* MediaAssetManagerImpl::mediaLibraryManager_ = nullptr;

std::shared_ptr<MediaAssetManager> MediaAssetManagerFactory::CreateMediaAssetManager()
{
    std::shared_ptr<MediaAssetManager> impl = std::make_shared<MediaAssetManagerImpl>();
    CHECK_AND_PRINT_LOG(impl != nullptr, "Failed to create MediaAssetManagerImpl instance.");

    return impl;
}

MediaAssetManagerImpl::MediaAssetManagerImpl()
{
    MediaAssetManagerImpl::mediaLibraryManager_ = MediaLibraryManager::GetMediaLibraryManager();
    CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
}

MediaAssetManagerImpl::~MediaAssetManagerImpl()
{
}

static void DeleteInProcessMapRecord(const std::string &requestUri, const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(multiStagesCaptureLock);
    if (inProcessUriMap.find(requestUri) == inProcessUriMap.end()) {
        return;
    }

    std::map<std::string, AssetHandler*> assetHandlers = inProcessUriMap[requestUri];
    if (assetHandlers.find(requestId) == assetHandlers.end()) {
        return;
    }

    assetHandlers.erase(requestId);
    if (!assetHandlers.empty()) {
        inProcessUriMap[requestUri] = assetHandlers;
        return;
    }

    inProcessUriMap.erase(requestUri);

    if (multiStagesObserverMap.find(requestUri) != multiStagesObserverMap.end()) {
        sDataShareHelper_->UnregisterObserverExt(Uri(requestUri),
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(multiStagesObserverMap[requestUri]));
    }
    multiStagesObserverMap.erase(requestUri);
}

static AssetHandler* CreateAssetHandler(const std::string &photoId, const std::string &requestId,
    const std::string &uri, const std::string &destUri, const MediaAssetDataHandlerPtr &handler)
{
    AssetHandler *assetHandler = new AssetHandler(photoId, requestId, uri, destUri, handler);
    MEDIA_DEBUG_LOG("[AssetHandler create] photoId: %{public}s, requestId: %{public}s, uri: %{public}s, %{public}p.",
        photoId.c_str(), requestId.c_str(), uri.c_str(), assetHandler);
    return assetHandler;
}

static void DeleteAssetHandlerSafe(AssetHandler *handler)
{
    if (handler != nullptr) {
        MEDIA_DEBUG_LOG("[AssetHandler delete] %{public}p.", handler);
        delete handler;
        handler = nullptr;
    }
}

static int32_t IsInProcessInMapRecord(const std::string &requestId, AssetHandler* &handler)
{
    std::lock_guard<std::mutex> lock(multiStagesCaptureLock);
    for (auto record : inProcessUriMap) {
        if (record.second.find(requestId) != record.second.end()) {
            handler = record.second[requestId];
            return true;
        }
    }

    return false;
}

static bool IsFastRequestCanceled(const std::string &requestId, std::string &photoId)
{
    AssetHandler *assetHandler = nullptr;
    if (!inProcessFastRequests.Find(requestId, assetHandler)) {
        MEDIA_ERR_LOG("requestId(%{public}s) not in progress.", requestId.c_str());
        return false;
    }

    if (assetHandler == nullptr) {
        MEDIA_ERR_LOG("assetHandler is nullptr.");
        return false;
    }
    photoId = assetHandler->photoId;
    inProcessFastRequests.Erase(requestId);
    return true;
}

static bool IsMapRecordCanceled(const std::string &requestId, std::string &photoId)
{
    AssetHandler *assetHandler = nullptr;
    if (!IsInProcessInMapRecord(requestId, assetHandler)) {
        MEDIA_ERR_LOG("requestId(%{public}s) not in progress.", requestId.c_str());
        return false;
    }

    if (assetHandler == nullptr) {
        MEDIA_ERR_LOG("assetHandler is nullptr.");
        return false;
    }
    photoId = assetHandler->photoId;
    DeleteInProcessMapRecord(assetHandler->requestUri, assetHandler->requestId);
    DeleteAssetHandlerSafe(assetHandler);
    return true;
}

static void DeleteDataHandler(NativeNotifyMode notifyMode, const std::string &requestUri, const std::string &requestId)
{
    MEDIA_INFO_LOG("Rmv %{public}d, %{public}s, %{public}s", notifyMode, requestUri.c_str(), requestId.c_str());
    if (notifyMode == NativeNotifyMode::WAIT_FOR_HIGH_QUALITY) {
        DeleteInProcessMapRecord(requestUri, requestId);
    }
    inProcessFastRequests.Erase(requestId);
}

static void InsertInProcessMapRecord(const std::string &requestUri, const std::string &requestId,
    AssetHandler *handler)
{
    std::lock_guard<std::mutex> lock(multiStagesCaptureLock);
    std::map<std::string, AssetHandler*> assetHandler;
    if (inProcessUriMap.find(requestUri) != inProcessUriMap.end()) {
        assetHandler = inProcessUriMap[requestUri];
        assetHandler[requestId] = handler;
        inProcessUriMap[requestUri] = assetHandler;
    } else {
        assetHandler[requestId] = handler;
        inProcessUriMap[requestUri] = assetHandler;
    }
}

static std::string GenerateRequestId()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

static AssetHandler* InsertDataHandler(NativeNotifyMode notifyMode,
    const unique_ptr<RequestSourceAsyncContext> &asyncContext)
{
    std::shared_ptr<CapiMediaAssetDataHandler> mediaAssetDataHandler = make_shared<CapiMediaAssetDataHandler>(
        asyncContext->onDataPreparedHandler, asyncContext->returnDataType, asyncContext->requestUri,
        asyncContext->destUri, asyncContext->requestOptions.sourceMode);

    mediaAssetDataHandler->SetNotifyMode(notifyMode);
    AssetHandler *assetHandler = CreateAssetHandler(asyncContext->photoId, asyncContext->requestId,
        asyncContext->requestUri, asyncContext->destUri, mediaAssetDataHandler);
    MEDIA_INFO_LOG("Add %{public}d, %{private}s, %{private}s, %{public}p", notifyMode,
        asyncContext->requestUri.c_str(), asyncContext->requestId.c_str(), assetHandler);

    switch (notifyMode) {
        case NativeNotifyMode::FAST_NOTIFY: {
            inProcessFastRequests.EnsureInsert(asyncContext->requestId, assetHandler);
            break;
        }
        case NativeNotifyMode::WAIT_FOR_HIGH_QUALITY: {
            InsertInProcessMapRecord(asyncContext->requestUri, asyncContext->requestId, assetHandler);
            break;
        }
        default:
            break;
    }

    return assetHandler;
}

MultiStagesCapturePhotoStatus MediaAssetManagerImpl::QueryPhotoStatus(int32_t fileId, std::string &photoId)
{
    photoId = "";
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Get sDataShareHelper_ failed");
        return MultiStagesCapturePhotoStatus::QUERY_INNER_FAIL;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    std::vector<std::string> fetchColumn { PhotoColumn::PHOTO_QUALITY, PhotoColumn::PHOTO_ID };
    Uri uri(PAH_QUERY_PHOTO);
    DataShare::DatashareBusinessError errCode;
    auto resultSet = sDataShareHelper_->Query(uri, predicates, fetchColumn, &errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        MEDIA_ERR_LOG("Query resultSet is nullptr");
        return MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    }

    int indexOfPhotoId = -1;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_ID, indexOfPhotoId);
    resultSet->GetString(indexOfPhotoId, photoId);

    int columnIndexQuality = -1;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_QUALITY, columnIndexQuality);
    int currentPhotoQuality = HIGH_QUALITY_IMAGE;
    resultSet->GetInt(columnIndexQuality, currentPhotoQuality);
    if (currentPhotoQuality == LOW_QUALITY_IMAGE) {
        MEDIA_ERR_LOG("Query photo status : lowQuality");
        return MultiStagesCapturePhotoStatus::LOW_QUALITY_STATUS;
    }
    MEDIA_ERR_LOG("Query photo status quality: %{public}d", currentPhotoQuality);
    return MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
}

bool MediaAssetManagerImpl::NotifyImageDataPrepared(AssetHandler *assetHandler)
{
    if (assetHandler == nullptr) {
        MEDIA_ERR_LOG("assetHandler is nullptr");
        return false;
    }

    std::lock_guard<std::mutex> lock(assetHandler->mutex_);
    auto dataHandler = assetHandler->dataHandler;
    if (dataHandler == nullptr) {
        MEDIA_ERR_LOG("Data handler is nullptr");
        DeleteAssetHandlerSafe(assetHandler);
        return false;
    }

    NativeNotifyMode notifyMode = dataHandler->GetNotifyMode();
    if (notifyMode == NativeNotifyMode::FAST_NOTIFY) {
        AssetHandler *tmp;
        if (!inProcessFastRequests.Find(assetHandler->requestId, tmp)) {
            MEDIA_ERR_LOG("The request has been canceled");
            DeleteAssetHandlerSafe(assetHandler);
            return false;
        }
    }

    int32_t writeResult = E_OK;
    if (dataHandler->GetReturnDataType() == ReturnDataType::TYPE_TARGET_FILE) {
        writeResult = MediaAssetManagerImpl::WriteFileToPath(dataHandler->GetRequestUri(), dataHandler->GetDestUri(),
            dataHandler->GetSourceMode() == NativeSourceMode::ORIGINAL_MODE);
        Native_RequestId requestId;
        strncpy_s(requestId.requestId, UUID_STR_LENGTH, assetHandler->requestId.c_str(), UUID_STR_LENGTH);
        if (dataHandler->onDataPreparedHandler_ != nullptr) {
            dataHandler->onDataPreparedHandler_(writeResult, requestId);
        }
    } else {
        MEDIA_ERR_LOG("Return mode type invalid %{public}d", dataHandler->GetReturnDataType());
        return false;
    }

    DeleteDataHandler(notifyMode, assetHandler->requestUri, assetHandler->requestId);
    MEDIA_INFO_LOG("Delete assetHandler: %{public}p", assetHandler);
    DeleteAssetHandlerSafe(assetHandler);
    return true;
}

void MediaAssetManagerImpl::CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }
    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
        if (sDataShareHelper_ == nullptr) {
            MEDIA_ERR_LOG("Create DataShareHelper failed.");
            return;
        }
    }
    MediaAssetManagerImpl::mediaLibraryManager_->InitMediaLibraryManager(remoteObj);
    MEDIA_INFO_LOG("InitMediaLibraryManager success!");
}

std::string MediaAssetManagerImpl::NativeRequestImage(const char* photoUri,
    const NativeRequestOptions &requestOptions, const char* destUri, const NativeOnDataPrepared &callback)
{
    if (photoUri == nullptr || destUri == nullptr || callback == nullptr) {
        MEDIA_ERR_LOG("Request image input params are invalid.");
        return ERROR_REQUEST_ID;
    }

    MediaLibraryTracer tracer;
    tracer.Start("NativeRequestImage");

    std::unique_ptr<RequestSourceAsyncContext> asyncContext = std::make_unique<RequestSourceAsyncContext>();
    asyncContext->callingPkgName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    asyncContext->destUri = std::string(destUri);
    asyncContext->requestUri = std::string(photoUri);
    asyncContext->displayName = MediaFileUtils::GetFileName(asyncContext->requestUri);
    asyncContext->fileId = std::stoi(MediaFileUtils::GetIdFromUri(asyncContext->requestUri));
    asyncContext->requestOptions.deliveryMode = requestOptions.deliveryMode;
    asyncContext->requestOptions.sourceMode = NativeSourceMode::EDITED_MODE;
    asyncContext->returnDataType = ReturnDataType::TYPE_TARGET_FILE;
    asyncContext->onDataPreparedHandler = callback;

    if (asyncContext->requestUri.length() > MAX_URI_SIZE || asyncContext->destUri.length() > MAX_URI_SIZE) {
        MEDIA_ERR_LOG("Request image uri lens out of limit requestUri lens: %{public}zu, destUri lens: %{public}zu",
            asyncContext->requestUri.length(), asyncContext->destUri.length());
        return ERROR_REQUEST_ID;
    }
    if (MediaFileUtils::GetMediaType(asyncContext->displayName) != MEDIA_TYPE_IMAGE ||
        MediaFileUtils::GetMediaType(MediaFileUtils::GetFileName(asyncContext->destUri)) != MEDIA_TYPE_IMAGE) {
        MEDIA_ERR_LOG("Request image file type invalid");
        return ERROR_REQUEST_ID;
    }
    bool isSuccess = false;
    asyncContext->requestId = GenerateRequestId();
    isSuccess = OnHandleRequestImage(asyncContext);
    if (isSuccess) {
        MEDIA_INFO_LOG("Request image success return requestId: %{public}s", asyncContext->requestId.c_str());
        return asyncContext->requestId;
    } else {
        return ERROR_REQUEST_ID;
    }
}

std::string MediaAssetManagerImpl::NativeRequestVideo(const char* videoUri,
    const NativeRequestOptions &requestOptions, const char* destUri, const NativeOnDataPrepared &callback)
{
    if (videoUri == nullptr || destUri == nullptr || callback == nullptr) {
        MEDIA_ERR_LOG("Request video input params are invalid.");
        return ERROR_REQUEST_ID;
    }
    MediaLibraryTracer tracer;
    tracer.Start("NativeRequestVideo");

    std::unique_ptr<RequestSourceAsyncContext> asyncContext = std::make_unique<RequestSourceAsyncContext>();
    asyncContext->callingPkgName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    asyncContext->destUri = std::string(destUri);
    asyncContext->requestUri = std::string(videoUri);
    asyncContext->displayName = MediaFileUtils::GetFileName(asyncContext->requestUri);
    asyncContext->fileId = std::stoi(MediaFileUtils::GetIdFromUri(asyncContext->requestUri));
    asyncContext->requestOptions.deliveryMode = requestOptions.deliveryMode;
    asyncContext->requestOptions.sourceMode = NativeSourceMode::EDITED_MODE;
    asyncContext->returnDataType = ReturnDataType::TYPE_TARGET_FILE;
    asyncContext->onDataPreparedHandler = callback;

    if (asyncContext->requestUri.length() > MAX_URI_SIZE || asyncContext->destUri.length() > MAX_URI_SIZE) {
        MEDIA_ERR_LOG("Request video uri lens out of limit requestUri lens: %{public}zu, destUri lens: %{public}zu",
            asyncContext->requestUri.length(), asyncContext->destUri.length());
        return ERROR_REQUEST_ID;
    }
    if (MediaFileUtils::GetMediaType(asyncContext->displayName) != MEDIA_TYPE_VIDEO ||
        MediaFileUtils::GetMediaType(MediaFileUtils::GetFileName(asyncContext->destUri)) != MEDIA_TYPE_VIDEO) {
        MEDIA_ERR_LOG("Request video file type invalid");
        return ERROR_REQUEST_ID;
    }
    bool isSuccess = false;
    asyncContext->requestId = GenerateRequestId();
    isSuccess = OnHandleRequestVideo(asyncContext);
    if (isSuccess) {
        MEDIA_ERR_LOG("Request video success return requestId: %{public}s", asyncContext->requestId.c_str());
        return asyncContext->requestId;
    } else {
        return ERROR_REQUEST_ID;
    }
}

bool MediaAssetManagerImpl::NativeCancelRequest(const std::string &requestId)
{
    if (requestId.empty()) {
        MEDIA_ERR_LOG("NativeCancel request id is empty.");
        return false;
    }

    std::string photoId = "";
    bool hasFastRequestInProcess = IsFastRequestCanceled(requestId, photoId);
    bool hasMapRecordInProcess = IsMapRecordCanceled(requestId, photoId);
    if (hasFastRequestInProcess || hasMapRecordInProcess) {
        MultiStagesCaptureManager::GetInstance().CancelProcessRequest(photoId);
    } else {
        MEDIA_ERR_LOG("NativeCancel requestId(%{public}s) not in progress.", requestId.c_str());
        return false;
    }
    return true;
}

bool MediaAssetManagerImpl::OnHandleRequestImage(
    const std::unique_ptr<RequestSourceAsyncContext> &asyncContext)
{
    MultiStagesCapturePhotoStatus status = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    bool result = false;
    switch (asyncContext->requestOptions.deliveryMode) {
        case NativeDeliveryMode::FAST_MODE:
            result = NotifyDataPreparedWithoutRegister(asyncContext);
            break;
        case NativeDeliveryMode::HIGH_QUALITY_MODE:
            status = QueryPhotoStatus(asyncContext->fileId, asyncContext->photoId);
            if (status == MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
                result = NotifyDataPreparedWithoutRegister(asyncContext);
            } else {
                RegisterTaskObserver(asyncContext);
                result = true;
            }
            break;
        case NativeDeliveryMode::BALANCED_MODE:
            status = QueryPhotoStatus(asyncContext->fileId, asyncContext->photoId);
            result = NotifyDataPreparedWithoutRegister(asyncContext);
            if (status == MultiStagesCapturePhotoStatus::LOW_QUALITY_STATUS) {
                RegisterTaskObserver(asyncContext);
            }
            break;
        default: {
            MEDIA_ERR_LOG("Invalid delivery mode %{public}d", asyncContext->requestOptions.deliveryMode);
            return result;
        }
    }
    ProcessImage(asyncContext->fileId, static_cast<int32_t>(asyncContext->requestOptions.deliveryMode),
        asyncContext->callingPkgName);
    return result;
}

bool MediaAssetManagerImpl::OnHandleRequestVideo(
    const std::unique_ptr<RequestSourceAsyncContext> &asyncContext)
{
    bool result = false;
    switch (asyncContext->requestOptions.deliveryMode) {
        case NativeDeliveryMode::FAST_MODE:
            result = NotifyDataPreparedWithoutRegister(asyncContext);
            break;
        case NativeDeliveryMode::HIGH_QUALITY_MODE:
            result = NotifyDataPreparedWithoutRegister(asyncContext);
            break;
        case NativeDeliveryMode::BALANCED_MODE:
            result = NotifyDataPreparedWithoutRegister(asyncContext);
            break;
        default: {
            MEDIA_ERR_LOG("Invalid delivery mode %{public}d", asyncContext->requestOptions.deliveryMode);
            return result;
        }
    }
    return result;
}

bool MediaAssetManagerImpl::NotifyDataPreparedWithoutRegister(
    const std::unique_ptr<RequestSourceAsyncContext> &asyncContext)
{
    AssetHandler *assetHandler = InsertDataHandler(NativeNotifyMode::FAST_NOTIFY, asyncContext);
    if (assetHandler == nullptr) {
        MEDIA_ERR_LOG("assetHandler is nullptr");
        return false;
    }

    return NotifyImageDataPrepared(assetHandler);
}

void MediaAssetManagerImpl::RegisterTaskObserver(const unique_ptr<RequestSourceAsyncContext> &asyncContext)
{
    auto dataObserver = std::make_shared<MultiStagesTaskObserver>(asyncContext->fileId);
    Uri uri(asyncContext->requestUri);
    if (multiStagesObserverMap.find(asyncContext->requestUri) == multiStagesObserverMap.end()) {
        sDataShareHelper_->RegisterObserverExt(uri,
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(dataObserver), false);
        multiStagesObserverMap.insert(std::make_pair(asyncContext->requestUri, dataObserver));
    }

    InsertDataHandler(NativeNotifyMode::WAIT_FOR_HIGH_QUALITY, asyncContext);

    ProcessImage(asyncContext->fileId, static_cast<int32_t>(asyncContext->requestOptions.deliveryMode),
        asyncContext->callingPkgName);
}

void MediaAssetManagerImpl::ProcessImage(const int fileId, const int deliveryMode, const std::string &packageName)
{
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Get sDataShareHelper_ failed");
        return;
    }
    std::string uriStr = PAH_PROCESS_IMAGE;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    Uri uri(uriStr);
    DataShare::DataSharePredicates predicates;
    DataShare::DatashareBusinessError errCode;
    std::vector<std::string> columns { std::to_string(fileId), std::to_string(deliveryMode), packageName };
    sDataShareHelper_->Query(uri, predicates, columns, &errCode);
}

void MultiStagesTaskObserver::OnChange(const ChangeInfo &changeInfo)
{
    if (changeInfo.changeType_ != static_cast<int32_t>(NotifyType::NOTIFY_UPDATE)) {
        MEDIA_DEBUG_LOG("Ignore notify change, type: %{public}d", changeInfo.changeType_);
        return;
    }
    std::string photoId = "";
    if (MediaAssetManagerImpl::QueryPhotoStatus(fileId_, photoId) !=
        MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
        MEDIA_ERR_LOG("Requested data not prepared");
        return;
    }

    for (auto &uri : changeInfo.uris_) {
        string uriString = uri.ToString();

        std::lock_guard<std::mutex> lock(multiStagesCaptureLock);
        if (inProcessUriMap.find(uriString) == inProcessUriMap.end()) {
            MEDIA_INFO_LOG("current uri does not in process, uri: %{public}s", uriString.c_str());
            return;
        }
        std::map<std::string, AssetHandler *> assetHandlers = inProcessUriMap[uriString];
        for (auto handler : assetHandlers) {
            auto assetHandler = handler.second;
            MediaAssetManagerImpl::NotifyImageDataPrepared(assetHandler);
        }
    }
}

int32_t MediaAssetManagerImpl::WriteFileToPath(const std::string &srcUri, const std::string &destUri,
    bool isSource)
{
    if (srcUri.empty() || destUri.empty()) {
        MEDIA_ERR_LOG("srcUri or destUri is empty");
        return E_INVALID_URI;
    }
    std::string tmpSrcUri = srcUri;
    if (isSource) {
        MediaFileUtils::UriAppendKeyValue(tmpSrcUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    int srcFd = MediaAssetManagerImpl::mediaLibraryManager_->OpenAsset(tmpSrcUri, MEDIA_FILEMODE_READONLY);
    if (srcFd < 0) {
        MEDIA_ERR_LOG("Get source %{public}s fd error: %{public}d", tmpSrcUri.c_str(), srcFd);
        return srcFd;
    }
    struct stat statSrc;
    if (fstat(srcFd, &statSrc) != SUCCESS) {
        MediaAssetManagerImpl::mediaLibraryManager_->CloseAsset(tmpSrcUri, srcFd);
        MEDIA_ERR_LOG("File get stat failed, %{public}d", errno);
        return E_FILE_OPER_FAIL;
    }
    int destFd = GetFdFromSandBoxUri(destUri);
    if (destFd < 0) {
        MEDIA_ERR_LOG("Get destination %{public}s fd error: %{public}d", destUri.c_str(), destFd);
        MediaAssetManagerImpl::mediaLibraryManager_->CloseAsset(tmpSrcUri, srcFd);
        return destFd;
    }
    if (sendfile(destFd, srcFd, nullptr, statSrc.st_size) == -1) {
        MediaAssetManagerImpl::mediaLibraryManager_->CloseAsset(tmpSrcUri, srcFd);
        close(destFd);
        MEDIA_ERR_LOG("Sendfile failed, %{public}d", errno);
        return E_FILE_OPER_FAIL;
    }
    MediaAssetManagerImpl::mediaLibraryManager_->CloseAsset(tmpSrcUri, srcFd);
    close(destFd);
    return SUCCESS;
}

int32_t MediaAssetManagerImpl::GetFdFromSandBoxUri(const std::string &sandBoxUri)
{
    AppFileService::ModuleFileUri::FileUri destUri(sandBoxUri);
    string destPath = destUri.GetRealPath();
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateFile(destPath)) {
        MEDIA_ERR_LOG("Create empty dest file in sandbox failed, path:%{private}s", destPath.c_str());
        return E_FILE_OPER_FAIL;
    }
    string absDestPath;
    if (!PathToRealPath(destPath, absDestPath)) {
        MEDIA_ERR_LOG("PathToRealPath failed, path:%{private}s", destPath.c_str());
        return E_FILE_OPER_FAIL;
    }
    return MediaFileUtils::OpenFile(absDestPath, MEDIA_FILEMODE_WRITETRUNCATE);
}
} // namespace Media
} // namespace OHOS