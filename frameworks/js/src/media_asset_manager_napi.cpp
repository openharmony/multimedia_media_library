/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaAssetManagerNapi"

#include "media_asset_manager_napi.h"

#include <fcntl.h>
#include <string>
#include <unordered_map>

#include "dataobs_mgr_client.h"
#include "file_asset_napi.h"
#include "file_uri.h"
#include "image_source.h"
#include "image_source_napi.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "media_library_napi.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_tracer.h"
#include "userfile_client.h"

namespace OHOS {
namespace Media {
static const std::string MEDIA_ASSET_MANAGER_CLASS = "MediaAssetManager";
static std::mutex multiStagesCaptureLock;

const int32_t LOW_QUALITY_IMAGE = 1;
const int32_t HIGH_QUALITY_IMAGE = 0;

thread_local unique_ptr<ChangeListenerNapi> g_multiStagesRequestListObj = nullptr;
thread_local napi_ref constructor_ = nullptr;
napi_env MediaAssetManagerNapi::env_ = nullptr;

static std::map<std::string, std::shared_ptr<MultiStagesTaskObserver>> multiStagesObserverMap;
static std::map<std::string, std::list<NapiMediaAssetDataHandler>> inProcessUriMap;

napi_value MediaAssetManagerNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {.name = MEDIA_ASSET_MANAGER_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_STATIC_FUNCTION("requestImage", JSRequestImage),
            DECLARE_NAPI_STATIC_FUNCTION("requestImageData", JSRequestImageData),
        }};
        MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
        return exports;
}

napi_value MediaAssetManagerNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    bool isConstructor = newTarget != nullptr;
    if (isConstructor) {
        napi_value thisVar = nullptr;
        unique_ptr<MediaAssetManagerNapi> obj = make_unique<MediaAssetManagerNapi>();
        CHECK_COND_WITH_MESSAGE(env, obj != nullptr, "Create MediaAssetManagerNapi failed");
        CHECK_ARGS(env,
            napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), MediaAssetManagerNapi::Destructor,
                nullptr, nullptr),
            JS_INNER_FAIL);
        obj.release();
        return thisVar;
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, constructor_, &constructor));
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    return result;
}

void MediaAssetManagerNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* mediaAssetManager = reinterpret_cast<MediaAssetManagerNapi*>(nativeObject);
    if (mediaAssetManager != nullptr) {
        delete mediaAssetManager;
        mediaAssetManager = nullptr;
    }
}

napi_env MediaAssetManagerNapi::GetMediaAssetManagerJsEnv()
{
    return env_;
}

void MediaAssetManagerNapi::SetMediaAssetManagerJsEnv(napi_env env)
{
    if (env_ != nullptr) {
        NAPI_ERR_LOG("env already initialized no need set again");
        return;
    }
    env_ = env;
}

MultiStagesCapturePhotoStatus MediaAssetManagerNapi::queryPhotoStatus(int fileId)
{
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    std::vector<std::string> fetchColumn { PhotoColumn::PHOTO_QUALITY };
    Uri uri(PAH_QUERY_PHOTO);
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        NAPI_ERR_LOG("query resultSet is nullptr");
        return MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    }
    int columnIndexQuality = -1;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_QUALITY, columnIndexQuality);
    int currentPhotoQuality = HIGH_QUALITY_IMAGE;
    resultSet->GetInt(columnIndexQuality, currentPhotoQuality);
    if (currentPhotoQuality == LOW_QUALITY_IMAGE) {
        NAPI_DEBUG_LOG("query photo status : lowQuality");
        return MultiStagesCapturePhotoStatus::LOW_QUALITY_STATUS;
    }
    NAPI_DEBUG_LOG("query photo status quality: %{public}d", currentPhotoQuality);
    return MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
}

void MediaAssetManagerNapi::ProcessImage(const int fileId, const int deliveryMode, const std::string &packageName)
{
    std::string uriStr = PAH_PROCESS_IMAGE;
    MediaLibraryNapiUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(uriStr);
    DataShare::DataSharePredicates predicates;
    int errCode = 0;
    std::vector<std::string> columns { std::to_string(fileId), std::to_string(deliveryMode), packageName };
    UserFileClient::Query(uri, predicates, columns, errCode);
}

void MediaAssetManagerNapi::AddImage(const int fileId, DeliveryMode deliveryMode)
{
    Uri updateAssetUri(PAH_ADD_IMAGE);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileId);
    valuesBucket.Put("deliveryMode", static_cast<int>(deliveryMode));
    UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
}
 
napi_status GetDeliveryMode(napi_env env, const napi_value arg, const string &propName,
    DeliveryMode& deliveryMode)
{
    bool present = false;
    napi_value property = nullptr;
    int mode = -1;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present),
        "Failed to check property name");
    if (!present) {
        NAPI_ERR_LOG("delivery mode invalid argument ");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "GetDeliveryMode failed");
        return napi_invalid_arg;
    }
    CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
    napi_get_value_int32(env, property, &mode);

    // delivery mode's valid range is 0 - 2
    if (mode < 0 || mode > 2) {
        NAPI_ERR_LOG("delivery mode invalid argument ");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "invalid delivery mode value");
        return napi_invalid_arg;
    }
    deliveryMode = static_cast<DeliveryMode>(mode);
    return napi_ok;
}

napi_status GetSourceMode(napi_env env, const napi_value arg, const string &propName,
    SourceMode& sourceMode)
{
    bool present = false;
    napi_value property = nullptr;
    int mode = -1;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present), "Failed to check property name");
    if (!present) {
        NAPI_ERR_LOG("source mode invalid argument ");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "GetSourceMode failed");
        return napi_invalid_arg;
    }
    CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
    napi_get_value_int32(env, property, &mode);

    // source mode's valid range is 0 - 1
    if (mode < 0 || mode > 1) {
        NAPI_ERR_LOG("source mode invalid argument ");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "invalid source mode value");
        return napi_invalid_arg;
    }
    sourceMode = static_cast<SourceMode>(mode);
    return napi_ok;
}

napi_status ParseArgGetRequestOption(napi_env env, napi_value arg, DeliveryMode &deliveryMode, SourceMode &sourceMode)
{
    CHECK_STATUS_RET(GetDeliveryMode(env, arg, "deliveryMode", deliveryMode), "Failed to parse deliveryMode");
    CHECK_STATUS_RET(GetSourceMode(env, arg, "sourceMode", sourceMode), "Failed to parse sourceMode");
    return napi_ok;
}

napi_status ParseArgGetCallingPakckageName(napi_env env, napi_value arg, std::string &callingPackageName)
{
    if (arg == nullptr) {
        NAPI_ERR_LOG("arg is invalid");
        return napi_invalid_arg;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, arg);
    if (context == nullptr) {
        NAPI_ERR_LOG("Failed to get context");
        return napi_invalid_arg;
    }
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        NAPI_ERR_LOG("abilityContext invalid");
        return napi_invalid_arg;
    }
    auto abilityInfo = abilityContext->GetAbilityInfo();
    callingPackageName = abilityInfo->bundleName;
    return napi_ok;
}

napi_status ParseArgGetPhotoAsset(napi_env env, napi_value arg, int &fileId, std::string &uri,
    std::string &displayName)
{
    if (arg == nullptr) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "ParseArgGetPhotoAsset failed to get photoAsset");
        return napi_invalid_arg;
    }
    FileAssetNapi *obj = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void**>(&obj));
    if (obj == nullptr) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "failed to get asset napi object");
        return napi_invalid_arg;
    }
    fileId = obj->GetFileId();
    uri = obj->GetFileUri();
    displayName = obj->GetFileDisplayName();
    return napi_ok;
}

void MediaAssetManagerNapi::RegisterTaskObserver(const std::string &photoUri, const int fileId,
    napi_value napiMediaDataHandler, ReturnDataType returnDataType, SourceMode sourceMode)
{
    if (napiMediaDataHandler == nullptr) {
        NAPI_ERR_LOG("apiMeidaDatalandler is null");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "GetDeliveryMode failed");
        return;
    }
    auto dataObserver = std::make_shared<MultiStagesTaskObserver>(photoUri, fileId, sourceMode);
    Uri uri(photoUri);
    if (multiStagesObserverMap.find(photoUri) == multiStagesObserverMap.end()) {
        UserFileClient::RegisterObserverExt(uri,
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(dataObserver), false);
        multiStagesObserverMap.insert(std::make_pair(photoUri, dataObserver));
    }

    NapiMediaAssetDataHandler mediaAssetDataHandler(MediaAssetManagerNapi::GetMediaAssetManagerJsEnv(),
        napiMediaDataHandler, returnDataType);
    if (inProcessUriMap.find(photoUri) != inProcessUriMap.end()) {
        inProcessUriMap[photoUri].push_back(mediaAssetDataHandler);
    } else {
        std::list<NapiMediaAssetDataHandler> requestHandler({mediaAssetDataHandler});
        inProcessUriMap[photoUri] = requestHandler;
    }
}

void MediaAssetManagerNapi::DeleteInProcessMapRecord(const std::string &requestUri)
{
    NAPI_INFO_LOG("DeleteInProcessMapRecord %{public}s deleted", requestUri.c_str());
    if (multiStagesObserverMap.find(requestUri) != multiStagesObserverMap.end()) {
        UserFileClient::UnregisterObserverExt(Uri(requestUri),
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(multiStagesObserverMap[requestUri]));
    }
    multiStagesObserverMap.erase(requestUri);
    inProcessUriMap.erase(requestUri);
}

napi_status MediaAssetManagerNapi::ParseRequestImageArgs(napi_env env, napi_callback_info info,
    unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    GET_JS_ARGS(env, info, asyncContext->argc, asyncContext->argv, asyncContext->thisVar);
    if (asyncContext->argc != ARGS_FOUR) {
        NAPI_ERR_LOG("requestImage argc error");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "requestImage argc invalid");
        return napi_invalid_arg;
    }
    if (ParseArgGetCallingPakckageName(env, asyncContext->argv[PARAM0], asyncContext->callingPkgName) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetCallingPakckageName error");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }
    if (ParseArgGetPhotoAsset(env, asyncContext->argv[PARAM1], asyncContext->fileId, asyncContext->photoUri,
        asyncContext->displayName) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetPhotoAsset error");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }
    if (ParseArgGetRequestOption(env, asyncContext->argv[PARAM2], asyncContext->deliveryMode,
        asyncContext->sourceMode) != napi_ok) {
            NAPI_ERR_LOG("requestImage ParseArgGetRequestOption error");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetRequestOption error");
        return napi_invalid_arg;
    }
    return napi_ok;
}

bool MediaAssetManagerNapi::InitUserFileClient(napi_env env, napi_callback_info info)
{
    if (UserFileClient::IsValid()) {
        return true;
    }

    std::unique_lock<std::mutex> helperLock(MediaLibraryNapi::sUserFileClientMutex_);
    if (!UserFileClient::IsValid()) {
        UserFileClient::Init(env, info);
    }
    helperLock.unlock();
    return UserFileClient::IsValid();
}

napi_value MediaAssetManagerNapi::JSRequestImageData(napi_env env, napi_callback_info info)
{
    if (env == nullptr || info == nullptr) {
        NAPI_ERR_LOG("JSRequestImageData js arg invalid");
        NapiError::ThrowError(env, JS_INNER_FAIL, "JSRequestImageData js arg invalid");
        return nullptr;
    }
    if (!InitUserFileClient(env, info)) {
        NAPI_ERR_LOG("JSRequestImageData init user file client failed");
        NapiError::ThrowError(env, JS_INNER_FAIL, "handler is invalid");
        return nullptr;
    }
    if (GetMediaAssetManagerJsEnv() == nullptr) {
        NAPI_INFO_LOG("js env is null need to intialize napi env");
        SetMediaAssetManagerJsEnv(env);
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSRequestImageData");
    unique_ptr<RequestImageAsyncContext> asyncContext = make_unique<RequestImageAsyncContext>();
    asyncContext->returnDataType = ReturnDataType::TYPE_ARRAY_BUFFER;
    if (ParseRequestImageArgs(env, info, asyncContext) != napi_ok) {
        NAPI_ERR_LOG("failed to parse requestImagedata args");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "failed to parse requestImagedata args");
        return nullptr;
    }
    onHandleRequestImage(asyncContext);
    napi_value promise;
    napi_value requestId;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);
    napi_create_string_utf8(env, "1", NAPI_AUTO_LENGTH, &requestId);
    napi_resolve_deferred(env, deferred, requestId);
    return promise;
}

napi_value MediaAssetManagerNapi::JSRequestImage(napi_env env, napi_callback_info info)
{
    if (env == nullptr || info == nullptr) {
        NAPI_ERR_LOG("JSRequestImage js arg invalid");
        NapiError::ThrowError(env, JS_INNER_FAIL, "JSRequestImage js arg invalid");
        return nullptr;
    }
    if (!InitUserFileClient(env, info)) {
        NAPI_ERR_LOG("JSRequestImage init user file client failed");
        NapiError::ThrowError(env, JS_INNER_FAIL, "handler is invalid");
        return nullptr;
    }
    if (GetMediaAssetManagerJsEnv() == nullptr) {
        NAPI_INFO_LOG("js env is null");
        SetMediaAssetManagerJsEnv(env);
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSRequestImage");

    unique_ptr<RequestImageAsyncContext> asyncContext = make_unique<RequestImageAsyncContext>();
    asyncContext->returnDataType = ReturnDataType::TYPE_IMAGE_SOURCE;
    if (ParseRequestImageArgs(env, info, asyncContext) != napi_ok) {
        NAPI_ERR_LOG("failed to parse requestImage args");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "failed to parse requestImage args");
        return nullptr;
    }
    onHandleRequestImage(asyncContext);
    napi_value promise;
    napi_value requestId;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);
    napi_create_string_utf8(env, "1", NAPI_AUTO_LENGTH, &requestId);
    napi_resolve_deferred(env, deferred, requestId);
    return promise;
}

void MediaAssetManagerNapi::onHandleRequestImage(const unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    MultiStagesCapturePhotoStatus status;
    switch (asyncContext->deliveryMode) {
        case DeliveryMode::FAST:
            MediaAssetManagerNapi::notifyDataPreparedWithoutRegister(asyncContext->photoUri,
                asyncContext->argv[PARAM3], asyncContext->returnDataType, asyncContext->sourceMode);
            break;
        case DeliveryMode::HIGH_QUALITY:
            status = MediaAssetManagerNapi::queryPhotoStatus(asyncContext->fileId);
            if (status == MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
                MediaAssetManagerNapi::notifyDataPreparedWithoutRegister(asyncContext->photoUri,
                    asyncContext->argv[PARAM3], asyncContext->returnDataType, asyncContext->sourceMode);
            }
            break;
        case DeliveryMode::BALANCED_MODE:
            status = MediaAssetManagerNapi::queryPhotoStatus(asyncContext->fileId);
            MediaAssetManagerNapi::notifyDataPreparedWithoutRegister(asyncContext->photoUri,
                asyncContext->argv[PARAM3], asyncContext->returnDataType, asyncContext->sourceMode);
            break;
        default: {
            NAPI_ERR_LOG("invalid delivery mode");
            return;
        }
    }

    MediaAssetManagerNapi::ProcessImage(asyncContext->fileId, static_cast<int32_t>(asyncContext->deliveryMode),
        asyncContext->callingPkgName);
}

void MediaAssetManagerNapi::notifyDataPreparedWithoutRegister(std::string &requestUri, napi_value napiMediaDataHandler,
    ReturnDataType returnDataType, SourceMode sourceMode)
{
    if (napiMediaDataHandler == nullptr) {
        NAPI_ERR_LOG("apiMeidaDatalandler is null");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "handler is invalid");
        return;
    }
    NapiMediaAssetDataHandler mediaAssetDataHandler(MediaAssetManagerNapi::GetMediaAssetManagerJsEnv(),
        napiMediaDataHandler, returnDataType);
    napi_value imageSourceNapiValue = nullptr;
    napi_value arrayBufferNapiValue = nullptr;
    if (returnDataType == ReturnDataType::TYPE_ARRAY_BUFFER) {
        if (arrayBufferNapiValue == nullptr) {
            GetByteArrayNapiObject(requestUri, arrayBufferNapiValue,
                sourceMode == SourceMode::ORIGINAL_MODE);
        }
        mediaAssetDataHandler.JsOnDataPreared(arrayBufferNapiValue);
    } else if (returnDataType == ReturnDataType::TYPE_IMAGE_SOURCE) {
        if (imageSourceNapiValue == nullptr) {
            GetImageSourceNapiObject(requestUri, imageSourceNapiValue,
                sourceMode == SourceMode::ORIGINAL_MODE);
        }
        mediaAssetDataHandler.JsOnDataPreared(imageSourceNapiValue);
    } else {
        NAPI_ERR_LOG("source mode type invalid");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "source mode type invalid");
    }
}

void MediaAssetManagerNapi::notifyImageDataPrepared(const std::string requestUri, SourceMode sourceMode)
{
    auto iter = inProcessUriMap.find(requestUri);
    if (iter == inProcessUriMap.end()) {
        NAPI_ERR_LOG("current does not in process");
        DeleteInProcessMapRecord(requestUri);
        return;
    }
    auto handlerList = iter->second;
    napi_value imageSourceNapiValue = nullptr;
    napi_value arrayBufferNapiValue = nullptr;
    for (auto listIter = handlerList.begin(); listIter != handlerList.end(); listIter++) {
        if (listIter->GetHandlerType() == ReturnDataType::TYPE_ARRAY_BUFFER) {
            NAPI_INFO_LOG("array buffer prepared");
            if (arrayBufferNapiValue == nullptr) {
                GetByteArrayNapiObject(requestUri, arrayBufferNapiValue,
                    sourceMode == SourceMode::ORIGINAL_MODE);
            }
            listIter->JsOnDataPreared(arrayBufferNapiValue);
        } else if (listIter->GetHandlerType() == ReturnDataType::TYPE_IMAGE_SOURCE) {
            NAPI_INFO_LOG("imageSource prepared");
            if (imageSourceNapiValue == nullptr) {
                GetImageSourceNapiObject(requestUri, imageSourceNapiValue,
                    sourceMode == SourceMode::ORIGINAL_MODE);
            }
            listIter->JsOnDataPreared(imageSourceNapiValue);
        } else {
            NAPI_ERR_LOG("notifyImageDataPrepared source mode type invalid");
            NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "source mode type invalid");
        }
    }
    DeleteInProcessMapRecord(requestUri);
}

void MultiStagesTaskObserver::OnChange(const ChangeInfo &changeInfo)
{
    if (MediaAssetManagerNapi::queryPhotoStatus(fileId_) != MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
        NAPI_ERR_LOG("requested data not prepared");
        return;
    }
    MediaAssetManagerNapi::notifyImageDataPrepared(requestUri_, sourceMode_);
}

void MediaAssetManagerNapi::GetImageSourceNapiObject(std::string fileUri, napi_value &imageSourceNapiObj,
    bool isSource)
{
    uint32_t errCode = 0;
    SourceOptions opts;
    napi_value tempImageSourceNapi;
    napi_env localEnv = MediaAssetManagerNapi::GetMediaAssetManagerJsEnv();
    ImageSourceNapi* imageSourceNapi = nullptr;
    if (localEnv == nullptr) {
        NAPI_ERR_LOG(" create image source object failed, need to initialize js env");
        NapiError::ThrowError(env_, JS_INNER_FAIL, "js env invalid error");
        return;
    }
    ImageSourceNapi::CreateImageSourceNapi(localEnv, &tempImageSourceNapi);
    napi_unwrap(localEnv, tempImageSourceNapi, reinterpret_cast<void**>(&imageSourceNapi));
    if (imageSourceNapi == nullptr) {
        NAPI_ERR_LOG("unwrap image napi object failed");
        NapiError::ThrowError(env_, JS_INNER_FAIL, "CreateImageSource error");
        return;
    }
    std::string tmpUri = fileUri;
    if (isSource) {
        MediaFileUtils::UriAppendKeyValue(tmpUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
        NAPI_INFO_LOG("request source image's imageSource");
    }
    Uri uri(tmpUri);
    int fd = UserFileClient::OpenFile(uri, "r");
    if (fd < 0) {
        NAPI_ERR_LOG("get iamge fd failed");
        NapiError::ThrowError(env_, OHOS_PERMISSION_DENIED_CODE, "open Image file error");
        return;
    }
    auto nativeImageSourcePtr = ImageSource::CreateImageSource(fd, opts, errCode);
    if (nativeImageSourcePtr == nullptr) {
        NAPI_ERR_LOG("get ImageSource::CreateImageSource failed nullptr");
        NapiError::ThrowError(env_, JS_INNER_FAIL, "CreateImageSource error");
        return;
    }
    imageSourceNapi->SetNativeImageSource(std::move(nativeImageSourcePtr));
    imageSourceNapiObj = tempImageSourceNapi;
}

void MediaAssetManagerNapi::GetByteArrayNapiObject(std::string requestUri, napi_value &arrayBuffer, bool isSource)
{
    napi_env localEnv = MediaAssetManagerNapi::GetMediaAssetManagerJsEnv();
    std::string tmpUri = requestUri;
    if (isSource) {
        MediaFileUtils::UriAppendKeyValue(tmpUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    Uri uri(tmpUri);
    int imageFd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    if (imageFd < 0) {
        NAPI_ERR_LOG("get iamge fd failed");
        NapiError::ThrowError(localEnv, OHOS_PERMISSION_DENIED_CODE, "open Image file error");
        return;
    }
    size_t imgLen = lseek(imageFd, 0, SEEK_END);
    lseek(imageFd, 0, SEEK_SET);
    char buf[imgLen];
    size_t readRet = read(imageFd, buf, imgLen);
    if (readRet != imgLen) {
        NAPI_ERR_LOG("read image failed");
        NapiError::ThrowError(localEnv, JS_INNER_FAIL, "open Image file error");
        return;
    }
    napi_create_arraybuffer(localEnv, imgLen, (void**)&buf, &arrayBuffer);
}
} // namespace Media
} // namespace OHOS