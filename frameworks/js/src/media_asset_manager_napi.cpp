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
#include <uuid/uuid.h>

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

const int32_t UUID_STR_LENGTH = 37;

thread_local unique_ptr<ChangeListenerNapi> g_multiStagesRequestListObj = nullptr;
thread_local napi_ref constructor_ = nullptr;

static std::map<std::string, std::shared_ptr<MultiStagesTaskObserver>> multiStagesObserverMap;
static SafeMap<std::string, std::map<std::string, AssetHandler*>> inProcessUriMap;
static SafeMap<std::string, AssetHandler*> inProcessFastRequests;

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

void MediaAssetManagerNapi::Destructor(napi_env env, void *nativeObject, void *finalizeHint)
{
    auto* mediaAssetManager = reinterpret_cast<MediaAssetManagerNapi*>(nativeObject);
    if (mediaAssetManager != nullptr) {
        delete mediaAssetManager;
        mediaAssetManager = nullptr;
    }
}

static void InsertInProcessMapRecord(const std::string &requestUri, const std::string &requestId,
    AssetHandler *handler)
{
    std::map<std::string, AssetHandler*> assetHandler;
    if (inProcessUriMap.Find(requestUri, assetHandler)) {
        assetHandler[requestId] = handler;
        inProcessUriMap.EnsureInsert(requestUri, assetHandler);
    } else {
        assetHandler[requestId] = handler;
        inProcessUriMap.Insert(requestUri, assetHandler);
    }
}

static void DeleteInProcessMapRecord(const std::string &requestUri, const std::string &requestId)
{
    std::map<std::string, AssetHandler*> assetHandlers;
    if (!inProcessUriMap.Find(requestUri, assetHandlers)) {
        return;
    }

    if (assetHandlers.find(requestId) == assetHandlers.end()) {
        return;
    }

    assetHandlers.erase(requestId);
    if (!assetHandlers.empty()) {
        inProcessUriMap.EnsureInsert(requestUri, assetHandlers);
        return;
    }

    inProcessUriMap.Erase(requestUri);

    if (multiStagesObserverMap.find(requestUri) != multiStagesObserverMap.end()) {
        UserFileClient::UnregisterObserverExt(Uri(requestUri),
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(multiStagesObserverMap[requestUri]));
    }
    multiStagesObserverMap.erase(requestUri);
}

static AssetHandler* InsertDataHandler(NotifyMode notifyMode, napi_env env,
    const unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    std::shared_ptr<NapiMediaAssetDataHandler> mediaAssetDataHandler = make_shared<NapiMediaAssetDataHandler>(
        env, asyncContext->dataHandler, asyncContext->returnDataType, asyncContext->photoUri, asyncContext->sourceMode);
    mediaAssetDataHandler->SetNotifyMode(notifyMode);

    napi_value workName = nullptr;
    napi_create_string_utf8(env, "Data Prepared", NAPI_AUTO_LENGTH, &workName);
    napi_threadsafe_function threadSafeFunc;
    napi_status status = napi_create_threadsafe_function(env, asyncContext->dataHandler, NULL, workName, 0, 1,
        NULL, NULL, NULL, MediaAssetManagerNapi::OnDataPrepared, &threadSafeFunc);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi_create_threadsafe_function fail");
        NapiError::ThrowError(env, JS_INNER_FAIL, "napi_create_threadsafe_function fail");
        return nullptr;
    }

    AssetHandler *assetHandler = new AssetHandler(asyncContext->photoId, asyncContext->requestId,
        asyncContext->photoUri, mediaAssetDataHandler, threadSafeFunc);
    NAPI_INFO_LOG("Add %{public}d, %{private}s, %{private}s, %{public}p", notifyMode, asyncContext->photoUri.c_str(),
        asyncContext->requestId.c_str(), assetHandler);

    switch (notifyMode) {
        case NotifyMode::FAST_NOTIFY: {
            inProcessFastRequests.EnsureInsert(asyncContext->requestId, assetHandler);
            break;
        }
        case NotifyMode::WAIT_FOR_HIGH_QUALITY: {
            InsertInProcessMapRecord(asyncContext->photoUri, asyncContext->requestId, assetHandler);
            break;
        }
        default:
            break;
    }

    return assetHandler;
}

static void DeleteDataHandler(NotifyMode notifyMode, const std::string &requestUri, const std::string &requestId)
{
    NAPI_INFO_LOG("Rmv %{public}d, %{public}s, %{public}s", notifyMode, requestUri.c_str(),
        requestId.c_str());
    if (notifyMode == NotifyMode::WAIT_FOR_HIGH_QUALITY) {
        DeleteInProcessMapRecord(requestUri, requestId);
    }
    inProcessFastRequests.Erase(requestId);
}

MultiStagesCapturePhotoStatus MediaAssetManagerNapi::QueryPhotoStatus(int fileId, std::string &photoId)
{
    photoId = "";
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    std::vector<std::string> fetchColumn { PhotoColumn::PHOTO_QUALITY, PhotoColumn::PHOTO_ID };
    Uri uri(PAH_QUERY_PHOTO);
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        NAPI_ERR_LOG("query resultSet is nullptr");
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
        // use default source mode
        sourceMode = SourceMode::EDITED_MODE;
        return napi_ok;
    }
    CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
    napi_get_value_int32(env, property, &mode);

    // source mode's valid range is 0 - 1
    if (mode < 0 || mode > 1) {
        NAPI_ERR_LOG("source mode invalid");
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

napi_status ParseArgGetDataHandler(napi_env env, napi_value arg, napi_value &dataHandler)
{
    if (arg == nullptr) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "data handler invalid argument");
        return napi_invalid_arg;
    }
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_object) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "data handler not a object");
        return napi_invalid_arg;
    }
    dataHandler = arg;
    return napi_ok;
}

static std::string GenerateRequestId()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

void MediaAssetManagerNapi::RegisterTaskObserver(napi_env env,
    const unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    auto dataObserver = std::make_shared<MultiStagesTaskObserver>(asyncContext->fileId);
    Uri uri(asyncContext->photoUri);
    if (multiStagesObserverMap.find(asyncContext->photoUri) == multiStagesObserverMap.end()) {
        UserFileClient::RegisterObserverExt(uri,
            static_cast<std::shared_ptr<DataShare::DataShareObserver>>(dataObserver), false);
        multiStagesObserverMap.insert(std::make_pair(asyncContext->photoUri, dataObserver));
    }

    InsertDataHandler(NotifyMode::WAIT_FOR_HIGH_QUALITY, env, asyncContext);

    MediaAssetManagerNapi::ProcessImage(asyncContext->fileId, static_cast<int32_t>(asyncContext->deliveryMode),
        asyncContext->callingPkgName);
}

napi_status MediaAssetManagerNapi::ParseRequestImageArgs(napi_env env, napi_callback_info info,
    unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, asyncContext->argc, asyncContext->argv, thisVar);
    if (asyncContext->argc != ARGS_FOUR) {
        NAPI_ERR_LOG("requestImage argc error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestImage argc invalid");
        return napi_invalid_arg;
    }
    if (ParseArgGetCallingPakckageName(env, asyncContext->argv[PARAM0], asyncContext->callingPkgName) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetCallingPakckageName error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }
    if (ParseArgGetPhotoAsset(env, asyncContext->argv[PARAM1], asyncContext->fileId, asyncContext->photoUri,
        asyncContext->displayName) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetPhotoAsset error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }
    if (ParseArgGetRequestOption(env, asyncContext->argv[PARAM2], asyncContext->deliveryMode,
        asyncContext->sourceMode) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetRequestOption error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetRequestOption error");
        return napi_invalid_arg;
    }
    if (ParseArgGetDataHandler(env, asyncContext->argv[PARAM3], asyncContext->dataHandler) != napi_ok) {
        NAPI_ERR_LOG("requestImage ParseArgGetDataHandler error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestImage ParseArgGetDataHandler error");
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

    MediaLibraryTracer tracer;
    tracer.Start("JSRequestImageData");
    unique_ptr<RequestImageAsyncContext> asyncContext = make_unique<RequestImageAsyncContext>();
    asyncContext->returnDataType = ReturnDataType::TYPE_ARRAY_BUFFER;
    if (ParseRequestImageArgs(env, info, asyncContext) != napi_ok) {
        NAPI_ERR_LOG("failed to parse requestImagedata args");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "failed to parse requestImagedata args");
        return nullptr;
    }

    asyncContext->requestId = GenerateRequestId();
    OnHandleRequestImage(env, asyncContext);

    napi_value promise;
    napi_value requestId;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);
    napi_create_string_utf8(env, asyncContext->requestId.c_str(), NAPI_AUTO_LENGTH, &requestId);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSRequestImage");

    unique_ptr<RequestImageAsyncContext> asyncContext = make_unique<RequestImageAsyncContext>();
    asyncContext->returnDataType = ReturnDataType::TYPE_IMAGE_SOURCE;
    if (ParseRequestImageArgs(env, info, asyncContext) != napi_ok) {
        NAPI_ERR_LOG("failed to parse requestImage args");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "failed to parse requestImage args");
        return nullptr;
    }

    asyncContext->requestId = GenerateRequestId();
    OnHandleRequestImage(env, asyncContext);
    napi_value promise;
    napi_value requestId;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);
    napi_create_string_utf8(env, asyncContext->requestId.c_str(), NAPI_AUTO_LENGTH, &requestId);
    napi_resolve_deferred(env, deferred, requestId);
    return promise;
}

void MediaAssetManagerNapi::OnHandleRequestImage(napi_env env,
    const unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    MultiStagesCapturePhotoStatus status = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    switch (asyncContext->deliveryMode) {
        case DeliveryMode::FAST:
            MediaAssetManagerNapi::NotifyDataPreparedWithoutRegister(env, asyncContext);
            break;
        case DeliveryMode::HIGH_QUALITY:
            status = MediaAssetManagerNapi::QueryPhotoStatus(asyncContext->fileId, asyncContext->photoId);
            if (status == MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
                MediaAssetManagerNapi::NotifyDataPreparedWithoutRegister(env, asyncContext);
            } else {
                RegisterTaskObserver(env, asyncContext);
            }
            break;
        case DeliveryMode::BALANCED_MODE:
            status = MediaAssetManagerNapi::QueryPhotoStatus(asyncContext->fileId, asyncContext->photoId);
            MediaAssetManagerNapi::NotifyDataPreparedWithoutRegister(env, asyncContext);
            if (status == MultiStagesCapturePhotoStatus::LOW_QUALITY_STATUS) {
                RegisterTaskObserver(env, asyncContext);
            }
            break;
        default: {
            NAPI_ERR_LOG("invalid delivery mode");
            return;
        }
    }
}

void MediaAssetManagerNapi::NotifyDataPreparedWithoutRegister(napi_env env,
    const unique_ptr<RequestImageAsyncContext> &asyncContext)
{
    AssetHandler *assetHandler = InsertDataHandler(NotifyMode::FAST_NOTIFY, env, asyncContext);
    if (assetHandler == nullptr) {
        NAPI_ERR_LOG("assetHandler is nullptr");
        return;
    }

    NotifyImageDataPrepared(assetHandler);
}

void MediaAssetManagerNapi::OnDataPrepared(napi_env env, napi_value cb, void *context, void *data)
{
    AssetHandler *assetHandler = reinterpret_cast<AssetHandler *>(data);
    CHECK_NULL_PTR_RETURN_VOID(assetHandler, "assetHandler is nullptr");

    auto dataHandler = assetHandler->dataHandler;
    if (dataHandler == nullptr) {
        NAPI_ERR_LOG("data handler is nullptr");
        delete assetHandler;
        return;
    }

    NotifyMode notifyMode = dataHandler->GetNotifyMode();
    if (notifyMode == NotifyMode::FAST_NOTIFY) {
        AssetHandler *tmp;
        if (!inProcessFastRequests.Find(assetHandler->requestId, tmp)) {
            NAPI_ERR_LOG("The request has been canceled");
            delete assetHandler;
            return;
        }
    }

    napi_value napiValueOfImage = nullptr;
    if (dataHandler->GetReturnDataType() == ReturnDataType::TYPE_ARRAY_BUFFER) {
        GetByteArrayNapiObject(dataHandler->GetRequestUri(), napiValueOfImage,
            dataHandler->GetSourceMode() == SourceMode::ORIGINAL_MODE, env);
        dataHandler->JsOnDataPrepared(napiValueOfImage);
    } else if (dataHandler->GetReturnDataType() == ReturnDataType::TYPE_IMAGE_SOURCE) {
        GetImageSourceNapiObject(dataHandler->GetRequestUri(), napiValueOfImage,
            dataHandler->GetSourceMode() == SourceMode::ORIGINAL_MODE, env);
        dataHandler->JsOnDataPrepared(napiValueOfImage);
    } else {
        NAPI_ERR_LOG("source mode type invalid");
    }

    DeleteDataHandler(notifyMode, assetHandler->requestUri, assetHandler->requestId);
    napi_release_threadsafe_function(assetHandler->threadSafeFunc, napi_tsfn_release);
    NAPI_INFO_LOG("delete assetHandler: %{public}p", assetHandler);
    delete assetHandler;
}

void MediaAssetManagerNapi::NotifyImageDataPrepared(AssetHandler *assetHandler)
{
    napi_status status = napi_call_threadsafe_function(assetHandler->threadSafeFunc, (void *)assetHandler,
        napi_tsfn_blocking);
    if (status != napi_ok) {
        napi_release_threadsafe_function(assetHandler->threadSafeFunc, napi_tsfn_release);
        if (assetHandler != nullptr) {
            delete assetHandler;
        }
    }
}

void MultiStagesTaskObserver::OnChange(const ChangeInfo &changeInfo)
{
    if (changeInfo.changeType_ != static_cast<int32_t>(NotifyType::NOTIFY_UPDATE)) {
        NAPI_DEBUG_LOG("ignore notify change, type: %{public}d", changeInfo.changeType_);
        return;
    }
    std::string photoId = "";
    if (MediaAssetManagerNapi::QueryPhotoStatus(fileId_, photoId) !=
        MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS) {
        NAPI_ERR_LOG("requested data not prepared");
        return;
    }

    for (auto &uri : changeInfo.uris_) {
        string uriString = uri.ToString();

        std::map<std::string, AssetHandler *> assetHandlers;
        if (!inProcessUriMap.Find(uriString, assetHandlers)) {
            NAPI_INFO_LOG("current uri does not in process, uri: %{public}s", uriString.c_str());
            return;
        }
        for (auto handler : assetHandlers) {
            auto assetHandler = handler.second;
            MediaAssetManagerNapi::NotifyImageDataPrepared(assetHandler);
        }
    }
}

void MediaAssetManagerNapi::GetImageSourceNapiObject(const std::string &fileUri, napi_value &imageSourceNapiObj,
    bool isSource, napi_env env)
{
    if (env == nullptr) {
        NAPI_ERR_LOG(" create image source object failed, need to initialize js env");
        return;
    }
    napi_value tempImageSourceNapi;
    ImageSourceNapi::CreateImageSourceNapi(env, &tempImageSourceNapi);
    ImageSourceNapi* imageSourceNapi = nullptr;
    napi_unwrap(env, tempImageSourceNapi, reinterpret_cast<void**>(&imageSourceNapi));
    if (imageSourceNapi == nullptr) {
        NAPI_ERR_LOG("unwrap image napi object failed");
        NapiError::ThrowError(env, JS_INNER_FAIL, "CreateImageSource error");
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
        NAPI_ERR_LOG("get image fd failed, errno: %{public}d", errno);
        NapiError::ThrowError(env, OHOS_PERMISSION_DENIED_CODE, "open image file error");
        return;
    }

    SourceOptions opts;
    uint32_t errCode = 0;
    auto nativeImageSourcePtr = ImageSource::CreateImageSource(fd, opts, errCode);
    close(fd);
    if (nativeImageSourcePtr == nullptr) {
        NAPI_ERR_LOG("get ImageSource::CreateImageSource failed nullptr");
        NapiError::ThrowError(env, JS_INNER_FAIL, "CreateImageSource error");
        return;
    }
    imageSourceNapi->SetNativeImageSource(std::move(nativeImageSourcePtr));
    imageSourceNapiObj = tempImageSourceNapi;
}

void MediaAssetManagerNapi::GetByteArrayNapiObject(const std::string &requestUri, napi_value &arrayBuffer,
    bool isSource, napi_env env)
{
    if (env == nullptr) {
        NAPI_ERR_LOG("create byte array object failed, need to initialize js env");
        return;
    }
    
    std::string tmpUri = requestUri;
    if (isSource) {
        MediaFileUtils::UriAppendKeyValue(tmpUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    Uri uri(tmpUri);
    int imageFd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    if (imageFd < 0) {
        NAPI_ERR_LOG("get image fd failed, %{public}d", errno);
        NapiError::ThrowError(env, OHOS_PERMISSION_DENIED_CODE, "open image file  error");
        return;
    }
    size_t imgLen = lseek(imageFd, 0, SEEK_END);
    void* buffer = nullptr;
    napi_create_arraybuffer(env, imgLen, &buffer, &arrayBuffer);
    lseek(imageFd, 0, SEEK_SET);
    size_t readRet = read(imageFd, buffer, imgLen);
    close(imageFd);
    if (readRet != imgLen) {
        NAPI_ERR_LOG("read image failed");
        NapiError::ThrowError(env, JS_INNER_FAIL, "open Image file error");
        return;
    }
}
} // namespace Media
} // namespace OHOS