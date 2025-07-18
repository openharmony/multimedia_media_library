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

#define MLOG_TAG "CloudMediaAssetManagerNapi"

#include "cloud_media_asset_manager_napi.h"

#include "media_column.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"
#include "media_library_napi.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "cloud_media_asset_types.h"
#include "cloud_media_asset_status_napi.h"
#include "cloud_media_asset_uri.h"
#include "start_download_cloud_media_vo.h"
#include "retain_cloud_media_asset_vo.h"
#include "medialibrary_business_code.h"
#include "user_define_ipc_client.h"
#include "medialibrary_business_code.h"
#include "get_cloudmedia_asset_status_vo.h"
#include "user_define_ipc_client.h"

using namespace std;
namespace OHOS::Media {
static const string CLOUD_MEDIA_ASSET_MANAGER_CLASS = "CloudMediaAssetManager";
thread_local napi_ref CloudMediaAssetManagerNapi::constructor_ = nullptr;
const size_t TYPE_SIZE = 6;
const int32_t INDEX_ZERO = 0;
const int32_t INDEX_ONE = 1;
const int32_t INDEX_TWO = 2;
const int32_t INDEX_THREE = 3;
const int32_t INDEX_FOUR = 4;
const int32_t INDEX_FIVE = 5;

napi_value CloudMediaAssetManagerNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = CLOUD_MEDIA_ASSET_MANAGER_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_STATIC_FUNCTION("getCloudMediaAssetManagerInstance", JSGetCloudMediaAssetManagerInstance),
            DECLARE_NAPI_FUNCTION("startDownloadCloudMedia", JSStartDownloadCloudMedia),
            DECLARE_NAPI_FUNCTION("pauseDownloadCloudMedia", JSPauseDownloadCloudMedia),
            DECLARE_NAPI_FUNCTION("cancelDownloadCloudMedia", JSCancelDownloadCloudMedia),
            DECLARE_NAPI_FUNCTION("retainCloudMediaAsset", JSRetainCloudMediaAsset),
            DECLARE_NAPI_FUNCTION("getCloudMediaAssetStatus", JSGetCloudMediaAssetStatus),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value CloudMediaAssetManagerNapi::Constructor(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL,
            "The cloud media asset manager instance can be called only by system apps");
        return nullptr;
    }
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Failed to check new.target");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
    if (!InitUserFileClient(env, info)) {
        NAPI_ERR_LOG("Failed to init UserFileClient");
        return nullptr;
    }

    unique_ptr<CloudMediaAssetManagerNapi> obj = make_unique<CloudMediaAssetManagerNapi>();
    CHECK_COND(env, obj != nullptr, JS_INNER_FAIL);
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), CloudMediaAssetManagerNapi::Destructor, nullptr,
            nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void CloudMediaAssetManagerNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* cloudMediaAssetManager = reinterpret_cast<CloudMediaAssetManagerNapi*>(nativeObject);
    if (cloudMediaAssetManager == nullptr) {
        NAPI_ERR_LOG("cloudMediaAssetManager is nullptr");
        return;
    }
    delete cloudMediaAssetManager;
    cloudMediaAssetManager = nullptr;
}

static bool CheckWhetherInitSuccess(napi_env env, napi_value value, bool checkIsValid)
{
    napi_value propertyNames;
    uint32_t propertyLength;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType != napi_object) {
        NAPI_ERR_LOG("valueType is not valid");
        return false;
    }

    NAPI_CALL_BASE(env, napi_get_property_names(env, value, &propertyNames), false);
    NAPI_CALL_BASE(env, napi_get_array_length(env, propertyNames, &propertyLength), false);
    if (propertyLength == 0) {
        NAPI_ERR_LOG("propertyLength is 0");
        return false;
    }
    if (checkIsValid && (!UserFileClient::IsValid())) {
        NAPI_ERR_LOG("UserFileClient is not valid");
        return false;
    }
    return true;
}

napi_value CloudMediaAssetManagerNapi::JSGetCloudMediaAssetManagerInstance(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCloudMediaAssetManagerInstance");

    constexpr size_t ARG_CONTEXT = 1;
    size_t argc = ARG_CONTEXT;
    napi_value argv[ARGS_TWO] = {0};

    napi_value thisVar = nullptr;
    napi_value ctor = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_get_reference_value(env, constructor_, &ctor));

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, ctor, argc, argv, &result));
    if (!CheckWhetherInitSuccess(env, result, false)) {
        NAPI_ERR_LOG("Init Cloud Media Asset Manager Instance is failed");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

bool CloudMediaAssetManagerNapi::InitUserFileClient(napi_env env, napi_callback_info info)
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

static napi_status ParseArgCloudMediaDownloadType(napi_env env, napi_callback_info info,
    unique_ptr<CloudMediaAssetAsyncContext>& context)
{
    CHECK_STATUS_RET(MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, ARGS_ONE, ARGS_ONE),
        "Failed to get args");
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, context->argv[ARGS_ZERO], &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_int32(env, context->argv[ARGS_ZERO], &context->cloudMediaDownloadType),
        "Failed to get int32 value");
    return napi_ok;
}

static napi_status ParseArgCloudMediaRetainType(napi_env env, napi_callback_info info,
    unique_ptr<CloudMediaAssetAsyncContext>& context)
{
    CHECK_STATUS_RET(MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, ARGS_ONE, ARGS_ONE),
        "Failed to get args");
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, context->argv[ARGS_ZERO], &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_int32(env, context->argv[ARGS_ZERO], &context->cloudMediaRetainType),
        "Failed to get int32 value");
    return napi_ok;
}

static void StartDownloadCloudMediaExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("StartDownloadCloudMediaExecute");
    NAPI_INFO_LOG("enter StartDownloadCloudMediaExecute");

    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    StartDownloadCloudMediaReqBody reqBody;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::START_DOWNLOAD_CLOUDMEDIA);
    reqBody.cloudMediaType = context->cloudMediaDownloadType;
    NAPI_INFO_LOG("before IPC::UserDefineIPCClient().Call");
    int32_t ret = IPC::UserDefineIPCClient().Call(businessCode, reqBody);
    NAPI_INFO_LOG("after IPC::UserDefineIPCClient().Call");
    if (ret < 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Start download cloud media failed, err: %{public}d", ret);
    }
}

static void StartDownloadCloudMediaCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CloudMediaAssetManagerNapi::JSStartDownloadCloudMedia(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSStartDownloadCloudMedia");

    auto asyncContext = make_unique<CloudMediaAssetAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgCloudMediaDownloadType(env, info, asyncContext) == napi_ok,
        "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "StartDownloadCloudMedia",
        StartDownloadCloudMediaExecute, StartDownloadCloudMediaCompleteCallback);
}

static void PauseDownloadCloudMediaExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("PauseDownloadCloudMediaExecute");
    NAPI_INFO_LOG("enter PauseDownloadCloudMediaExecute");

    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAUSE_DOWNLOAD_CLOUDMEDIA);
    NAPI_INFO_LOG("before IPC::UserDefineIPCClient().Call");
    int32_t ret = IPC::UserDefineIPCClient().Call(businessCode);
    NAPI_INFO_LOG("after IPC::UserDefineIPCClient().Call");
    if (ret < 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Pause download cloud media failed, err: %{public}d", ret);
    }
}

static void PauseDownloadCloudMediaCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CloudMediaAssetManagerNapi::JSPauseDownloadCloudMedia(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSPauseDownloadCloudMedia");

    auto asyncContext = make_unique<CloudMediaAssetAsyncContext>();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "PauseDownloadCloudMedia",
        PauseDownloadCloudMediaExecute, PauseDownloadCloudMediaCompleteCallback);
}

static void CancelDownloadCloudMediaExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("CancelDownloadCloudMediaExecute");
    NAPI_INFO_LOG("enter CancelDownloadCloudMediaExecute");

    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_DOWNLOAD_CLOUDMEDIA);
    NAPI_INFO_LOG("before IPC::UserDefineIPCClient().Call");
    int32_t ret = IPC::UserDefineIPCClient().Call(businessCode);
    NAPI_INFO_LOG("after IPC::UserDefineIPCClient().Call");
    if (ret < 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Cancel download cloud media failed, err: %{public}d", ret);
    }
}

static void CancelDownloadCloudMediaCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CloudMediaAssetManagerNapi::JSCancelDownloadCloudMedia(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSCancelDownloadCloudMedia");

    auto asyncContext = make_unique<CloudMediaAssetAsyncContext>();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "CancelDownloadCloudMedia",
        CancelDownloadCloudMediaExecute, CancelDownloadCloudMediaCompleteCallback);
}

static void RetainCloudMediaAssetExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("RetainCloudMediaAssetExecute");
    NAPI_INFO_LOG("enter RetainCloudMediaAssetExecute");

    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    RetainCloudMediaAssetReqBody reqBody;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::RETAIN_CLOUDMEDIA_ASSET);
    reqBody.cloudMediaRetainType = context->cloudMediaRetainType;
    NAPI_INFO_LOG("before IPC::UserDefineIPCClient().Call");
    int32_t ret = IPC::UserDefineIPCClient().Call(businessCode, reqBody);
    NAPI_INFO_LOG("after IPC::UserDefineIPCClient().Call");
    if (ret < 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Retain cloud media asset failed, err: %{public}d", ret);
    }
}

static void RetainCloudMediaAssetCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CloudMediaAssetManagerNapi::JSRetainCloudMediaAsset(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSRetainCloudMediaAsset");

    auto asyncContext = make_unique<CloudMediaAssetAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgCloudMediaRetainType(env, info, asyncContext) == napi_ok,
        "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "RetainCloudMediaAsset",
        RetainCloudMediaAssetExecute, RetainCloudMediaAssetCompleteCallback);
}

static bool CanConvertToInt32(const std::string &str)
{
    std::istringstream stringStream(str);
    int32_t num = 0;
    stringStream >> num;
    return stringStream.eof() && !stringStream.fail();
}

static bool SplitUriString(const std::string& str, std::vector<std::string> &type)
{
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) {
            return false;
        }
        type.emplace_back(item);
    }
    return type.size() == TYPE_SIZE;
}

static void GetCloudMediaAssetStatusExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCloudMediaAssetStatusExecute");
    NAPI_INFO_LOG("enter GetCloudMediaAssetStatusExecute");

    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    GetCloudMediaAssetStatusReqBody reqBody;
    GetCloudMediaAssetStatusReqBody respBody;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::QUERY_GET_CLOUDMEDIA_ASSET_STATUS);
    int32_t ret = IPC::UserDefineIPCClient().Call(businessCode, reqBody, respBody);
    if (ret != 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Get cloud media asset status failed, err: %{public}d", ret);
        return;
    }

    NAPI_INFO_LOG("Get cloud media asset, res: %{public}s.", respBody.status.c_str());
    std::vector<std::string> type;
    if (!SplitUriString(respBody.status, type)) {
        NAPI_ERR_LOG("GetType failed");
        return;
    }
    if (!CanConvertToInt32(type[INDEX_ZERO]) || !CanConvertToInt32(type[INDEX_FIVE])) {
        NAPI_ERR_LOG("GetType failed");
        return;
    }
    context->cloudMediaAssetTaskStatus_ = static_cast<CloudMediaAssetTaskStatus>(std::stoi(type[INDEX_ZERO]));
    context->cloudMediaTaskPauseCause_ = static_cast<CloudMediaTaskPauseCause>(std::stoi(type[INDEX_FIVE]));
    std::string taskInfo = "totalcount: " + type[INDEX_ONE] + "," +
                           "totalSize: " + type[INDEX_TWO] + "," +
                           "remainCount: " + type[INDEX_THREE] + "," +
                           "remainSize: " + type[INDEX_FOUR];
    context->taskInfo_ = taskInfo;
}

static void GetCloudMediaAssetStatusCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudMediaAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        napi_value cloudMediaAssetStatus = CloudMediaAssetStatusNapi::NewCloudMediaAssetStatusNapi(env, context);
        jsContext->data = cloudMediaAssetStatus;
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CloudMediaAssetManagerNapi::JSGetCloudMediaAssetStatus(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSGetCloudMediaAssetStatus");

    auto asyncContext = make_unique<CloudMediaAssetAsyncContext>();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "GetCloudMediaAssetStatus",
        GetCloudMediaAssetStatusExecute, GetCloudMediaAssetStatusCompleteCallback);
}
} // namespace OHOS::Media