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

#define MLOG_TAG "CloudEnhancementNapi"

#include "cloud_enhancement_napi.h"

#include <unordered_set>

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
#include "cloud_enhancement_task_state_napi.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
using namespace OHOS::MediaEnhance;
#endif

namespace OHOS::Media {
static const string CLOUD_ENHANCEMENT_CLASS = "CloudEnhancement";
thread_local napi_ref CloudEnhancementNapi::constructor_ = nullptr;

constexpr int32_t STRONG_ASSOCIATION = 1;

napi_value CloudEnhancementNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = { .name = CLOUD_ENHANCEMENT_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_STATIC_FUNCTION("getCloudEnhancementInstance", JSGetCloudEnhancementInstance),
            DECLARE_NAPI_FUNCTION("submitCloudEnhancementTasks", JSSubmitCloudEnhancementTasks),
            DECLARE_NAPI_FUNCTION("prioritizeCloudEnhancementTask", JSPrioritizeCloudEnhancementTask),
            DECLARE_NAPI_FUNCTION("cancelCloudEnhancementTasks", JSCancelCloudEnhancementTasks),
            DECLARE_NAPI_FUNCTION("cancelAllCloudEnhancementTasks", JSCancelAllCloudEnhancementTasks),
            DECLARE_NAPI_FUNCTION("queryCloudEnhancementTaskState", JSQueryCloudEnhancementTaskState),
            DECLARE_NAPI_FUNCTION("syncCloudEnhancementTaskStatus", JSSyncCloudEnhancementTaskStatus),
            DECLARE_NAPI_FUNCTION("getCloudEnhancementPair", JSGetCloudEnhancementPair),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value CloudEnhancementNapi::Constructor(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL,
            "The cloud enhancement instance can be called only by system apps");
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

    unique_ptr<CloudEnhancementNapi> obj = make_unique<CloudEnhancementNapi>();
    CHECK_COND(env, obj != nullptr, JS_INNER_FAIL);
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), CloudEnhancementNapi::Destructor, nullptr,
            nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void CloudEnhancementNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* cloudEnhancement = reinterpret_cast<CloudEnhancementNapi*>(nativeObject);
    if (cloudEnhancement == nullptr) {
        return;
    }
    delete cloudEnhancement;
    cloudEnhancement = nullptr;
}

static bool CheckWhetherInitSuccess(napi_env env, napi_value value, bool checkIsValid)
{
    napi_value propertyNames;
    uint32_t propertyLength;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType != napi_object) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_get_property_names(env, value, &propertyNames), false);
    NAPI_CALL_BASE(env, napi_get_array_length(env, propertyNames, &propertyLength), false);
    if (propertyLength == 0) {
        return false;
    }
    if (checkIsValid && (!UserFileClient::IsValid())) {
        NAPI_ERR_LOG("UserFileClient is not valid");
        return false;
    }
    return true;
}

napi_value CloudEnhancementNapi::JSGetCloudEnhancementInstance(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCloudEnhancementInstance");

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
        NAPI_ERR_LOG("Init Cloud Enhancement Instance is failed");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

bool CloudEnhancementNapi::InitUserFileClient(napi_env env, napi_callback_info info)
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

napi_status CloudEnhancementNapi::ParseArgGetPhotoAsset(napi_env env, napi_value arg, int &fileId, std::string &uri,
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

static napi_value ParseArgsSubmitCloudEnhancementTasks(napi_env env, napi_callback_info info,
    unique_ptr<CloudEnhancementAsyncContext>& context)
{
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, ARGS_TWO, ARGS_TWO) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, CloudEnhancementNapi::InitUserFileClient(env, info), JS_INNER_FAIL);

    napi_valuetype valueType = napi_undefined;
    CHECK_ARGS(env, napi_typeof(env, context->argv[PARAM1], &valueType), JS_INNER_FAIL);
    CHECK_COND(env, valueType == napi_boolean, JS_INNER_FAIL);

    bool hasCloudWatermark = false;
    if (napi_get_value_bool(env, context->argv[PARAM1], &hasCloudWatermark) != napi_ok) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    vector<string> uris;
    vector<napi_value> napiValues;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM0], napiValues));
    CHECK_COND_WITH_MESSAGE(env, !napiValues.empty(), "array is empty");
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_INNER_FAIL);
    if (valueType == napi_object) { // array of asset object
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetUriArrayFromAssets(env, napiValues, uris));
    } else {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid type");
        return nullptr;
    }

    CHECK_COND_WITH_MESSAGE(env, !uris.empty(), "Failed to check empty array");
    for (const auto& uri : uris) {
        CHECK_COND(env, uri.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos, JS_E_URI);
    }
    
    context->hasCloudWatermark_ = hasCloudWatermark;
    context->predicates.In(PhotoColumn::MEDIA_ID, uris);
    context->uris.assign(uris.begin(), uris.end());
    RETURN_NAPI_TRUE(env);
}

static void SubmitCloudEnhancementTasksExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("SubmitCloudEnhancementTasksExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_ADD;
    MediaLibraryNapiUtils::UriAppendKeyValue(uriStr, MEDIA_OPERN_KEYWORD, to_string(context->hasCloudWatermark_));
    Uri addTaskUri(uriStr);
    context->valuesBucket.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION, STRONG_ASSOCIATION);
    int32_t changeRows = UserFileClient::Update(addTaskUri, context->predicates, context->valuesBucket);
    if (changeRows < 0) {
        context->SaveError(changeRows);
        NAPI_ERR_LOG("Submit cloud enhancement tasks failed, err: %{public}d", changeRows);
        return;
    }
    NAPI_INFO_LOG("SubmitCloudEnhancementTasksExecute Success");
}

static void SubmitCloudEnhancementTasksCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
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

napi_value CloudEnhancementNapi::JSSubmitCloudEnhancementTasks(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSSubmitCloudEnhancementTasks");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsSubmitCloudEnhancementTasks(env, info, asyncContext), "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "SubmitCloudEnhancementTasks",
        SubmitCloudEnhancementTasksExecute, SubmitCloudEnhancementTasksCompleteCallback);
}

static napi_status ParseArgPrioritize(napi_env env, napi_callback_info info,
    unique_ptr<CloudEnhancementAsyncContext>& context)
{
    napi_value thisVar = nullptr;
    context->argc = ARGS_ONE;
    GET_JS_ARGS(env, info, context->argc, context->argv, thisVar);

    if (CloudEnhancementNapi::ParseArgGetPhotoAsset(env, context->argv[PARAM0], context->fileId, context->photoUri,
        context->displayName) != napi_ok) {
        NAPI_ERR_LOG("requestMedia ParseArgGetPhotoAsset error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestMedia ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }

    NAPI_INFO_LOG("Parse Arg: %{public}d, %{private}s, %{public}s", context->fileId, context->photoUri.c_str(),
        context->displayName.c_str());

    return napi_ok;
}

static void PrioritizeCloudEnhancementTaskExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("PrioritizeCloudEnhancementTaskExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_PRIORITIZE;
    Uri prioritizeTaskUri(uriStr);
    context->predicates.EqualTo(MediaColumn::MEDIA_ID, context->photoUri);
    context->valuesBucket.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION, STRONG_ASSOCIATION);
    int32_t changedRows = UserFileClient::Update(prioritizeTaskUri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        NAPI_ERR_LOG("Prioritize cloud enhancement task failed, err: %{public}d", changedRows);
    }
    NAPI_INFO_LOG("PrioritizeCloudEnhancementTaskExecute Success");
}

static void PrioritizeCloudEnhancementTaskCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
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

napi_value CloudEnhancementNapi::JSPrioritizeCloudEnhancementTask(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSPrioritizeCloudEnhancementTask");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND(env, CloudEnhancementNapi::InitUserFileClient(env, info), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, ParseArgPrioritize(env, info, asyncContext) == napi_ok, "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPrioritizeCloudEnhancementTask",
        PrioritizeCloudEnhancementTaskExecute, PrioritizeCloudEnhancementTaskCompleteCallback);
}

static napi_value ParseArgsCancelCloudEnhancementTasks(napi_env env, napi_callback_info info,
    unique_ptr<CloudEnhancementAsyncContext>& context)
{
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, ARGS_ONE, ARGS_ONE) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, CloudEnhancementNapi::InitUserFileClient(env, info), JS_INNER_FAIL);

    napi_valuetype valueType = napi_undefined;
    CHECK_ARGS(env, napi_typeof(env, context->argv[PARAM0], &valueType), JS_INNER_FAIL);
    CHECK_COND(env, valueType == napi_object, JS_INNER_FAIL);

    vector<string> uris;
    vector<napi_value> napiValues;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM0], napiValues));
    CHECK_COND_WITH_MESSAGE(env, !napiValues.empty(), "array is empty");
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_INNER_FAIL);
    if (valueType == napi_object) { // array of asset object
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetUriArrayFromAssets(env, napiValues, uris));
    } else {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid type");
        return nullptr;
    }

    CHECK_COND_WITH_MESSAGE(env, !uris.empty(), "Failed to check empty array");
    for (const auto& uri : uris) {
        NAPI_INFO_LOG("CloudEnhancementNapi ParseArgsCancelCloudEnhancementTasks: %{public}s", uri.c_str());
        CHECK_COND(env, uri.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos, JS_E_URI);
    }

    context->predicates.In(PhotoColumn::MEDIA_ID, uris);
    context->uris.assign(uris.begin(), uris.end());
    RETURN_NAPI_TRUE(env);
}

static void CancelCloudEnhancementTasksExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("CancelCloudEnhancementTasksExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_CANCEL;
    Uri cancelTaskUri(uriStr);
    string fileUri = context->uris.front();
    context->valuesBucket.Put(MediaColumn::MEDIA_ID, fileUri);
    int32_t changeRows = UserFileClient::Update(cancelTaskUri, context->predicates, context->valuesBucket);
    if (changeRows < 0) {
        context->SaveError(changeRows);
        NAPI_ERR_LOG("Cancel cloud enhancement tasks failed, err: %{public}d", changeRows);
    }
    NAPI_INFO_LOG("CancelCloudEnhancementTasksExecute Success");
}

static void CancelCloudEnhancementTasksCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
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

napi_value CloudEnhancementNapi::JSCancelCloudEnhancementTasks(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSCancelCloudEnhancementTasks");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCancelCloudEnhancementTasks(env, info, asyncContext), "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "CancelCloudEnhancementTasks",
        CancelCloudEnhancementTasksExecute, CancelCloudEnhancementTasksCompleteCallback);
}

static void CancelAllCloudEnhancementTasksExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("CancelAllCloudEnhancementTasksExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_CANCEL_ALL;
    Uri cancelAllTaskUri(uriStr);
    context->valuesBucket.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION, STRONG_ASSOCIATION);
    int32_t changeRows = UserFileClient::Update(cancelAllTaskUri, context->predicates, context->valuesBucket);
    if (changeRows < 0) {
        context->SaveError(changeRows);
        NAPI_ERR_LOG("Cancel all cloud enhancement tasks failed, err: %{public}d", changeRows);
    }
    NAPI_INFO_LOG("CancelAllCloudEnhancementTasksExecute Success");
}

static void CancelAllCloudEnhancementTasksCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
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

napi_value CloudEnhancementNapi::JSCancelAllCloudEnhancementTasks(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSCancelAllCloudEnhancementTasks");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, asyncContext, ARGS_ZERO, ARGS_ZERO) == napi_ok,
        "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "CancelAllCloudEnhancementTasks",
        CancelAllCloudEnhancementTasksExecute, CancelAllCloudEnhancementTasksCompleteCallback);
}

static napi_status ParseArgQuery(napi_env env, napi_callback_info info,
    unique_ptr<CloudEnhancementAsyncContext>& context)
{
    napi_value thisVar = nullptr;
    context->argc = ARGS_ONE;
    GET_JS_ARGS(env, info, context->argc, context->argv, thisVar);

    if (CloudEnhancementNapi::ParseArgGetPhotoAsset(env, context->argv[PARAM0], context->fileId, context->photoUri,
        context->displayName) != napi_ok) {
        NAPI_ERR_LOG("requestMedia ParseArgGetPhotoAsset error");
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "requestMedia ParseArgGetPhotoAsset error");
        return napi_invalid_arg;
    }

    NAPI_INFO_LOG("Parse Arg: %{public}d, %{private}s, %{public}s", context->fileId, context->photoUri.c_str(),
        context->displayName.c_str());

    return napi_ok;
}

static void FillTaskStageWithClientQuery(CloudEnhancementAsyncContext* context, string &photoId)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    shared_ptr<MediaEnhanceClient> enhancementClient_ = make_shared<MediaEnhanceClient>(TASK_TYPE::TYPE_CAMERA);
    if (!enhancementClient_->IsConnected()) {
        enhancementClient_->LoadSA();
    }
    MediaEnhanceBundle queryResult = enhancementClient_->QueryTaskState(photoId);
    int32_t currentState = queryResult.GetInt(QueryConstants::CURRENT_STATE);
    if (currentState == QueryConstants::EN_EXCEPTION) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_EXCEPTION;
        return;
    }
    if (currentState == QueryConstants::EN_PREPARING) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_PREPARING;
    } else if (currentState == QueryConstants::EN_UPLOADING) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_UPLOADING;
        context->transferredFileSize_ = queryResult.GetInt(QueryConstants::UPLOAD_PROGRESS);
        context->totalFileSize_ = queryResult.GetInt(QueryConstants::UPLOAD_SIZE);
    } else if (currentState == QueryConstants::EN_EXECUTING) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_EXECUTING;
        context->expectedDuration_ = queryResult.GetInt(QueryConstants::EXECUTE_TIME);
    } else if (currentState == QueryConstants::EN_DOWNLOADING) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_DOWNLOADING;
    }
#endif
}

static void QueryCloudEnhancementTaskStateExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryCloudEnhancementTaskStateExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_QUERY;
    Uri queryTaskUri(uriStr);
    vector<string> columns = {
        MediaColumn::MEDIA_ID, PhotoColumn::PHOTO_ID,
        PhotoColumn::PHOTO_CE_AVAILABLE, PhotoColumn::PHOTO_CE_STATUS_CODE
    };
    int errCode = 0;
    context->predicates.EqualTo(MediaColumn::MEDIA_ID, context->photoUri);
    auto resultSet = UserFileClient::Query(queryTaskUri, context->predicates, columns, errCode);
    if (resultSet == nullptr || resultSet->GoToNextRow() != E_OK) {
        NAPI_ERR_LOG("ResultSet is nullptr, errCode is %{public}d", errCode);
        context->SaveError(JS_INNER_FAIL);
        return;
    }
    int32_t fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
    string photoId = get<string>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_ID, resultSet, TYPE_STRING));
    int32_t ceAvailable =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_CE_AVAILABLE, resultSet, TYPE_INT32));
    int32_t CEErrorCode = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_CE_STATUS_CODE,
        resultSet, TYPE_INT32));
    NAPI_INFO_LOG("query fileId: %{public}d, photoId: %{private}s, ceAvailable: %{public}d",
        fileId, photoId.c_str(), ceAvailable);

    if (ceAvailable == static_cast<int32_t>(CE_AVAILABLE::NOT_SUPPORT)) {
        NAPI_ERR_LOG("photo not support cloud enhancement, fileId: %{public}d", fileId);
        return;
    }
    // 任务成功或失败，不能再查云增强，否则会让云增强误报准备中
    if (ceAvailable == static_cast<int32_t>(CE_AVAILABLE::SUCCESS)) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_COMPLETED;
        return;
    }
    if (ceAvailable == static_cast<int32_t>(CE_AVAILABLE::FAILED_RETRY) ||
        ceAvailable == static_cast<int32_t>(CE_AVAILABLE::FAILED)) {
        context->cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_FAILED;
        context->statusCode_ = CEErrorCode;
        NAPI_INFO_LOG("TASK_STAGE_FAILED, fileId: %{public}d, statusCode: %{public}d", fileId, ceAvailable);
        return;
    }
    FillTaskStageWithClientQuery(context, photoId);
}

static void QueryCloudEnhancementTaskStateCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        napi_value cloudEnhancementTaskState =
            CloudEnhancementTaskStateNapi::NewCloudEnhancementTaskStateNapi(env, context);
        jsContext->data = cloudEnhancementTaskState;
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

napi_value CloudEnhancementNapi::JSQueryCloudEnhancementTaskState(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSQueryCloudEnhancementTaskState");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND(env, CloudEnhancementNapi::InitUserFileClient(env, info), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, ParseArgQuery(env, info, asyncContext) == napi_ok, "Failed to parse args");
    
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "QueryCloudEnhancementTaskState",
        QueryCloudEnhancementTaskStateExecute, QueryCloudEnhancementTaskStateCompleteCallback);
}

static void SyncCloudEnhancementTaskStatusExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("SyncCloudEnhancementTaskStatusExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    string uriStr = PAH_CLOUD_ENHANCEMENT_SYNC;
    Uri syncUri(uriStr);
    context->valuesBucket.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION, STRONG_ASSOCIATION);
    int32_t changeRows = UserFileClient::Update(syncUri, context->predicates, context->valuesBucket);
    if (changeRows < 0) {
        context->SaveError(changeRows);
        NAPI_ERR_LOG("sync cloud enhancement failed, err: %{public}d", changeRows);
    }
    NAPI_INFO_LOG("CloudEnhancementNapi SyncCloudEnhancementTaskStatusExecute Success");
}

static void SyncCloudEnhancementTaskStatusCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
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

napi_value CloudEnhancementNapi::JSSyncCloudEnhancementTaskStatus(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("JSSyncCloudEnhancementTaskStatus");

    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, asyncContext, ARGS_ZERO, ARGS_ZERO) == napi_ok,
        "Failed to parse args");
   
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "SyncCloudEnhancementTaskStatus",
        SyncCloudEnhancementTaskStatusExecute, SyncCloudEnhancementTaskStatusCompleteCallback);
}

bool CloudEnhancementAsyncContext::GetPairAsset()
{
    if (fetchFileResult->GetCount() != 1) {
        NAPI_ERR_LOG("Object number of fetchfileResult is not one");
        return false;
    }
    fileAsset = fetchFileResult->GetFirstObject();
    if (fileAsset == nullptr) {
        NAPI_ERR_LOG("Fail to get fileAsset from fetchFileResult");
        return false;
    }
    return true;
}

static void GetCloudEnhancementPairExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCloudEnhancementPairExecute");

    auto* context = static_cast<CloudEnhancementAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "AsyncContext is null");
    std::string  uriStr = PAH_CLOUD_ENHANCEMENT_GET_PAIR;
    Uri getPairUri(uriStr);
    std::vector<std::string> columns;
    int errCode = 0;
    NAPI_INFO_LOG("CloudEnhancementNAPI context->photoUri is %{private}s", context->photoUri.c_str());
    context->predicates.EqualTo(MediaColumn::MEDIA_ID, context->photoUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet =
        UserFileClient::Query(getPairUri, context->predicates, columns, errCode);
    if (resultSet == nullptr || resultSet->GoToNextRow() != E_OK) {
        NAPI_ERR_LOG("Resultset is nullptr, errCode is %{public}d", errCode);
        context->SaveError(JS_INNER_FAIL);
        return;
    }
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    if (!context->GetPairAsset()) {
        NAPI_ERR_LOG("Fail to getPairAsset");
        return;
    }

    NAPI_INFO_LOG("CloudEnhancementNapi GetCloudEnhancementPairExecute Success");
}

static void GetNapiPairFileAsset(napi_env env, CloudEnhancementAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    // Create PhotiAsset object using the contents of fileAsset
    if (context->fileAsset == nullptr) {
        NAPI_ERR_LOG("No fetch file result found!");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain Fetch File Result");
        return;
    }
    if (context->fileAsset->GetPhotoEditTime() != 0) {
        NAPI_WARN_LOG("PhotoAsset is edited");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain Fetch File Result");
        return;
    }
    context->fileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    napi_value jsFileAsset = FileAssetNapi::CreateFileAsset(env, context->fileAsset);
    if (jsFileAsset == nullptr) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to create js object for Fetch File Result");
    } else {
        jsContext->data = jsFileAsset;
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    }
}

static void GetCloudEnhancementPairCompleteCallback(napi_env env, napi_status status, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCloudEnhancementPairCompleteCallback");

    CloudEnhancementAsyncContext *context = static_cast<CloudEnhancementAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, jsContext->error);
    } else {
        GetNapiPairFileAsset(env, context, jsContext);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
            context->work, *jsContext);
    }
    delete context;
}

napi_value CloudEnhancementNapi::JSGetCloudEnhancementPair(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetCloudEnhancementPair");
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    auto asyncContext = make_unique<CloudEnhancementAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->assetType = TYPE_PHOTO;

    CHECK_COND(env, CloudEnhancementNapi::InitUserFileClient(env, info), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, ParseArgQuery(env, info, asyncContext) == napi_ok, "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "GetCloudEnhancementPair",
        GetCloudEnhancementPairExecute, GetCloudEnhancementPairCompleteCallback);
}
} // namespace OHOS::Media