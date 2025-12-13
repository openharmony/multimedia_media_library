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

#include "cloud_media_asset_status_napi.h"
#include "medialibrary_client_errno.h"

using namespace std;
namespace OHOS::Media {
static const string CLOUD_MEDIA_ASSET_STATUS_NAPI = "CloudMediaAssetStatus";
thread_local napi_ref CloudMediaAssetStatusNapi::constructor_ = nullptr;

napi_value CloudMediaAssetStatusNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = CLOUD_MEDIA_ASSET_STATUS_NAPI,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_GETTER("taskStatus", JSGetTaskStatus),
            DECLARE_NAPI_GETTER("errorCode", JSGetErrorCode),
            DECLARE_NAPI_GETTER("taskInfo", JSGetTaskInfo),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value CloudMediaAssetStatusNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Invalid call to constructor");

    size_t argc = ARGS_ZERO;
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ZERO, "Number of args is invalid");

    unique_ptr<CloudMediaAssetStatusNapi> obj = make_unique<CloudMediaAssetStatusNapi>();
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), CloudMediaAssetStatusNapi::Destructor,
        nullptr, nullptr), JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void CloudMediaAssetStatusNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* cloudMediaAssetStatusNapi = reinterpret_cast<CloudMediaAssetStatusNapi*>(nativeObject);
    if (cloudMediaAssetStatusNapi == nullptr) {
        NAPI_ERR_LOG("cloudMediaAssetStatusNapi is nullptr");
        return;
    }

    delete cloudMediaAssetStatusNapi;
    cloudMediaAssetStatusNapi = nullptr;
}

CloudMediaAssetTaskStatus CloudMediaAssetStatusNapi::GetCloudMediaAssetTaskStatus() const
{
    return this->cloudMediaAssetTaskStatus_;
}

void CloudMediaAssetStatusNapi::SetCloudMediaAssetTaskStatus(CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus)
{
    this->cloudMediaAssetTaskStatus_ = cloudMediaAssetTaskStatus;
}

CloudMediaTaskPauseCause CloudMediaAssetStatusNapi::GetCloudMediaTaskPauseCause() const
{
    return this->cloudMediaTaskPauseCause_;
}

void CloudMediaAssetStatusNapi::SetCloudMediaTaskPauseCause(CloudMediaTaskPauseCause cloudMediaTaskPauseCause)
{
    this->cloudMediaTaskPauseCause_ = cloudMediaTaskPauseCause;
}

std::string CloudMediaAssetStatusNapi::GetTaskInfo() const
{
    return this->taskInfo_;
}

void CloudMediaAssetStatusNapi::SetTaskInfo(const std::string &taskInfo)
{
    this->taskInfo_ = taskInfo;
}

napi_value CloudMediaAssetStatusNapi::NewCloudMediaAssetStatusNapi(napi_env env,
    CloudMediaAssetAsyncContext* context)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to get reference of constructor, napi status: %{public}d",
        static_cast<int>(status));
    status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    CHECK_COND_RET(status == napi_ok, nullptr,
        "Failed to get new instance of cloud media asset manager task state, napi status: %{public}d",
        static_cast<int>(status));
    CHECK_COND_RET(instance != nullptr, nullptr, "Instance is nullptr");

    CloudMediaAssetStatusNapi* cloudMediaAssetStatusNapi = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void**>(&cloudMediaAssetStatusNapi));
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to unwarp instance of CloudMediaAssetStatusNapi");
    CHECK_COND_RET(cloudMediaAssetStatusNapi != nullptr, nullptr, "cloudMediaAssetStatusNapi is nullptr");
    cloudMediaAssetStatusNapi->SetCloudMediaAssetTaskStatus(context->cloudMediaAssetTaskStatus_);
    cloudMediaAssetStatusNapi->SetCloudMediaTaskPauseCause(context->cloudMediaTaskPauseCause_);
    cloudMediaAssetStatusNapi->SetTaskInfo(context->taskInfo_);
    return instance;
}

napi_value CloudMediaAssetStatusNapi::JSGetTaskStatus(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudMediaAssetStatusNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        NAPI_ERR_LOG("Failed to get taskStatus");
        return nullptr;
    }
    CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus = obj->GetCloudMediaAssetTaskStatus();
    napi_create_int32(env, static_cast<int32_t>(cloudMediaAssetTaskStatus), &result);
    return result;
}

napi_value CloudMediaAssetStatusNapi::JSGetErrorCode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudMediaAssetStatusNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        NAPI_ERR_LOG("Failed to get errorCode");
        return nullptr;
    }
    CloudMediaTaskPauseCause cloudMediaTaskPauseCause = obj->GetCloudMediaTaskPauseCause();
    napi_create_int32(env, static_cast<int32_t>(cloudMediaTaskPauseCause), &result);
    return result;
}

napi_value CloudMediaAssetStatusNapi::JSGetTaskInfo(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudMediaAssetStatusNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        NAPI_ERR_LOG("Failed to get taskInfo");
        return nullptr;
    }
    std::string taskInfo = obj->GetTaskInfo();
    napi_create_string_utf8(env, taskInfo.c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}
}