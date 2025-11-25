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

#include "cloud_enhancement_task_state_napi.h"

#include <fcntl.h>
#include <unistd.h>

#include "directory_ex.h"
#include "file_uri.h"
#include "media_file_utils.h"
#include "media_library_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_utils.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"

using namespace std;

namespace OHOS {
namespace Media {

static const string CLOUD_ENHANCEMENT_TASK_STATE_CLASS = "CloudEnhancementTaskState";
thread_local napi_ref CloudEnhancementTaskStateNapi::constructor_ = nullptr;

napi_value CloudEnhancementTaskStateNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = CLOUD_ENHANCEMENT_TASK_STATE_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_GETTER("taskStage", JSGetTaskStage),
            DECLARE_NAPI_GETTER("transferredFileSize", JSGetTransferredFileSize),
            DECLARE_NAPI_GETTER("totalFileSize", JSGetTotalFileSize),
            DECLARE_NAPI_GETTER("expectedDuration", JSGetExpectedDuration),
            DECLARE_NAPI_GETTER("statusCode", JSGetStatusCode),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value CloudEnhancementTaskStateNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Invalid call to constructor");

    size_t argc = ARGS_ZERO;
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ZERO, "Number of args is invalid");

    unique_ptr<CloudEnhancementTaskStateNapi> obj = make_unique<CloudEnhancementTaskStateNapi>();
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), CloudEnhancementTaskStateNapi::Destructor,
        nullptr, nullptr), JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void CloudEnhancementTaskStateNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* cloudEnhancementTaskStateNapi = reinterpret_cast<CloudEnhancementTaskStateNapi*>(nativeObject);
    if (cloudEnhancementTaskStateNapi == nullptr) {
        return;
    }

    delete cloudEnhancementTaskStateNapi;
    cloudEnhancementTaskStateNapi = nullptr;
}

CloudEnhancementTaskStage CloudEnhancementTaskStateNapi::GetCloudEnhancementTaskStage() const
{
    return this->cloudEnhancementTaskStage_;
}

void CloudEnhancementTaskStateNapi::SetCloudEnhancementTaskStage(CloudEnhancementTaskStage cloudEnhancementTaskStage)
{
    this->cloudEnhancementTaskStage_ = cloudEnhancementTaskStage;
}

int32_t CloudEnhancementTaskStateNapi::GetTransferredFileSize() const
{
    return this->transferredFileSize_;
}

void CloudEnhancementTaskStateNapi::SetTransferredFileSize(int32_t transferredFileSize)
{
    this->transferredFileSize_ = transferredFileSize;
}

int32_t CloudEnhancementTaskStateNapi::GetTotalFileSize() const
{
    return this->totalFileSize_;
}

void CloudEnhancementTaskStateNapi::SetTotalFileSize(int32_t totalFileSize)
{
    this->totalFileSize_ = totalFileSize;
}

int32_t CloudEnhancementTaskStateNapi::GetExpectedDuration() const
{
    return this->expectedDuration_;
}

void CloudEnhancementTaskStateNapi::SetExpectedDuration(int32_t expectedDuration)
{
    this->expectedDuration_ = expectedDuration;
}

int32_t CloudEnhancementTaskStateNapi::GetStatusCode() const
{
    return this->statusCode_;
}

void CloudEnhancementTaskStateNapi::SetStatusCode(int32_t statusCode)
{
    this->statusCode_ = statusCode;
}

napi_value CloudEnhancementTaskStateNapi::NewCloudEnhancementTaskStateNapi(napi_env env,
    CloudEnhancementAsyncContext* context)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to get reference of constructor, napi status: %{public}d",
        static_cast<int>(status));
    status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    CHECK_COND_RET(status == napi_ok, nullptr,
        "Failed to get new instance of cloud enhancement task state, napi status: %{public}d",
        static_cast<int>(status));
    CHECK_COND_RET(instance != nullptr, nullptr, "Instance is nullptr");

    CloudEnhancementTaskStateNapi* cloudEnhancementTaskStateNapi = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void**>(&cloudEnhancementTaskStateNapi));
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to unwarp instance of CloudEnhancementTaskStateNapi");
    CHECK_COND_RET(cloudEnhancementTaskStateNapi != nullptr, nullptr, "cloudEnhancementTaskStateNapi is nullptr");
    cloudEnhancementTaskStateNapi->SetCloudEnhancementTaskStage(context->cloudEnhancementTaskStage_);
    cloudEnhancementTaskStateNapi->SetTransferredFileSize(context->transferredFileSize_);
    cloudEnhancementTaskStateNapi->SetTotalFileSize(context->totalFileSize_);
    cloudEnhancementTaskStateNapi->SetExpectedDuration(context->expectedDuration_);
    cloudEnhancementTaskStateNapi->SetStatusCode(context->statusCode_);
    return instance;
}

napi_value CloudEnhancementTaskStateNapi::JSGetTaskStage(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudEnhancementTaskStateNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        CloudEnhancementTaskStage cloudEnhancementTaskStage = obj->GetCloudEnhancementTaskStage();
        napi_create_int32(env, static_cast<int32_t>(cloudEnhancementTaskStage), &result);
    } else {
        NAPI_ERR_LOG("Failed to get taskStage");
    }
    return result;
}

napi_value CloudEnhancementTaskStateNapi::JSGetTransferredFileSize(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudEnhancementTaskStateNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        int32_t transferredFileSize = obj->GetTransferredFileSize();
        if (transferredFileSize != UNDEFINED) {
            napi_create_int32(env, transferredFileSize, &result);
        }
    } else {
        NAPI_ERR_LOG("Failed to get transferredFileSize");
    }
    return result;
}

napi_value CloudEnhancementTaskStateNapi::JSGetTotalFileSize(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudEnhancementTaskStateNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        int32_t totalFileSize = obj->GetTotalFileSize();
        if (totalFileSize != UNDEFINED) {
            napi_create_int32(env, totalFileSize, &result);
        }
    } else {
        NAPI_ERR_LOG("Failed to get totalFileSize");
    }
    return result;
}

napi_value CloudEnhancementTaskStateNapi::JSGetExpectedDuration(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudEnhancementTaskStateNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        int32_t expectedDuration = obj->GetExpectedDuration();
        if (expectedDuration != UNDEFINED) {
            napi_create_int32(env, expectedDuration, &result);
        }
    } else {
        NAPI_ERR_LOG("Failed to get expectedDuration");
    }
    return result;
}

napi_value CloudEnhancementTaskStateNapi::JSGetStatusCode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudEnhancementTaskStateNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        int32_t statusCode = obj->GetStatusCode();
        if (statusCode != UNDEFINED) {
            napi_create_int32(env, statusCode, &result);
        }
    } else {
        NAPI_ERR_LOG("Failed to get statusCode");
    }
    return result;
}

} // namespace Media
} // namespace OHOS
