/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_class_name.h"
#include "cloud_enhancement_task_state_ani.h"

using namespace std;

namespace OHOS {
namespace Media {
ani_status CloudEnhancementTaskStateAni::Init(ani_env *env)
{
    static const char *className = PAH_ANI_CLASS_CLOUD_ENHANCEMENT_TASK_STATE_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getTransferredFileSize", nullptr,
            reinterpret_cast<void *>(CloudEnhancementTaskStateAni::GetTransferredFileSize)},
        ani_native_function {"getTotalFileSize", nullptr,
            reinterpret_cast<void *>(CloudEnhancementTaskStateAni::GetTotalFileSize)},
        ani_native_function {"getExpectedDuration", nullptr,
            reinterpret_cast<void *>(CloudEnhancementTaskStateAni::GetExpectedDuration)},
        ani_native_function {"getStatusCode", nullptr,
            reinterpret_cast<void *>(CloudEnhancementTaskStateAni::GetStatusCode)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status CloudEnhancementTaskStateAni::BindAniAttributes(ani_env *env, ani_class cls, ani_object object,
    unique_ptr<CloudEnhancementTaskStateAni> &nativeHandle)
{
    CHECK_COND_RET(nativeHandle != nullptr, ANI_ERROR, "CloudEnhancementTaskStateAni is nullptr");
    ani_method taskStageSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>taskStage", nullptr, &taskStageSetter), "No <set>taskStage");
    ani_enum_item taskStage = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, nativeHandle->GetCloudEnhancementTaskStage(), taskStage),
        "Get taskStage index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, taskStageSetter, taskStage), "<set>taskStage fail");
    return ANI_OK;
}

ani_object CloudEnhancementTaskStateAni::NewCloudEnhancementTaskStateAni(ani_env *env,
    unique_ptr<CloudEnhancementAniContext> &context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "CloudEnhancementAniContext is nullptr");
    static const char *className = PAH_ANI_CLASS_CLOUD_ENHANCEMENT_TASK_STATE_HANDLE.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        ani_object nullobj = nullptr;
        return nullobj;
    }
    unique_ptr<CloudEnhancementTaskStateAni> nativeHandle = make_unique<CloudEnhancementTaskStateAni>();
    nativeHandle->SetCloudEnhancementTaskStage(context->cloudEnhancementTaskStage_);
    nativeHandle->SetTransferredFileSize(context->transferredFileSize_);
    nativeHandle->SetTotalFileSize(context->totalFileSize_);
    nativeHandle->SetExpectedDuration(context->expectedDuration_);
    nativeHandle->SetStatusCode(context->statusCode_);

    ani_object aniObject = Constructor(env, cls, nativeHandle);
    CHECK_COND_RET(aniObject != nullptr, nullptr, "Failed to construct CloudEnhancementTaskStateAni");
    CHECK_COND_RET(BindAniAttributes(env, cls, aniObject, nativeHandle) == ANI_OK, nullptr,
        "CloudEnhancementTaskStateAni BindAniAttributes Fail");
    nativeHandle.release();
    return aniObject;
}

ani_object CloudEnhancementTaskStateAni::Constructor(ani_env *env, ani_class cls,
    unique_ptr<CloudEnhancementTaskStateAni> &nativeHandle)
{
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object aniObject;
    if (ANI_OK !=env->Object_New(cls, ctor, &aniObject, reinterpret_cast<ani_long>(nativeHandle.get()))) {
        ANI_ERR_LOG("New CloudEnhancementTaskStateAni Fail");
        return nullptr;
    }
    return aniObject;
}

CloudEnhancementTaskStateAni* CloudEnhancementTaskStateAni::Unwrap(ani_env *env, ani_object aniObject)
{
    ani_long nativeHandle;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &nativeHandle)) {
        ANI_ERR_LOG("Failed to get nativeHandle");
        return nullptr;
    }
    return reinterpret_cast<CloudEnhancementTaskStateAni*>(nativeHandle);
}

CloudEnhancementTaskStage CloudEnhancementTaskStateAni::GetCloudEnhancementTaskStage() const
{
    return this->cloudEnhancementTaskStage_;
}

void CloudEnhancementTaskStateAni::SetCloudEnhancementTaskStage(CloudEnhancementTaskStage cloudEnhancementTaskStage)
{
    this->cloudEnhancementTaskStage_ = cloudEnhancementTaskStage;
}

ani_double CloudEnhancementTaskStateAni::GetTransferredFileSize(ani_env *env, ani_object object)
{
    CloudEnhancementTaskStateAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudEnhancementTaskStateAni::UNDEFINED,
        "CloudEnhancementTaskStateAni is nullptr");
    return static_cast<ani_double>(nativeHandle->transferredFileSize_);
}

void CloudEnhancementTaskStateAni::SetTransferredFileSize(int32_t transferredFileSize)
{
    this->transferredFileSize_ = transferredFileSize;
}

ani_double CloudEnhancementTaskStateAni::GetTotalFileSize(ani_env *env, ani_object object)
{
    CloudEnhancementTaskStateAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudEnhancementTaskStateAni::UNDEFINED,
        "CloudEnhancementTaskStateAni is nullptr");
    return static_cast<ani_double>(nativeHandle->totalFileSize_);
}

void CloudEnhancementTaskStateAni::SetTotalFileSize(int32_t totalFileSize)
{
    this->totalFileSize_ = totalFileSize;
}

ani_double CloudEnhancementTaskStateAni::GetExpectedDuration(ani_env *env, ani_object object)
{
    CloudEnhancementTaskStateAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudEnhancementTaskStateAni::UNDEFINED,
        "CloudEnhancementTaskStateAni is nullptr");
    return static_cast<ani_double>(nativeHandle->expectedDuration_);
}

void CloudEnhancementTaskStateAni::SetExpectedDuration(int32_t expectedDuration)
{
    this->expectedDuration_ = expectedDuration;
}

ani_double CloudEnhancementTaskStateAni::GetStatusCode(ani_env *env, ani_object object)
{
    CloudEnhancementTaskStateAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudEnhancementTaskStateAni::UNDEFINED,
        "CloudEnhancementTaskStateAni is nullptr");
    return static_cast<ani_double>(nativeHandle->statusCode_);
}

void CloudEnhancementTaskStateAni::SetStatusCode(int32_t statusCode)
{
    this->statusCode_ = statusCode;
}
} // namespace Media
} // namespace OHOS
