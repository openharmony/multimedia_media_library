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

#include "cloud_media_asset_status_ani.h"

#include "ani_class_name.h"
#include "directory_ex.h"
#include "file_uri.h"
#include "media_file_utils.h"
#include "media_library_ani.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_utils.h"
#include "userfile_client.h"
#include "cloud_media_asset_types.h"

namespace OHOS::Media {
ani_status CloudMediaAssetStatusAni::Init(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = PAH_ANI_CLASS_CLOUD_MEDIA_ASSET_STATUS_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"GettaskStatus", nullptr,
            reinterpret_cast<void *>(CloudMediaAssetStatusAni::CloudMediaAssetGetTaskStatus)},
        ani_native_function {"GettaskInfo", nullptr,
            reinterpret_cast<void *>(CloudMediaAssetStatusAni::CloudMediaAssetGetTaskInfo)},
        ani_native_function {"GeterrorCode", nullptr,
            reinterpret_cast<void *>(CloudMediaAssetStatusAni::CloudMediaAssetGetErrorCode)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_object CloudMediaAssetStatusAni::Constructor(ani_env *env, ani_class cls,
    std::unique_ptr<CloudMediaAssetStatusAni> &nativeHandle)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(nativeHandle != nullptr, nullptr, "nativeHandle is nullptr");
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object aniObject;
    if (ANI_OK != env->Object_New(cls, ctor, &aniObject, reinterpret_cast<ani_long>(nativeHandle.get()))) {
        ANI_ERR_LOG("New CloudMediaAssetStatusAni Fail");
        return nullptr;
    }
    return aniObject;
}

CloudMediaAssetTaskStatus CloudMediaAssetStatusAni::GetCloudMediaAssetTaskStatus() const
{
    return this->cloudMediaAssetTaskStatus_;
}

void CloudMediaAssetStatusAni::SetCloudMediaAssetTaskStatus(CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus)
{
    this->cloudMediaAssetTaskStatus_ = cloudMediaAssetTaskStatus;
}

CloudMediaTaskPauseCause CloudMediaAssetStatusAni::GetCloudMediaTaskPauseCause() const
{
    return this->cloudMediaTaskPauseCause_;
}

void CloudMediaAssetStatusAni::SetCloudMediaTaskPauseCause(CloudMediaTaskPauseCause cloudMediaTaskPauseCause)
{
    this->cloudMediaTaskPauseCause_ = cloudMediaTaskPauseCause;
}

std::string CloudMediaAssetStatusAni::GetTaskInfo() const
{
    return this->taskInfo_;
}

void CloudMediaAssetStatusAni::SetTaskInfo(const std::string &taskInfo)
{
    this->taskInfo_ = taskInfo;
}

ani_object CloudMediaAssetStatusAni::NewCloudMediaAssetStatusAni(ani_env *env,
    std::unique_ptr<CloudMediaAssetAsyncAniContext> &context)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(context != nullptr, nullptr, "CloudMediaAssetAsyncAniContext is nullptr");
    static const char *className = PAH_ANI_CLASS_CLOUD_MEDIA_ASSET_STATUS_HANDLE.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }
    std::unique_ptr<CloudMediaAssetStatusAni> nativeHandle = make_unique<CloudMediaAssetStatusAni>();
    CHECK_COND_RET(nativeHandle != nullptr, nullptr, "CloudMediaAssetStatusAni is nullptr");
    nativeHandle->SetCloudMediaAssetTaskStatus(context->cloudMediaAssetTaskStatus_);
    nativeHandle->SetCloudMediaTaskPauseCause(context->cloudMediaTaskPauseCause_);
    nativeHandle->SetTaskInfo(context->taskInfo_);

    ani_object aniObject = Constructor(env, cls, nativeHandle);
    (void)nativeHandle.release();
    return aniObject;
}

CloudMediaAssetStatusAni* CloudMediaAssetStatusAni::Unwrap(ani_env *env, ani_object aniObject)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_long nativeHandle;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &nativeHandle)) {
        ANI_ERR_LOG("Failed to get nativeHandle");
        return nullptr;
    }
    return reinterpret_cast<CloudMediaAssetStatusAni*>(nativeHandle);
}

ani_double CloudMediaAssetStatusAni::CloudMediaAssetGetTaskStatus(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, CloudMediaAssetStatusAni::UNDEFINED, "env is nullptr");
    CloudMediaAssetStatusAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudMediaAssetStatusAni::UNDEFINED,
        "GetTaskStatus failed ,CloudMediaAssetStatusAni is nullptr");
    return static_cast<ani_double>(nativeHandle->cloudMediaAssetTaskStatus_);
}

ani_double CloudMediaAssetStatusAni::CloudMediaAssetGetErrorCode(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, CloudMediaAssetStatusAni::UNDEFINED, "env is nullptr");
    CloudMediaAssetStatusAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, CloudMediaAssetStatusAni::UNDEFINED,
        "GetErrorCode failed ,CloudMediaAssetStatusAni is nullptr");
    return static_cast<ani_double>(nativeHandle->cloudMediaTaskPauseCause_);
}

ani_string CloudMediaAssetStatusAni::CloudMediaAssetGetTaskInfo(ani_env *env, ani_object object)
{
    ani_string Info = {};
    CHECK_COND_RET(env != nullptr, UNDEFINED_STR, "env is nullptr");
    CloudMediaAssetStatusAni* nativeHandle = Unwrap(env, object);
    CHECK_COND_RET(nativeHandle != nullptr, UNDEFINED_STR,
        "GetTaskInfo failed ,CloudMediaAssetStatusAni is nullptr");

    auto status = MediaLibraryAniUtils::ToAniString(env, nativeHandle->taskInfo_, Info);
    if (status != ANI_OK) {
        AniError::ThrowError(env, JS_INNER_FAIL, "Failed to get indexProgress ani string");
    }
    return Info;
}
} // namespace OHOS::Media
