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

#include "cloud_enhancement_ani.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
ani_status CloudEnhancementAni::CloudEnhancementAniInit(ani_env *env)
{
    static const char *className = "Lcloud_enhancement/CloudEnhancementHandle;";
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        env->ThrowError(ani_error(status));
    }

    std::array methods = {
        ani_native_function {"create", nullptr,
            reinterpret_cast<void *>(CloudEnhancementAni::Constructor)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        env->ThrowError(ani_error(status));
    }
    return ANI_OK;
}

ani_object CloudEnhancementAni::Constructor(ani_env *env, [[maybe_unused]] ani_class clazz, ani_object context)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL,
            "The cloud enhancement instance can be called only by system apps");
        return nullptr;
    }

    std::unique_ptr<CloudEnhancementAni> nativeHandle = std::make_unique<CloudEnhancementAni>();
    static const char *className = "Lcloud_enhancement/CloudEnhancementHandle;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object aniObject;
    if (ANI_OK !=env->Object_New(cls, ctor, &aniObject, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ANI_ERR_LOG("New MediaAssetChangeRequest Fail");
        return nullptr;
    }

    return aniObject;
}

CloudEnhancementAni* CloudEnhancementAni::Unwrap(ani_env *env, ani_object aniObject)
{
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &context)) {
        return nullptr;
    }
    return reinterpret_cast<CloudEnhancementAni*>(context);
}
} // namespace Media
} // namespace OHOS
