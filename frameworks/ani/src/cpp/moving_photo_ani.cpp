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
#include <iostream>
#include <array>
#include "ani_class_name.h"
#include "media_log.h"
#include "moving_photo_ani.h"
#include "medialibrary_ani_utils.h"

using namespace OHOS::Media;

ani_status MovingPhotoAni::MovingPhotoInit(ani_env *env)
{
    static const char *className = ANI_CLASS_MOVING_PHOTO.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        MEDIA_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }
    std::array methods = {
        ani_native_function {"requestContent1", nullptr, reinterpret_cast<void *>(MovingPhotoAni::RequestContent1)},
        ani_native_function {"requestContent2", nullptr, reinterpret_cast<void *>(MovingPhotoAni::RequestContent2)},
        ani_native_function {"requestContent3", nullptr, reinterpret_cast<void *>(MovingPhotoAni::RequestContent3)},
        ani_native_function {"getUri", nullptr, reinterpret_cast<void *>(MovingPhotoAni::GetUri)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        MEDIA_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }

    ANI_INFO_LOG("MovingPhotoInit ok");
    return ANI_OK;
}

ani_object MovingPhotoAni::Constructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz,
    [[maybe_unused]] ani_object context)
{
    auto nativeMovingPhotoHandle = std::make_unique<MovingPhotoAni>();

    static const char *className = ANI_CLASS_MOVING_PHOTO.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        MEDIA_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        MEDIA_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object movingPhoto_object;
    if (ANI_OK != env->Object_New(cls, ctor, &movingPhoto_object,
        reinterpret_cast<ani_long>(nativeMovingPhotoHandle.get()))) {
        MEDIA_ERR_LOG("New MovingPhoto Fail");
        return nullptr;
    }

    nativeMovingPhotoHandle.release();
    return movingPhoto_object;
}

MovingPhotoAni* MovingPhotoAni::Unwrap(ani_env *env, ani_object object)
{
    ani_long movingPhoto;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeMovingPhoto", &movingPhoto)) {
        MEDIA_ERR_LOG("get nativeMovingPhoto Fail");
        return nullptr;
    }
    return reinterpret_cast<MovingPhotoAni*>(movingPhoto);
}

std::string MovingPhotoAni::GetUriInner()
{
    return photoUri_;
}

void MovingPhotoAni::RequestContent1(ani_env *env, ani_object object, ani_string imageFileUri, ani_string videoFileUri)
{
    auto movingPhotoAni = Unwrap(env, object);
    if (movingPhotoAni == nullptr) {
        ANI_ERR_LOG("movingPhotoAni is nullptr");
        return;
    }

    std::string imageFileUriStr;
    MediaLibraryAniUtils::GetString(env, imageFileUri, imageFileUriStr);
    std::string videoFileUriStr;
    MediaLibraryAniUtils::GetString(env, videoFileUri, videoFileUriStr);
    return;
}

void MovingPhotoAni::RequestContent2(ani_env *env, ani_object object, ani_enum_item resourceType, ani_string fileUri)
{
    return;
}

void MovingPhotoAni::RequestContent3(ani_env *env, ani_object object, ani_enum_item resourceType)
{
    return;
}

ani_string MovingPhotoAni::GetUri(ani_env *env, ani_object object)
{
    ani_string result = nullptr;
    auto movingPhotoAni = Unwrap(env, object);
    if (movingPhotoAni == nullptr) {
        ANI_ERR_LOG("movingPhotoAni is nullptr");
        return result;
    }

    const std::string& uri = movingPhotoAni->GetUriInner();
    const char *utf8String = uri.c_str();
    const ani_size stringLength = uri.length();
    env->String_NewUTF8(utf8String, stringLength, &result);
    return result;
}