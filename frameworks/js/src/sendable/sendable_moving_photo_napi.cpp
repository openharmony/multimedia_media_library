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

#include "sendable_moving_photo_napi.h"

#include <fcntl.h>
#include <unistd.h>

#include "directory_ex.h"
#include "file_uri.h"
#include "media_file_utils.h"
#include "media_library_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_utils.h"
#include "sendable_medialibrary_napi_utils.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"

using namespace std;

namespace OHOS {
namespace Media {

static const string SENDABLE_MOVING_PHOTO_NAPI_CLASS = "MovingPhoto";
thread_local napi_ref SendableMovingPhotoNapi::constructor_ = nullptr;

napi_value SendableMovingPhotoNapi::Init(napi_env env, napi_value exports)
{
    napi_value ctorObj;
    napi_property_descriptor mov_photo_props[] = {
        DECLARE_NAPI_FUNCTION("getUri", JSGetUri),
    };
    napi_define_sendable_class(env, SENDABLE_MOVING_PHOTO_NAPI_CLASS.c_str(), NAPI_AUTO_LENGTH,
                               Constructor, nullptr,
                               sizeof(mov_photo_props) / sizeof(mov_photo_props[0]),
                               mov_photo_props, nullptr, &ctorObj);
    NAPI_CALL(env, napi_create_reference(env, ctorObj, NAPI_INIT_REF_COUNT, &constructor_));
    NAPI_CALL(env, napi_set_named_property(env, exports, SENDABLE_MOVING_PHOTO_NAPI_CLASS.c_str(), ctorObj));
    return exports;
}

napi_value SendableMovingPhotoNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Invalid call to constructor");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    napi_valuetype valueType;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
    CHECK_ARGS(env, napi_typeof(env, argv[PARAM0], &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_string, "Invalid argument type");
    size_t result;
    char photoUri[PATH_MAX];
    CHECK_ARGS(env, napi_get_value_string_utf8(env, argv[PARAM0], photoUri, PATH_MAX, &result), JS_INNER_FAIL);

    unique_ptr<SendableMovingPhotoNapi> obj = make_unique<SendableMovingPhotoNapi>(string(photoUri));
    CHECK_ARGS(env, napi_wrap_sendable(env, thisVar, reinterpret_cast<void*>(obj.get()),
               SendableMovingPhotoNapi::Destructor, nullptr), JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void SendableMovingPhotoNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* movingPhotoNapi = reinterpret_cast<SendableMovingPhotoNapi*>(nativeObject);
    if (movingPhotoNapi == nullptr) {
        return;
    }

    delete movingPhotoNapi;
    movingPhotoNapi = nullptr;
}

string SendableMovingPhotoNapi::GetUri()
{
    return photoUri_;
}

SourceMode SendableMovingPhotoNapi::GetSourceMode()
{
    return sourceMode_;
}

void SendableMovingPhotoNapi::SetSourceMode(SourceMode sourceMode)
{
    sourceMode_ = sourceMode;
}

static int32_t OpenReadOnlyVideo(const std::string& videoUri, bool isMediaLibUri)
{
    if (isMediaLibUri) {
        std::string openVideoUri = videoUri;
        MediaFileUtils::UriAppendKeyValue(openVideoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD,
            OPEN_MOVING_PHOTO_VIDEO);
        Uri uri(openVideoUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    AppFileService::ModuleFileUri::FileUri fileUri(videoUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        NAPI_ERR_LOG("Failed to open read only video file");
        return -1;
    }
    return fd;
}

static int32_t OpenReadOnlyImage(const std::string& imageUri, bool isMediaLibUri)
{
    if (isMediaLibUri) {
        Uri uri(imageUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    AppFileService::ModuleFileUri::FileUri fileUri(imageUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        NAPI_ERR_LOG("Failed to open read only image file");
        return -1;
    }
    return fd;
}

int32_t SendableMovingPhotoNapi::OpenReadOnlyFile(const std::string& uri, bool isReadImage)
{
    if (uri.empty()) {
        NAPI_ERR_LOG("Failed to open read only file, uri is empty");
        return -1;
    }
    std::string curUri = uri;
    bool isMediaLibUri = MediaFileUtils::IsMediaLibraryUri(uri);
    if (!isMediaLibUri) {
        std::vector<std::string> uris;
        if (!MediaFileUtils::SplitMovingPhotoUri(uri, uris)) {
            NAPI_ERR_LOG("Failed to open read only file, split moving photo failed");
            return -1;
        }
        curUri = uris[isReadImage ? MOVING_PHOTO_IMAGE_POS : MOVING_PHOTO_VIDEO_POS];
    }
    return isReadImage ? OpenReadOnlyImage(curUri, isMediaLibUri) : OpenReadOnlyVideo(curUri, isMediaLibUri);
}

napi_value SendableMovingPhotoNapi::NewMovingPhotoNapi(napi_env env, const string& photoUri,
    SourceMode sourceMode)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_value napiStringUri = nullptr;
    napi_status status = napi_create_string_utf8(env, photoUri.c_str(), NAPI_AUTO_LENGTH, &napiStringUri);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to create napi string, napi status: %{public}d",
        static_cast<int>(status));
    status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to get reference of constructor, napi status: %{public}d",
        static_cast<int>(status));
    status = napi_new_instance(env, constructor, 1, &napiStringUri, &instance);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to get new instance of moving photo, napi status: %{public}d",
        static_cast<int>(status));
    CHECK_COND_RET(instance != nullptr, nullptr, "Instance is nullptr");

    SendableMovingPhotoNapi* movingPhotoNapi = nullptr;
    status = napi_unwrap_sendable(env, instance, reinterpret_cast<void**>(&movingPhotoNapi));
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to unwarp instance of SendableMovingPhotoNapi");
    CHECK_COND_RET(movingPhotoNapi != nullptr, nullptr, "movingPhotoNapi is nullptr");
    movingPhotoNapi->SetSourceMode(sourceMode);
    return instance;
}

napi_value SendableMovingPhotoNapi::JSGetUri(napi_env env, napi_callback_info info)
{
    SendableMovingPhotoNapi *obj = nullptr;
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }

    CHECK_ARGS(env, napi_unwrap_sendable(env, thisVar, reinterpret_cast<void **>(&obj)), JS_INNER_FAIL);
    if (obj == nullptr) {
        NapiError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetUri().c_str(), NAPI_AUTO_LENGTH, &jsResult), JS_INNER_FAIL);
    return jsResult;
}
} // namespace Media
} // namespace OHOS