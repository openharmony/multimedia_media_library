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

#include "moving_photo_napi.h"

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

static const string MOVING_PHOTO_NAPI_CLASS = "MovingPhoto";
thread_local napi_ref MovingPhotoNapi::constructor_ = nullptr;

napi_value MovingPhotoNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = MOVING_PHOTO_NAPI_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_FUNCTION("requestContent", JSRequestContent),
            DECLARE_NAPI_FUNCTION("getUri", JSGetUri),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value MovingPhotoNapi::Constructor(napi_env env, napi_callback_info info)
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

    unique_ptr<MovingPhotoNapi> obj = make_unique<MovingPhotoNapi>(string(photoUri));
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), MovingPhotoNapi::Destructor, nullptr,
            nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void MovingPhotoNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* movingPhotoNapi = reinterpret_cast<MovingPhotoNapi*>(nativeObject);
    if (movingPhotoNapi == nullptr) {
        return;
    }

    delete movingPhotoNapi;
    movingPhotoNapi = nullptr;
}

string MovingPhotoNapi::GetUri()
{
    return photoUri_;
}

SourceMode MovingPhotoNapi::GetSourceMode()
{
    return sourceMode_;
}

void MovingPhotoNapi::SetSourceMode(SourceMode sourceMode)
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
        NAPI_ERR_LOG("Failed to open read only video file, errno:%{public}d", errno);
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
        NAPI_ERR_LOG("Failed to open read only image file, errno: %{public}d", errno);
        return -1;
    }
    return fd;
}

int32_t MovingPhotoNapi::OpenReadOnlyFile(const std::string& uri, bool isReadImage)
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

int32_t MovingPhotoNapi::OpenReadOnlyLivePhoto(const string& destLivePhotoUri)
{
    if (destLivePhotoUri.empty()) {
        NAPI_ERR_LOG("Failed to open read only file, uri is empty");
        return E_ERR;
    }
    if (MediaFileUtils::IsMediaLibraryUri(destLivePhotoUri)) {
        string livePhotoUri = destLivePhotoUri;
        MediaFileUtils::UriAppendKeyValue(livePhotoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD,
            OPEN_PRIVATE_LIVE_PHOTO);
        Uri uri(livePhotoUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    return E_ERR;
}

static int32_t CopyFileFromMediaLibrary(int32_t srcFd, int32_t destFd)
{
    constexpr size_t bufferSize = 4096;
    char buffer[bufferSize];
    ssize_t bytesRead;
    ssize_t bytesWritten;
    while ((bytesRead = read(srcFd, buffer, bufferSize)) > 0) {
        bytesWritten = write(destFd, buffer, bytesRead);
        if (bytesWritten != bytesRead) {
            NAPI_ERR_LOG("Failed to copy file from srcFd=%{public}d to destFd=%{public}d, errno=%{public}d",
                srcFd, destFd, errno);
            return E_HAS_FS_ERROR;
        }
    }

    if (bytesRead < 0) {
        NAPI_ERR_LOG("Failed to read from srcFd=%{public}d, errno=%{public}d", srcFd, errno);
        return E_HAS_FS_ERROR;
    }
    return E_OK;
}

static int32_t WriteToSandboxUri(int32_t srcFd, const string& sandboxUri)
{
    UniqueFd srcUniqueFd(srcFd);

    AppFileService::ModuleFileUri::FileUri fileUri(sandboxUri);
    string destPath = fileUri.GetRealPath();
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateFile(destPath)) {
        NAPI_ERR_LOG("Create empty dest file in sandbox failed, path:%{private}s", destPath.c_str());
        return E_HAS_FS_ERROR;
    }
    int32_t destFd = MediaFileUtils::OpenFile(destPath, MEDIA_FILEMODE_READWRITE);
    if (destFd < 0) {
        NAPI_ERR_LOG("Open dest file failed, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }
    UniqueFd destUniqueFd(destFd);

    if (ftruncate(destUniqueFd.Get(), 0) == -1) {
        NAPI_ERR_LOG("Truncate old file in sandbox failed, error:%{public}d", errno);
        return E_HAS_FS_ERROR;
    }
    return CopyFileFromMediaLibrary(srcUniqueFd.Get(), destUniqueFd.Get());
}

static bool HandleFd(int32_t& fd)
{
    if (fd == E_ERR) {
        fd = E_HAS_FS_ERROR;
        return false;
    } else if (fd < 0) {
        NAPI_ERR_LOG("Open failed due to OpenFile failure, error: %{public}d", fd);
        return false;
    }
    return true;
}

static int32_t RequestContentToSandbox(MovingPhotoAsyncContext* context)
{
    string movingPhotoUri = context->movingPhotoUri;
    if (context->sourceMode == SourceMode::ORIGINAL_MODE) {
        MediaFileUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    if (!context->destImageUri.empty()) {
        int32_t imageFd = MovingPhotoNapi::OpenReadOnlyFile(movingPhotoUri, true);
        CHECK_COND_RET(HandleFd(imageFd), imageFd, "Open source image file failed");
        int32_t ret = WriteToSandboxUri(imageFd, context->destImageUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write image to sandbox failed");
    }
    if (!context->destVideoUri.empty()) {
        int32_t videoFd = MovingPhotoNapi::OpenReadOnlyFile(movingPhotoUri, false);
        CHECK_COND_RET(HandleFd(videoFd), videoFd, "Open source video file failed");
        int32_t ret = WriteToSandboxUri(videoFd, context->destVideoUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write video to sandbox failed");
    }
    if (!context->destLivePhotoUri.empty()) {
        int32_t livePhotoFd = MovingPhotoNapi::OpenReadOnlyLivePhoto(movingPhotoUri);
        CHECK_COND_RET(HandleFd(livePhotoFd), livePhotoFd, "Open source video file failed");
        int32_t ret = WriteToSandboxUri(livePhotoFd, context->destLivePhotoUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write video to sandbox failed");
    }

    return E_OK;
}

static int32_t AcquireFdForArrayBuffer(MovingPhotoAsyncContext* context)
{
    int32_t fd = 0;
    string movingPhotoUri = context->movingPhotoUri;
    if (context->sourceMode == SourceMode::ORIGINAL_MODE) {
        MediaFileUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    switch (context->resourceType) {
        case ResourceType::IMAGE_RESOURCE: {
            fd = MovingPhotoNapi::OpenReadOnlyFile(movingPhotoUri, true);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source image file failed");
            return fd;
        }
        case ResourceType::VIDEO_RESOURCE:
            fd = MovingPhotoNapi::OpenReadOnlyFile(movingPhotoUri, false);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source video file failed");
            return fd;
        case ResourceType::PRIVATE_MOVING_PHOTO_RESOURCE:
            fd = MovingPhotoNapi::OpenReadOnlyLivePhoto(movingPhotoUri);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source video file failed");
            return fd;
        default:
            NAPI_ERR_LOG("Invalid resource type: %{public}d", static_cast<int32_t>(context->resourceType));
            return -EINVAL;
    }
}

static int32_t RequestContentToArrayBuffer(napi_env env, MovingPhotoAsyncContext* context)
{
    int32_t fd = AcquireFdForArrayBuffer(context);
    if (fd < 0) {
        return fd;
    }
    UniqueFd uniqueFd(fd);
    
    off_t fileLen = lseek(uniqueFd.Get(), 0, SEEK_END);
    if (fileLen < 0) {
        NAPI_ERR_LOG("Failed to get file length, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }

    off_t ret = lseek(uniqueFd.Get(), 0, SEEK_SET);
    if (ret < 0) {
        NAPI_ERR_LOG("Failed to reset file offset, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }

    size_t fileSize = static_cast<size_t>(fileLen);

    context->arrayBufferData = malloc(fileSize);
    if (!context->arrayBufferData) {
        NAPI_ERR_LOG("Failed to malloc array buffer data, moving photo uri is %{public}s, resource type is %{public}d",
            context->movingPhotoUri.c_str(), static_cast<int32_t>(context->resourceType));
        return E_HAS_FS_ERROR;
    }

    size_t readBytes = static_cast<size_t>(read(uniqueFd.Get(), context->arrayBufferData, fileSize));
    if (readBytes != fileSize) {
        NAPI_ERR_LOG("read file failed, read bytes is %{public}zu, actual length is %{public}zu, "
            "error: %{public}d", readBytes, fileSize, errno);
        free(context->arrayBufferData);
        context->arrayBufferData = nullptr;
        return E_HAS_FS_ERROR;
    }

    context->arrayBufferLength = fileSize;
    return E_OK;
}

static bool IsValidResourceType(int32_t resourceType)
{
    return (resourceType == static_cast<int>(ResourceType::IMAGE_RESOURCE) ||
        resourceType == static_cast<int>(ResourceType::VIDEO_RESOURCE) ||
        resourceType == static_cast<int>(ResourceType::PRIVATE_MOVING_PHOTO_RESOURCE));
}

static napi_value ParseArgsForRequestContent(napi_env env, size_t argc, const napi_value argv[],
    MovingPhotoNapi* thisArg, unique_ptr<MovingPhotoAsyncContext>& context)
{
    CHECK_COND_WITH_MESSAGE(env, (argc == ARGS_ONE || argc == ARGS_TWO), "Invalid number of arguments");
    CHECK_COND(env, thisArg != nullptr, JS_INNER_FAIL);
    context->movingPhotoUri = thisArg->GetUri();
    context->sourceMode = thisArg->GetSourceMode();

    int32_t resourceType = 0;
    if (argc == ARGS_ONE) {
        // return by array buffer
        CHECK_ARGS(env, napi_get_value_int32(env, argv[ARGS_ZERO], &resourceType), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, IsValidResourceType(resourceType), "Invalid resource type");
        context->requestContentMode = MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER;
        context->resourceType = static_cast<ResourceType>(resourceType);
    } else if (argc == ARGS_TWO) {
        context->requestContentMode = MovingPhotoAsyncContext::WRITE_TO_SANDBOX;
        napi_valuetype valueTypeFront;
        napi_valuetype valueTypeBack;
        CHECK_ARGS(env, napi_typeof(env, argv[ARGS_ZERO], &valueTypeFront), JS_INNER_FAIL);
        CHECK_ARGS(env, napi_typeof(env, argv[ARGS_ONE], &valueTypeBack), JS_INNER_FAIL);
        if (valueTypeFront == napi_string && valueTypeBack == napi_string) {
            // write both image and video to sandbox
            CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, argv[ARGS_ZERO], context->destImageUri),
                JS_INNER_FAIL);
            CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, argv[ARGS_ONE], context->destVideoUri),
                JS_INNER_FAIL);
        } else if (valueTypeFront == napi_number && valueTypeBack == napi_string) {
            // write image or video to sandbox
            CHECK_ARGS(env, napi_get_value_int32(env, argv[ARGS_ZERO], &resourceType), JS_INNER_FAIL);
            CHECK_COND_WITH_MESSAGE(env, IsValidResourceType(resourceType), "Invalid resource type");
            if (resourceType == static_cast<int>(ResourceType::IMAGE_RESOURCE)) {
                CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, argv[ARGS_ONE],
                    context->destImageUri), JS_INNER_FAIL);
            } else if (resourceType == static_cast<int>(ResourceType::VIDEO_RESOURCE)) {
                CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, argv[ARGS_ONE],
                    context->destVideoUri), JS_INNER_FAIL);
            } else {
                CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, argv[ARGS_ONE],
                    context->destLivePhotoUri), JS_INNER_FAIL);
            }
            context->resourceType = static_cast<ResourceType>(resourceType);
        } else {
            NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, __FUNCTION__, __LINE__, "Invalid type of arguments");
            return nullptr;
        }
    }
    RETURN_NAPI_TRUE(env);
}

static void RequestContentExecute(napi_env env, void *data)
{
    auto* context = static_cast<MovingPhotoAsyncContext*>(data);
    int32_t ret;
    switch (context->requestContentMode) {
        case MovingPhotoAsyncContext::WRITE_TO_SANDBOX:
            ret = RequestContentToSandbox(context);
            break;
        case MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER:
            ret = RequestContentToArrayBuffer(env, context);
            break;
        default:
            NAPI_ERR_LOG("Invalid request content mode: %{public}d", static_cast<int32_t>(context->requestContentMode));
            context->error = OHOS_INVALID_PARAM_CODE;
            return;
    }
    if (ret != E_OK) {
        context->SaveError(ret);
        return;
    }
}

static void RequestContentComplete(napi_env env, napi_status status, void *data)
{
    MovingPhotoAsyncContext *context = static_cast<MovingPhotoAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    napi_value outBuffer = nullptr;
    if (context->error == E_OK && context->requestContentMode == MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER) {
        napi_status status = napi_create_external_arraybuffer(
            env, context->arrayBufferData, context->arrayBufferLength,
            [](napi_env env, void* data, void* hint) { free(data); }, nullptr, &outBuffer);
        if (status != napi_ok) {
            NAPI_ERR_LOG("Failed to create array buffer object, uri is %{public}s, resource type is %{public}d",
                context->movingPhotoUri.c_str(), context->resourceType);
            free(context->arrayBufferData);
            context->arrayBufferData = nullptr;
            context->error = JS_INNER_FAIL;
        }
    } else if (context->arrayBufferData != nullptr) {
        free(context->arrayBufferData);
        context->arrayBufferData = nullptr;
    }

    unique_ptr<JSAsyncContextOutput> outContext = make_unique<JSAsyncContextOutput>();
    outContext->status = false;
    napi_get_undefined(env, &outContext->data);

    if (context->error != E_OK) {
        context->HandleError(env, outContext->error);
    } else {
        outContext->status = true;
        if (context->requestContentMode == MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER) {
            outContext->data = outBuffer;
        }
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, nullptr,
                                                   context->work, *outContext);
    } else {
        NAPI_ERR_LOG("Async work is nullptr");
    }
    delete context;
}

napi_value MovingPhotoNapi::JSRequestContent(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);

    unique_ptr<MovingPhotoAsyncContext> asyncContext = make_unique<MovingPhotoAsyncContext>();
    MovingPhotoNapi* nativeObject;
    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&nativeObject)), JS_INNER_FAIL);
    CHECK_NULLPTR_RET(ParseArgsForRequestContent(env, argc, argv, nativeObject, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSRequestContent",
        RequestContentExecute, RequestContentComplete);
}

napi_value MovingPhotoNapi::NewMovingPhotoNapi(napi_env env, const string& photoUri,
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

    MovingPhotoNapi* movingPhotoNapi = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void**>(&movingPhotoNapi));
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to unwarp instance of MovingPhotoNapi");
    CHECK_COND_RET(movingPhotoNapi != nullptr, nullptr, "movingPhotoNapi is nullptr");
    movingPhotoNapi->SetSourceMode(sourceMode);
    return instance;
}

napi_value MovingPhotoNapi::JSGetUri(napi_env env, napi_callback_info info)
{
    MovingPhotoNapi *obj = nullptr;
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }

    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj)), JS_INNER_FAIL);
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
