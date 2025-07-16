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
#define MLOG_TAG "MovingPhotoAni"
#include "moving_photo_ani.h"

#include <cstddef>
#include <iostream>
#include <array>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <securec.h>

#include "ani_class_name.h"
#include "medialibrary_ani_utils.h"
#include "media_file_utils.h"
#include "file_uri.h"
#include "unique_fd.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"
#include "ability_context.h"
#include "application_context.h"
#include "media_call_transcode.h"

namespace OHOS {
namespace Media {

static std::function<void(int, int, std::string)> callback_;
static SafeMap<std::string, bool> isMovingPhotoTranscoderMap;
static SafeMap<std::string, MovingPhotoAsyncContext *> requestContentCompleteResult;
static std::mutex isMovingPhotoTranscoderMapMutex;
static std::mutex requestContentCompleteResultMutex;
ani_status MovingPhotoAni::Init(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = PAH_ANI_CLASS_MOVING_PHOTO_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }
    std::array methods = {
        ani_native_function {"requestContentByImageFileAndVideoFile", nullptr,
            reinterpret_cast<void *>(MovingPhotoAni::RequestContentByImageFileAndVideoFile)},
        ani_native_function {"requestContentByResourceTypeAndFile", nullptr,
            reinterpret_cast<void *>(MovingPhotoAni::RequestContentByResourceTypeAndFile)},
        ani_native_function {"requestContentByResourceType", nullptr,
            reinterpret_cast<void *>(MovingPhotoAni::RequestContentByResourceType)},
        ani_native_function {"getUri", nullptr, reinterpret_cast<void *>(MovingPhotoAni::GetUri)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_object MovingPhotoAni::NewMovingPhotoAni(ani_env *env, const string& photoUri, SourceMode sourceMode,
    MovingPhotoParam movingPhotoParam, const std::function<void(int, int, std::string)> callbacks)
{
    ani_string photoUriAni;
    if (ANI_OK != MediaLibraryAniUtils::ToAniString(env, photoUri, photoUriAni)) {
        ANI_ERR_LOG("ToAniString photoUri fail");
        return nullptr;
    }
    ani_object movingPhotoObject = Constructor(env, nullptr, photoUriAni);
    MovingPhotoAni* movingPhotoAni = Unwrap(env, movingPhotoObject);
    if (movingPhotoAni == nullptr) {
        ANI_ERR_LOG("movingPhotoAni is nullptr");
        return nullptr;
    }
    movingPhotoAni->SetSourceMode(sourceMode);
    movingPhotoAni->SetRequestId(movingPhotoParam.requestId);
    movingPhotoAni->SetCompatibleMode(movingPhotoParam.compatibleMode);
    movingPhotoAni->SetMovingPhotoCallback(callbacks);
    return movingPhotoObject;
}

void MovingPhotoAni::SubRequestContent(int32_t fd, MovingPhotoAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    UniqueFd uniqueFd(fd);
    off_t fileLen = lseek(uniqueFd.Get(), 0, SEEK_END);
    if (fileLen < 0) {
        ANI_ERR_LOG("Failed to get file length, error: %{public}d", errno);
        context->error = E_HAS_FS_ERROR;
        return;
    }

    off_t ret = lseek(uniqueFd.Get(), 0, SEEK_SET);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to reset file offset, error: %{public}d", errno);
        context->error = E_HAS_FS_ERROR;
        return;
    }

    size_t fileSize = static_cast<size_t>(fileLen);
    context->arrayBufferData = malloc(fileSize);
    if (!context->arrayBufferData) {
        ANI_ERR_LOG("Failed to malloc array buffer data, moving photo uri is %{public}s, resource type is %{public}d",
            context->movingPhotoUri.c_str(), static_cast<int32_t>(context->resourceType));
        context->error = E_HAS_FS_ERROR;
        return;
    }
    size_t readBytes = static_cast<size_t>(read(uniqueFd.Get(), context->arrayBufferData, fileSize));
    if (readBytes != fileSize) {
        ANI_ERR_LOG("read file failed, read bytes is %{public}zu, actual length is %{public}zu, "
            "error: %{public}d", readBytes, fileSize, errno);
        free(context->arrayBufferData);
        context->arrayBufferData = nullptr;
        context->error = E_HAS_FS_ERROR;
        return;
    }
    context->arrayBufferLength = fileSize;
    return;
}

ani_object MovingPhotoAni::Constructor(ani_env *env, [[maybe_unused]] ani_class clazz, ani_string photoUriAni)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    std::string photoUri;
    if (ANI_OK != MediaLibraryAniUtils::GetString(env, photoUriAni, photoUri)) {
        ANI_ERR_LOG("Failed to get photoUri");
        return nullptr;
    }
    unique_ptr<MovingPhotoAni> obj = make_unique<MovingPhotoAni>(photoUri);
    CHECK_COND_RET(obj != nullptr, nullptr, "obj is nullptr");
    static const char *className = PAH_ANI_CLASS_MOVING_PHOTO_HANDLE.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    ani_object movingPhotoObject;
    if (ANI_OK != env->Object_New(cls, ctor, &movingPhotoObject, reinterpret_cast<ani_long>(obj.get()))) {
        ANI_ERR_LOG("New MovingPhoto Fail");
        return nullptr;
    }
    (void)obj.release();
    return movingPhotoObject;
}

MovingPhotoAni* MovingPhotoAni::Unwrap(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_long movingPhoto;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeMovingPhoto", &movingPhoto)) {
        return nullptr;
    }
    return reinterpret_cast<MovingPhotoAni*>(movingPhoto);
}

std::string MovingPhotoAni::GetUriInner()
{
    return photoUri_;
}

SourceMode MovingPhotoAni::GetSourceMode()
{
    return sourceMode_;
}

void MovingPhotoAni::SetSourceMode(SourceMode sourceMode)
{
    sourceMode_ = sourceMode;
}

CompatibleMode MovingPhotoAni::GetCompatibleMode()
{
    return compatibleMode_;
}

void MovingPhotoAni::SetCompatibleMode(const CompatibleMode compatibleMode)
{
    compatibleMode_ = compatibleMode;
}

void MovingPhotoAni::SetMovingPhotoCallback(const std::function<void(int, int, std::string)> callback)
{
    callback_ = callback;
}

std::function<void(int, int, std::string)> MovingPhotoAni::GetMovingPhotoCallback()
{
    return callback_;
}

std::string MovingPhotoAni::GetRequestId()
{
    return requestId_;
}

void MovingPhotoAni::SetRequestId(const std::string &requestId)
{
    requestId_ = requestId;
}

int32_t MovingPhotoAni::GetFdFromUri(const std::string &uri)
{
    AppFileService::ModuleFileUri::FileUri destUri(uri);
    string destPath = destUri.GetRealPath();
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateFile(destPath)) {
        ANI_ERR_LOG("Create empty dest file in sandbox failed, path:%{private}s", destPath.c_str());
        return E_ERR;
    }
    return MediaFileUtils::OpenFile(destPath, MEDIA_FILEMODE_READWRITE);
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
    OHOS::AppFileService::ModuleFileUri::FileUri fileUri(videoUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        ANI_ERR_LOG("Failed to open read only video file, errno:%{public}d", errno);
        return -1;
    }
    return fd;
}

static int32_t OpenReadOnlyImage(const std::string& imageUri, bool isMediaLibUri)
{
    if (isMediaLibUri) {
        OHOS::Uri uri(imageUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    OHOS::AppFileService::ModuleFileUri::FileUri fileUri(imageUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        ANI_ERR_LOG("Failed to open read only image file, errno: %{public}d", errno);
        return -1;
    }
    return fd;
}

int32_t MovingPhotoAni::OpenReadOnlyFile(const std::string& uri, bool isReadImage)
{
    if (uri.empty()) {
        ANI_ERR_LOG("Failed to open read only file, uri is empty");
        return -1;
    }
    std::string curUri = uri;
    bool isMediaLibUri = MediaFileUtils::IsMediaLibraryUri(uri);
    if (!isMediaLibUri) {
        std::vector<std::string> uris;
        if (!MediaFileUtils::SplitMovingPhotoUri(uri, uris)) {
            ANI_ERR_LOG("Failed to open read only file, split moving photo failed");
            return -1;
        }
        curUri = uris[isReadImage ? MOVING_PHOTO_IMAGE_POS : MOVING_PHOTO_VIDEO_POS];
    }
    return isReadImage ? OpenReadOnlyImage(curUri, isMediaLibUri) : OpenReadOnlyVideo(curUri, isMediaLibUri);
}

int32_t MovingPhotoAni::OpenReadOnlyLivePhoto(const string& destLivePhotoUri)
{
    if (destLivePhotoUri.empty()) {
        ANI_ERR_LOG("Failed to open read only file, uri is empty");
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

int32_t MovingPhotoAni::OpenReadOnlyMetadata(const string& movingPhotoUri)
{
    if (movingPhotoUri.empty()) {
        ANI_ERR_LOG("Failed to open metadata of moving photo, uri is empty");
        return E_ERR;
    }

    if (!MediaFileUtils::IsMediaLibraryUri(movingPhotoUri)) {
        ANI_ERR_LOG("Failed to check uri of moving photo: %{private}s", movingPhotoUri.c_str());
        return E_ERR;
    }

    string movingPhotoMetadataUri = movingPhotoUri;
    MediaFileUtils::UriAppendKeyValue(
        movingPhotoMetadataUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_PRIVATE_MOVING_PHOTO_METADATA);
    Uri uri(movingPhotoMetadataUri);
    return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
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
            ANI_ERR_LOG("Failed to copy file from srcFd=%{public}d to destFd=%{public}d, errno=%{public}d",
                srcFd, destFd, errno);
            return E_HAS_FS_ERROR;
        }
    }

    if (bytesRead < 0) {
        ANI_ERR_LOG("Failed to read from srcFd=%{public}d, errno=%{public}d", srcFd, errno);
        return E_HAS_FS_ERROR;
    }
    return E_OK;
}

static int32_t WriteToSandboxUri(int32_t srcFd, const string& sandboxUri)
{
    UniqueFd srcUniqueFd(srcFd);

    OHOS::AppFileService::ModuleFileUri::FileUri fileUri(sandboxUri);
    string destPath = fileUri.GetRealPath();
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateFile(destPath)) {
        ANI_ERR_LOG("Create empty dest file in sandbox failed, path:%{private}s", destPath.c_str());
        return E_HAS_FS_ERROR;
    }
    int32_t destFd = MediaFileUtils::OpenFile(destPath, MEDIA_FILEMODE_READWRITE);
    if (destFd < 0) {
        ANI_ERR_LOG("Open dest file failed, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }
    UniqueFd destUniqueFd(destFd);

    if (ftruncate(destUniqueFd.Get(), 0) == -1) {
        ANI_ERR_LOG("Truncate old file in sandbox failed, error:%{public}d", errno);
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
        ANI_ERR_LOG("Open failed due to OpenFile failure, error: %{public}d", fd);
        return false;
    }
    return true;
}

static int32_t RequestContentToSandbox(MovingPhotoAsyncContext* context)
{
    CHECK_COND_RET(context != nullptr, E_ERR, "context is nullptr");
    string movingPhotoUri = context->movingPhotoUri;
    if (context->sourceMode == SourceMode::ORIGINAL_MODE) {
        MediaLibraryAniUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    if (!context->destImageUri.empty()) {
        int32_t imageFd = MovingPhotoAni::OpenReadOnlyFile(movingPhotoUri, true);
        CHECK_COND_RET(HandleFd(imageFd), imageFd, "Open source image file failed");
        int32_t ret = WriteToSandboxUri(imageFd, context->destImageUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write image to sandbox failed");
    }
    if (!context->destVideoUri.empty()) {
        int32_t videoFd = MovingPhotoAni::OpenReadOnlyFile(movingPhotoUri, false);
        CHECK_COND_RET(HandleFd(videoFd), videoFd, "Open source video file failed");
        int32_t ret = WriteToSandboxUri(videoFd, context->destVideoUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write video to sandbox failed");
    }
    if (!context->destLivePhotoUri.empty()) {
        int32_t livePhotoFd = MovingPhotoAni::OpenReadOnlyLivePhoto(movingPhotoUri);
        CHECK_COND_RET(HandleFd(livePhotoFd), livePhotoFd, "Open source video file failed");
        int32_t ret = WriteToSandboxUri(livePhotoFd, context->destLivePhotoUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write video to sandbox failed");
    }
    if (!context->destMetadataUri.empty()) {
        int32_t extraDataFd = MovingPhotoAni::OpenReadOnlyMetadata(movingPhotoUri);
        CHECK_COND_RET(HandleFd(extraDataFd), extraDataFd, "Open moving photo metadata failed");
        int32_t ret = WriteToSandboxUri(extraDataFd, context->destMetadataUri);
        CHECK_COND_RET(ret == E_OK, ret, "Write metadata to sandbox failed");
    }
    return E_OK;
}

static int32_t AcquireFdForArrayBuffer(MovingPhotoAsyncContext* context)
{
    CHECK_COND_RET(context != nullptr, E_ERR, "context is nullptr");
    int32_t fd = 0;
    string movingPhotoUri = context->movingPhotoUri;
    if (context->sourceMode == SourceMode::ORIGINAL_MODE) {
        MediaFileUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    }
    switch (context->resourceType) {
        case ResourceType::IMAGE_RESOURCE: {
            fd = MovingPhotoAni::OpenReadOnlyFile(movingPhotoUri, true);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source image file failed");
            return fd;
        }
        case ResourceType::VIDEO_RESOURCE:
            fd = MovingPhotoAni::OpenReadOnlyFile(movingPhotoUri, false);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source video file failed");
            return fd;
        case ResourceType::PRIVATE_MOVING_PHOTO_RESOURCE:
            fd = MovingPhotoAni::OpenReadOnlyLivePhoto(movingPhotoUri);
            CHECK_COND_RET(HandleFd(fd), fd, "Open source video file failed");
            return fd;
        case ResourceType::PRIVATE_MOVING_PHOTO_METADATA:
            fd = MovingPhotoAni::OpenReadOnlyMetadata(movingPhotoUri);
            CHECK_COND_RET(HandleFd(fd), fd, "Open moving photo metadata failed");
            return fd;
        default:
            ANI_ERR_LOG("Invalid resource type: %{public}d", static_cast<int32_t>(context->resourceType));
            return -EINVAL;
    }
}

static int32_t ArrayBufferToTranscode(ani_env *env, MovingPhotoAsyncContext* context, int32_t fd)
{
    CHECK_COND_RET(context != nullptr, E_ERR, "context is nullptr");
    {
        std::lock_guard<std::mutex> lockMutex(requestContentCompleteResultMutex);
        requestContentCompleteResult.Insert(context->requestId, context);
    }
    std::string uri = context->movingPhotoUri;
    ANI_DEBUG_LOG("uri %{public}s", uri.c_str());
    auto abilityContext = AbilityRuntime::Context::GetApplicationContext();
    if (abilityContext == nullptr) {
        ANI_INFO_LOG("abilityContext is null");
        return E_ERR;
    }
    string cachePath = abilityContext->GetCacheDir();
    string destUri = cachePath + "/" +context->requestId + ".mp4";
    ANI_DEBUG_LOG("destUri:%{public}s", destUri.c_str());
    int destFd = MovingPhotoAni::GetFdFromUri(destUri);
    if (destFd < 0) {
        context->error = destFd;
        ANI_ERR_LOG("get destFd fail");
        return E_ERR;
    }
    ani_object resultNapiValue = nullptr;
    struct stat statSrc;
    UniqueFd uniqueFd(fd);
    UniqueFd uniqueDestFd(destFd);
    if (fstat(uniqueFd.Get(), &statSrc) == E_ERR) {
        MediaLibraryAniUtils::ToAniBooleanObject(env, false, resultNapiValue);
        ANI_DEBUG_LOG("File get stat failed, %{public}d", errno);
        return E_ERR;
    }
    MediaCallTranscode::RegisterCallback(context->callback);
    bool result = MediaCallTranscode::DoTranscode(uniqueFd.Get(), uniqueDestFd.Get(), statSrc.st_size,
        context->requestId);
    if (!result) {
        ANI_INFO_LOG("DoTranscode fail");
        return E_GET_PRAMS_FAIL;
    }
    {
        std::lock_guard<std::mutex> lock(isMovingPhotoTranscoderMapMutex);
        isMovingPhotoTranscoderMap.Insert(context->requestId, true);
    }
    return E_OK;
}

static int32_t RequestContentToArrayBuffer(ani_env *env, MovingPhotoAsyncContext *context)
{
    CHECK_COND_RET(context != nullptr, E_ERR, "context is nullptr");
    int32_t fd = AcquireFdForArrayBuffer(context);
    if (fd < 0) {
        return fd;
    }
    if (context->resourceType == ResourceType::VIDEO_RESOURCE &&
        context->compatibleMode == CompatibleMode::COMPATIBLE_FORMAT_MODE) {
        {
            std::lock_guard<std::mutex> lockMutex(requestContentCompleteResultMutex);
            requestContentCompleteResult.Insert(context->requestId, context);
        }
        return ArrayBufferToTranscode(env, context, fd);
    }
    MovingPhotoAni::SubRequestContent(fd, context);
    return E_OK;
}

static bool IsValidResourceType(int32_t resourceType)
{
    return (resourceType == static_cast<int>(ResourceType::IMAGE_RESOURCE) ||
        resourceType == static_cast<int>(ResourceType::VIDEO_RESOURCE) ||
        resourceType == static_cast<int>(ResourceType::PRIVATE_MOVING_PHOTO_RESOURCE));
}

static ani_status ParseArgsByImageFileAndVideoFile(ani_env *env, ani_string imageFileUri, ani_string videoFileUri,
    MovingPhotoAni* thisArg, std::unique_ptr<MovingPhotoAsyncContext>& context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    CHECK_COND_RET(thisArg != nullptr, ANI_ERROR, "thisArg is nullptr");
    context->movingPhotoUri = thisArg->GetUriInner();
    context->sourceMode = thisArg->GetSourceMode();
    context->requestContentMode = MovingPhotoAsyncContext::WRITE_TO_SANDBOX;
    // write both image and video to sandbox
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, imageFileUri, context->destImageUri) == ANI_OK,
        ANI_INVALID_ARGS, "Failed to get imageFileUri");
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, videoFileUri, context->destVideoUri) == ANI_OK,
        ANI_INVALID_ARGS, "Failed to get videoFileUri");
    return ANI_OK;
}

static ani_status ParseArgsByResourceTypeAndFile(ani_env *env, ani_enum_item resourceTypeAni, ani_string videoFileUri,
    MovingPhotoAni* thisArg, std::unique_ptr<MovingPhotoAsyncContext>& context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    CHECK_COND_RET(thisArg != nullptr, ANI_ERROR, "thisArg is nullptr");
    context->movingPhotoUri = thisArg->GetUriInner();
    context->sourceMode = thisArg->GetSourceMode();
    context->requestContentMode = MovingPhotoAsyncContext::WRITE_TO_SANDBOX;
    // write image or video to sandbox
    int32_t resourceType = static_cast<int32_t>(ResourceType::INVALID_RESOURCE);

    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryEnumAni::EnumGetValueInt32(env, resourceTypeAni, resourceType) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get resourceType");

    CHECK_COND_WITH_RET_MESSAGE(env, IsValidResourceType(resourceType), ANI_INVALID_ARGS, "Invalid resource type");
    if (resourceType == static_cast<int>(ResourceType::IMAGE_RESOURCE)) {
        CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::GetParamStringPathMax(env, videoFileUri,
            context->destImageUri) == ANI_OK, ANI_INVALID_ARGS, "Failed to get destImageUri");
    } else if (resourceType == static_cast<int>(ResourceType::VIDEO_RESOURCE)) {
        CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::GetParamStringPathMax(env, videoFileUri,
            context->destVideoUri) == ANI_OK, ANI_INVALID_ARGS, "Failed to get destVideoUri");
    } else {
        CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::GetParamStringPathMax(env, videoFileUri,
            context->destLivePhotoUri) == ANI_OK, ANI_INVALID_ARGS, "Failed to get destLivePhotoUri");
    }
    context->resourceType = static_cast<ResourceType>(resourceType);
    return ANI_OK;
}

static ani_status ParseArgsByResourceType(ani_env *env, ani_enum_item resourceTypeAni,
    MovingPhotoAni* thisArg, std::unique_ptr<MovingPhotoAsyncContext>& context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    CHECK_COND_RET(thisArg != nullptr, ANI_ERROR, "thisArg is nullptr");
    context->movingPhotoUri = thisArg->GetUriInner();
    context->sourceMode = thisArg->GetSourceMode();
    int32_t resourceType = static_cast<int32_t>(ResourceType::INVALID_RESOURCE);

    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryEnumAni::EnumGetValueInt32(env, resourceTypeAni, resourceType) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get resourceType");

    CHECK_COND_WITH_RET_MESSAGE(env, IsValidResourceType(resourceType), ANI_INVALID_ARGS, "Invalid resource type");
    context->requestContentMode = MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER;
    context->resourceType = static_cast<ResourceType>(resourceType);
    return ANI_OK;
}

static void RequestContentExecute(ani_env *env, unique_ptr<MovingPhotoAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    int32_t ret;
    switch (context->requestContentMode) {
        case MovingPhotoAsyncContext::WRITE_TO_SANDBOX:
            ret = RequestContentToSandbox(context.get());
            break;
        case MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER:
            ret = RequestContentToArrayBuffer(env, context.get());
            break;
        default:
            ANI_ERR_LOG("Invalid request content mode: %{public}d", static_cast<int32_t>(context->requestContentMode));
            context->error = OHOS_INVALID_PARAM_CODE;
            return;
    }
    if (ret != E_OK) {
        context->SaveError(ret);
        return;
    }
}

static ani_object RequestContentComplete(ani_env *env, unique_ptr<MovingPhotoAsyncContext> &context)
{
    ani_arraybuffer externalBuffer = {};
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    bool isTranscoder = false;
    {
        std::lock_guard<std::mutex> lock(isMovingPhotoTranscoderMapMutex);
        isMovingPhotoTranscoderMap.Find(context->requestId, isTranscoder);
    }
    if (isTranscoder) {
        std::lock_guard<std::mutex> lockMutex(requestContentCompleteResultMutex);
        requestContentCompleteResult.EnsureInsert(context->requestId, context.get());
        return nullptr;
    }
    if (context->error == E_OK && context->requestContentMode == MovingPhotoAsyncContext::WRITE_TO_ARRAY_BUFFER) {
        void* buffer = nullptr;
        ani_status status = env->CreateArrayBuffer(context->arrayBufferLength, &buffer, &externalBuffer);
        if (context->arrayBufferData != nullptr) {
            if (buffer == nullptr) {
                ANI_ERR_LOG("Failed to malloc array buffer data, uri is %{public}s, resource type is %{public}d",
                    context->movingPhotoUri.c_str(), context->resourceType);
                context->error = JS_INNER_FAIL;
            } else {
                memcpy_s(buffer, context->arrayBufferLength, context->arrayBufferData, context->arrayBufferLength);
            }
        }
        free(context->arrayBufferData);
        if (status != ANI_OK) {
            ANI_ERR_LOG("Failed to create array buffer object, uri is %{public}s, resource type is %{public}d",
                context->movingPhotoUri.c_str(), context->resourceType);
            context->arrayBufferData = nullptr;
            context->error = JS_INNER_FAIL;
        }
    } else if (context->arrayBufferData != nullptr) {
        free(context->arrayBufferData);
        context->arrayBufferData = nullptr;
    }
    ani_object errorObj {};
    if (context->error != E_OK) {
        ANI_ERR_LOG("context error: %{public}d", context->error);
        context->HandleError(env, errorObj);
    }
    return externalBuffer;
}

ani_object MovingPhotoAni::RequestContentByImageFileAndVideoFile(ani_env *env, ani_object object,
    ani_string imageFileUri, ani_string videoFileUri)
{
    unique_ptr<MovingPhotoAsyncContext> asyncContext = make_unique<MovingPhotoAsyncContext>();
    MovingPhotoAni* nativeObject = Unwrap(env, object);
    CHECK_COND_RET(nativeObject != nullptr, nullptr, "nativeObject is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsByImageFileAndVideoFile(env, imageFileUri, videoFileUri, nativeObject,
        asyncContext) == ANI_OK, nullptr, "Failed to parse requestContent args");
    RequestContentExecute(env, asyncContext);
    return RequestContentComplete(env, asyncContext);
}

ani_object MovingPhotoAni::RequestContentByResourceTypeAndFile(ani_env *env, ani_object object,
    ani_enum_item resourceTypeAni, ani_string fileUri)
{
    unique_ptr<MovingPhotoAsyncContext> asyncContext = make_unique<MovingPhotoAsyncContext>();
    MovingPhotoAni* nativeObject = Unwrap(env, object);
    if (nativeObject == nullptr) {
        return nullptr;
    }

    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsByResourceTypeAndFile(env, resourceTypeAni, fileUri, nativeObject,
        asyncContext) == ANI_OK, nullptr, "Failed to parse requestContent args");
    RequestContentExecute(env, asyncContext);
    return RequestContentComplete(env, asyncContext);
}

ani_object MovingPhotoAni::RequestContentByResourceType(ani_env *env, ani_object object, ani_enum_item resourceTypeAni)
{
    unique_ptr<MovingPhotoAsyncContext> asyncContext = make_unique<MovingPhotoAsyncContext>();
    MovingPhotoAni* nativeObject = Unwrap(env, object);

    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsByResourceType(env, resourceTypeAni, nativeObject,
        asyncContext) == ANI_OK, nullptr, "Failed to parse requestContent args");
    RequestContentExecute(env, asyncContext);
    return RequestContentComplete(env, asyncContext);
}

ani_string MovingPhotoAni::GetUri(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
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
} // namespace Media
} // namespace OHOS
