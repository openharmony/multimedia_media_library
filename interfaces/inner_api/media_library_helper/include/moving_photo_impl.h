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

#ifndef NTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_IMPL_H
#define NTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_IMPL_H

#include "nocopyable.h"
#include "moving_photo.h"

namespace OHOS {
namespace Media {

enum class SourceMode {
    ORIGINAL_MODE = 0,
    EDITED_MODE,
};

class MovingPhotoImpl : public MovingPhoto, public NoCopyable {
public:
    MovingPhotoImpl(const std::string& imageUri);
    ~MovingPhotoImpl();

    MediaLibrary_ErrorCode GetUri(const char** uri) override;
    MediaLibrary_ErrorCode RequestContentWithUris(char* imageUri, char* videoUri) override;
    MediaLibrary_ErrorCode RequestContentWithUri(MediaLibrary_ResourceType resourceType, char* uri) override;
    MediaLibrary_ErrorCode RequestContentWithBuffer(MediaLibrary_ResourceType resourceType,
        const uint8_t** buffer, uint32_t* size) override;

private:
    int32_t RequestContentToSandbox();
    int32_t WriteToSandboxUri(int32_t srcFd, std::string& sandboxUri);
    int32_t CopyFileFromMediaLibrary(int32_t srcFd, int32_t destFd);
    int32_t OpenReadOnlyFile(const std::string& uri, bool isReadImage);
    bool HandleFd(int32_t& fd);
    int32_t OpenReadOnlyImage(const std::string& imageUri, bool isMediaLibUri);
    int32_t RequestContentToArrayBuffer();
    int32_t AcquireFdForArrayBuffer();
    int32_t OpenReadOnlyVideo(const std::string& videoUri, bool isMediaLibUri);

private:
    std::string imageUri_;
    char* destImageUri_ = nullptr;
    char* destVideoUri_ = nullptr;
    MediaLibrary_ResourceType resourceType_ = MEDIA_LIBRARY_IMAGE_RESOURCE;
    void* arrayBufferData_ = nullptr;
    size_t arrayBufferLength_ = 0;
    SourceMode sourceMode_ = SourceMode::ORIGINAL_MODE;
};

}
}

#endif // NTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_IMPL_H