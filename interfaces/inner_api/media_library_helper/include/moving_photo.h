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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_H

#include <string>

#include "media_asset_base_capi.h"

namespace OHOS {
namespace Media {

class MovingPhoto {
public:
    virtual ~MovingPhoto() = default;

public:
    virtual MediaLibrary_ErrorCode GetUri(const char** uri) = 0;
    virtual MediaLibrary_ErrorCode RequestContentWithUris(char* imageUri, char* videoUri) = 0;
    virtual MediaLibrary_ErrorCode RequestContentWithUri(MediaLibrary_ResourceType resourceType, char* uri) = 0;
    virtual MediaLibrary_ErrorCode RequestContentWithBuffer(MediaLibrary_ResourceType resourceType,
        const uint8_t** buffer, uint32_t* size) = 0;
};

class __attribute__((visibility("default"))) MovingPhotoFactory {
public:
    static std::shared_ptr<MovingPhoto> CreateMovingPhoto(const std::string& uri);
private:
    MovingPhotoFactory() = default;
    ~MovingPhotoFactory() = default;
};

} // Media
} // OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MOVING_PHOTO_H
