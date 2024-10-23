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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_H

#include "file_asset.h"
#include "media_asset_base_capi.h"

namespace OHOS {
namespace Media {

class MediaAsset {
public:
    virtual ~MediaAsset() = default;

public:
    virtual MediaLibrary_ErrorCode GetUri(const char** uri) = 0;
    virtual MediaLibrary_ErrorCode GetMediaType(MediaLibrary_MediaType* mediaType) = 0;
    virtual MediaLibrary_ErrorCode GetMediaSubType(MediaLibrary_MediaSubType* mediaSubType) = 0;
    virtual MediaLibrary_ErrorCode GetDisplayName(const char** displayName) = 0;
    virtual MediaLibrary_ErrorCode GetSize(uint32_t* size) = 0;
    virtual MediaLibrary_ErrorCode GetDateAdded(uint32_t* dateAdded) = 0;
    virtual MediaLibrary_ErrorCode GetDateModified(uint32_t* dateModified) = 0;
    virtual MediaLibrary_ErrorCode GetDateAddedMs(uint32_t* dateAddedMs) = 0;
    virtual MediaLibrary_ErrorCode GetDateModifiedMs(uint32_t* dateModifiedMs) = 0;
    virtual MediaLibrary_ErrorCode GetDateTaken(uint32_t* dateTaken) = 0;
    virtual MediaLibrary_ErrorCode GetDuration(uint32_t* duration) = 0;
    virtual MediaLibrary_ErrorCode GetWidth(uint32_t* width) = 0;
    virtual MediaLibrary_ErrorCode GetHeight(uint32_t* height) = 0;
    virtual MediaLibrary_ErrorCode GetOrientation(uint32_t* orientation) = 0;
    virtual MediaLibrary_ErrorCode IsFavorite(uint32_t* favorite) = 0;
    virtual MediaLibrary_ErrorCode GetTitle(const char** title) = 0;

    virtual std::shared_ptr<FileAsset> GetFileAssetInstance() const = 0;
};

class __attribute__((visibility("default"))) MediaAssetFactory {
public:
    static std::shared_ptr<MediaAsset> CreateMediaAsset(std::shared_ptr<FileAsset> fileAsset);
private:
    MediaAssetFactory() = default;
    ~MediaAssetFactory() = default;
};

} // Media
} // OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_H
