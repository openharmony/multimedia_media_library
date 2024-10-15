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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_IMPL_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_IMPL_H

#include "nocopyable.h"
#include "file_asset.h"
#include "media_asset.h"

namespace OHOS {
namespace Media {

class MediaAssetImpl : public MediaAsset, public NoCopyable {
public:
    MediaAssetImpl(std::shared_ptr<FileAsset> fileAsset);
    ~MediaAssetImpl();

    MediaLibrary_ErrorCode GetUri(const char** uri) override;
    MediaLibrary_ErrorCode GetMediaType(MediaLibrary_MediaType* mediaType) override;
    MediaLibrary_ErrorCode GetMediaSubType(MediaLibrary_MediaSubType* mediaSubType) override;
    MediaLibrary_ErrorCode GetDisplayName(const char** displayName) override;
    MediaLibrary_ErrorCode GetSize(uint32_t* size) override;
    MediaLibrary_ErrorCode GetDateAdded(uint32_t* dateAdded) override;
    MediaLibrary_ErrorCode GetDateModified(uint32_t* dateModified) override;
    MediaLibrary_ErrorCode GetDateAddedMs(uint32_t* dateAddedMs) override;
    MediaLibrary_ErrorCode GetDateModifiedMs(uint32_t* dateModifiedMs) override;
    MediaLibrary_ErrorCode GetDateTaken(uint32_t* dateTaken) override;
    MediaLibrary_ErrorCode GetDuration(uint32_t* duration) override;
    MediaLibrary_ErrorCode GetWidth(uint32_t* width) override;
    MediaLibrary_ErrorCode GetHeight(uint32_t* height) override;
    MediaLibrary_ErrorCode GetOrientation(uint32_t* orientation) override;
    MediaLibrary_ErrorCode IsFavorite(uint32_t* favorite) override;
    MediaLibrary_ErrorCode GetTitle(const char** title) override;

    std::shared_ptr<FileAsset> GetFileAssetInstance() const override;

private:
    std::shared_ptr<FileAsset> fileAsset_ = nullptr;
    char* uri_;
    char* displayName_;
    char* title_;
};

}
}

#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_IMPL_H
