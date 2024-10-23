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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_H

#include "media_asset_base_capi.h"
#include "media_asset.h"
#include "media_asset_types.h"

namespace OHOS {
namespace Media {

class MediaAssetChangeRequest {
public:
    virtual ~MediaAssetChangeRequest() = default;

public:
    virtual MediaLibrary_ErrorCode GetWriteCacheHandler(int32_t* fd) = 0;
    virtual MediaLibrary_ErrorCode AddResourceWithUri(MediaLibrary_ResourceType resourceType, char* fileUri) = 0;
    virtual MediaLibrary_ErrorCode AddResourceWithBuffer(MediaLibrary_ResourceType resourceType, uint8_t* buffer,
        uint32_t length) = 0;
    virtual MediaLibrary_ErrorCode SaveCameraPhoto(MediaLibrary_ImageFileType imageFileType) = 0;
    virtual MediaLibrary_ErrorCode DiscardCameraPhoto() = 0;
    virtual MediaLibrary_ErrorCode ApplyChanges() = 0;

    virtual void RecordChangeOperation(AssetChangeOperation changeOperation) = 0;
};

class __attribute__((visibility("default"))) MediaAssetChangeRequestFactory {
public:
    static std::shared_ptr<MediaAssetChangeRequest> CreateMediaAssetChangeRequest(
        std::shared_ptr<MediaAsset> mediaAsset);
private:
    MediaAssetChangeRequestFactory() = default;
    ~MediaAssetChangeRequestFactory() = default;
};

} // Media
} // OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_H
