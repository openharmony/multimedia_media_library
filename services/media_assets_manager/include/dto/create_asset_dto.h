/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_DTO_H
#define OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_DTO_H

#include <stdint.h>
#include <string>

#include "create_asset_vo.h"

namespace OHOS::Media {
class CreateAssetDto {
public:
    int32_t tokenId{0};
    int32_t mediaType{0};
    int32_t photoSubtype{0};
    std::string title;
    std::string extension;
    std::string displayName;
    std::string cameraShotKey;
    std::string bundleName;
    std::string packageName;
    std::string appId;
    std::string ownerAlbumId;

    int32_t fileId{0};
    std::string outUri;

public:
    CreateAssetDto(const CreateAssetReqBody &reqBody);
    CreateAssetDto(const CreateAssetForAppReqBody &reqBody);
    CreateAssetRespBody GetRespBody();
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_DTO_H