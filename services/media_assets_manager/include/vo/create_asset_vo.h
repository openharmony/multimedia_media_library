/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_VO_H
#define OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_VO_H

#include <stdint.h>
#include <string>
#include <sstream>

#include "i_media_parcelable.h"
#include "create_asset_dto.h"

namespace OHOS::Media {
class CreateAssetReqBody : public IPC::IMediaParcelable {
public:
    int32_t mediaType{0};
    int32_t photoSubtype{0};
    std::string title;
    std::string extension;
    std::string displayName;
    std::string cameraShotKey;

public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
public:
    void Convert2Dto(CreateAssetDto &dto);
public:  // basic functions
    std::string ToString() const;
};

class CreateAssetRspBody : public IPC::IMediaParcelable {
public:
    int32_t fileId{-1};
    std::string outUri;

public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
public:
    void InitByDto(const CreateAssetDto &dto);
public:  // basic functions
    std::string ToString() const;
};

class CreateAssetForAppReqBody : public IPC::IMediaParcelable {
public:
    int32_t tokenId{0};
    int32_t mediaType{0};
    int32_t photoSubtype{0};
    std::string title;
    std::string extension;
    std::string displayName;
    std::string bundleName;
    std::string packageName;
    std::string appId;
    std::string ownerAlbumId;
public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
public:
    void Convert2Dto(CreateAssetDto &dto);
public:  // basic functions
    std::string ToString() const;
};

using CreateAssetForAppRspBody = CreateAssetRspBody;

} // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_MANAGER_CREATE_ASSET_VO_H