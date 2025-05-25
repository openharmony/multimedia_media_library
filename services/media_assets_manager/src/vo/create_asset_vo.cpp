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

#include "create_asset_vo.h"

#include "media_log.h"

namespace OHOS::Media {

bool CreateAssetReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->mediaType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->photoSubtype);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->extension);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->displayName);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.ReadString(this->cameraShotKey);
}

bool CreateAssetReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->mediaType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->photoSubtype);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->extension);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->displayName);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.WriteString(this->cameraShotKey);
}

void CreateAssetReqBody::Convert2Dto(CreateAssetDto &dto)
{
    dto.mediaType = this->mediaType;
    dto.photoSubtype = this->photoSubtype;
    dto.title = this->title;
    dto.extension = this->extension;
    dto.displayName = this->displayName;
    dto.cameraShotKey = this->cameraShotKey;
}

std::string CreateAssetReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"mediaType\": \"" << this->mediaType << "\""
        << ",\"photoSubtype\": \"" << this->photoSubtype << "\""
        << ",\"title\": \"" << this->title << "\""
        << ",\"extension\": \"" << this->extension << "\""
        << ",\"displayName\": \"" << this->displayName << "\""
        << ",\"cameraShotKey\": \"" << this->cameraShotKey << "\""
        << "}";
    return ss.str();
}

bool CreateAssetRspBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.ReadString(this->outUri);
}

bool CreateAssetRspBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.WriteString(this->outUri);
}

void CreateAssetRspBody::InitByDto(const CreateAssetDto &dto)
{
    this->fileId = dto.fileId;
    this->outUri = dto.outUri;
}

std::string CreateAssetRspBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"fileId\": \"" << this->fileId << "\""
        << ",\"outUri\": \"" << this->outUri << "\""
        << "}";
    return ss.str();
}

bool CreateAssetForAppReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->tokenId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->mediaType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->photoSubtype);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->extension);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->displayName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->packageName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->appId);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.ReadString(this->ownerAlbumId);
}

bool CreateAssetForAppReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->tokenId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->mediaType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->photoSubtype);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->extension);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->displayName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->packageName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->appId);
    CHECK_AND_RETURN_RET(status, status);
    return parcel.WriteString(this->ownerAlbumId);
}

void CreateAssetForAppReqBody::Convert2Dto(CreateAssetDto &dto)
{
    dto.tokenId = this->tokenId;
    dto.mediaType = this->mediaType;
    dto.photoSubtype = this->photoSubtype;
    dto.title = this->title;
    dto.extension = this->extension;
    dto.bundleName = this->bundleName;
    dto.packageName = this->packageName;
    dto.appId = this->appId;
    dto.ownerAlbumId = this->ownerAlbumId;
}

std::string CreateAssetForAppReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"tokenId\": \"" << this->tokenId << "\""
        << ",\"mediaType\": \"" << this->mediaType << "\""
        << ",\"photoSubtype\": \"" << this->photoSubtype << "\""
        << ",\"title\": \"" << this->title << "\""
        << ",\"extension\": \"" << this->extension << "\""
        << ",\"displayName\": \"" << this->displayName << "\""
        << ",\"bundleName\": \"" << this->bundleName << "\""
        << ",\"packageName\": \"" << this->packageName << "\""
        << ",\"appId\": \"" << this->appId << "\""
        << ",\"ownerAlbumId\": \"" << this->ownerAlbumId << "\""
        << "}";
    return ss.str();
}
} // namespace OHOS::Media