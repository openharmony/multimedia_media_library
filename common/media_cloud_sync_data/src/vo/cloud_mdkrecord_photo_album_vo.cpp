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

#define MLOG_TAG "Media_Cloud_Vo"

#include "cloud_mdkrecord_photo_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool CloudMdkRecordPhotoAlbumVo::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteInt32(albumId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(albumType), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(albumName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(lpath), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(albumSubtype), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateAdded), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateModified), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(bundleName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(localLanguage), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(albumPluginCloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(albumNameEn), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(dualAlbumName), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(priority), false);
    CHECK_AND_RETURN_RET(parcel.WriteBool(isInWhiteList), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(coverUriSource), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(coverCloudId), false);
    return true;
}

bool CloudMdkRecordPhotoAlbumVo::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadInt32(albumId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(albumType), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(albumName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(lpath), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(albumSubtype), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateAdded), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateModified), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(bundleName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(localLanguage), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(albumPluginCloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(albumNameEn), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(dualAlbumName), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(priority), false);
    CHECK_AND_RETURN_RET(parcel.ReadBool(isInWhiteList), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(coverUriSource), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(coverCloudId), false);
    return true;
}

std::string CloudMdkRecordPhotoAlbumVo::ToString() const
{
    return "";
}

bool CloudMdkRecordPhotoAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->size);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadBool(this->isCloudSpaceFull);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool CloudMdkRecordPhotoAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->size);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteBool(this->isCloudSpaceFull);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

std::string CloudMdkRecordPhotoAlbumReqBody::ToString() const
{
    return "";
}

std::vector<CloudMdkRecordPhotoAlbumVo> CloudMdkRecordPhotoAlbumRespBody::GetPhotoAlbumRecords()
{
    return this->baseAlbumUploadVo;
}

bool CloudMdkRecordPhotoAlbumRespBody::Marshalling(MessageParcel &parcel) const
{
    if (baseAlbumUploadVo.size() == 0) {
        return false;
    }
    CHECK_AND_RETURN_RET(parcel.WriteInt32(static_cast<int32_t>(baseAlbumUploadVo.size())), false);
    for (const auto &entry : baseAlbumUploadVo) {
        if (!entry.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

bool CloudMdkRecordPhotoAlbumRespBody::GetRecords(std::vector<CloudMdkRecordPhotoAlbumVo> &val, MessageParcel &parcel)
{
    int32_t len = parcel.ReadInt32();
    if (len < 0) {
        return false;
    }

    size_t readAbleSize = parcel.GetReadableBytes();
    size_t size = static_cast<size_t>(len);
    if ((size > readAbleSize) || (size > val.max_size())) {
        return false;
    }

    val.clear();
    bool isValid;
    for (size_t i = 0; i < size; i++) {
        CloudMdkRecordPhotoAlbumVo nodeObj;
        isValid = nodeObj.Unmarshalling(parcel);
        CHECK_AND_RETURN_RET(isValid, false);
        val.emplace_back(nodeObj);
    }
    return true;
}
bool CloudMdkRecordPhotoAlbumRespBody::Unmarshalling(MessageParcel &parcel)
{
    return GetRecords(this->baseAlbumUploadVo, parcel);
}

std::string CloudMdkRecordPhotoAlbumRespBody::ToString() const
{
    return "";
}
}  // namespace OHOS::Media::CloudSync