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

#include "on_delete_records_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool OnDeleteAlbumData::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadBool(this->isSuccess), false, "isSuccess");
    return true;
}
bool OnDeleteAlbumData::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteBool(this->isSuccess), false, "isSuccess");
    return true;
}

std::string OnDeleteAlbumData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << cloudId << "\", "
       << "\"isSuccess\": \"" << isSuccess << "}";
    return ss.str();
}

bool OnDeleteRecordsAlbumReqBody::AddSuccessResult(OnDeleteAlbumData &albumData)
{
    this->albums.emplace_back(albumData);
    return true;
}

bool OnDeleteRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::UnmarshallingParcelable<OnDeleteAlbumData>(this->albums, parcel), false, "albums");
    return true;
}

bool OnDeleteRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::MarshallingParcelable<OnDeleteAlbumData>(this->albums, parcel), false, "albums");
    return true;
}

std::string OnDeleteRecordsAlbumReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"albums\": [";
    for (size_t i = 0; i < albums.size(); i++) {
        ss << albums[i].ToString();
        if (i != albums.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}

bool OnDeleteRecordsAlbumRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->failSize), false, "failSize");
    return true;
}

bool OnDeleteRecordsAlbumRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->failSize), false, "failSize");
    return true;
}

std::string OnDeleteRecordsAlbumRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"failSize\": " << failSize << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync