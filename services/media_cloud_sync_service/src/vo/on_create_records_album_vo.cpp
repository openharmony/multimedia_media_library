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

#include "on_create_records_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"

namespace OHOS::Media::CloudSync {

bool OnCreateRecordsAlbumReqBodyAlbumData::Unmarshalling(MessageParcel &parcel)
{
    parcel.ReadBool(this->isSuccess);
    parcel.ReadString(this->cloudId);
    parcel.ReadString(this->newCloudId);
    parcel.ReadString(this->localPath);
    return true;
}
bool OnCreateRecordsAlbumReqBodyAlbumData::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteBool(this->isSuccess);
    parcel.WriteString(this->cloudId);
    parcel.WriteString(this->newCloudId);
    parcel.WriteString(this->localPath);
    return true;
}

std::string OnCreateRecordsAlbumReqBodyAlbumData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"isSuccess\": \"" << isSuccess << "\", "
       << "\"localPath\": \"" << localPath << "\", "
       << "\"newCloudId\": \"" << newCloudId << "\""
       << "\"cloudId\": \"" << cloudId << "\""
       << "}";
    return ss.str();
}

bool OnCreateRecordsAlbumReqBody::AddAlbumData(std::string cloudId, std::string newCloudId, bool isSuccess)
{
    OnCreateRecordsAlbumReqBodyAlbumData albumData;
    albumData.cloudId = cloudId;
    albumData.newCloudId = newCloudId;
    albumData.isSuccess = isSuccess;
    this->albums.emplace_back(albumData);
    return true;
}

bool OnCreateRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    return IPC::ITypeMediaUtil::UnmarshallingParcelable<OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel);
}

bool OnCreateRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    return IPC::ITypeMediaUtil::MarshallingParcelable<OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel);
}

std::string OnCreateRecordsAlbumReqBody::ToString() const
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
}  // namespace OHOS::Media::CloudSync