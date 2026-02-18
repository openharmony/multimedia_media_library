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

#include "on_fetch_records_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool OnFetchRecordsAlbumReqBody::AlbumReqData::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->localPath), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->albumName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->albumBundleName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->localLanguage), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->albumId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->priority), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->albumType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->albumSubType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->albumDateCreated), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->albumDateAdded), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->albumDateModified), false);
    CHECK_AND_RETURN_RET(parcel.ReadBool(this->isDelete), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->coverUriSource), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->coverCloudId), false);
    return true;
}
bool OnFetchRecordsAlbumReqBody::AlbumReqData::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->localPath), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->albumName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->albumBundleName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->localLanguage), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->albumId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->priority), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->albumType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->albumSubType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->albumDateCreated), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->albumDateAdded), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->albumDateModified), false);
    CHECK_AND_RETURN_RET(parcel.WriteBool(this->isDelete), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->coverUriSource), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->coverCloudId), false);
    return true;
}

std::string OnFetchRecordsAlbumReqBody::AlbumReqData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << cloudId << "\","
       << "\"albumBundleName\": \"" << albumBundleName << "\","
       << "\"localLanguage\": \"" << localLanguage << "\","
       << "\"albumId\": \"" << albumId << "\","
       << "\"priority\": \"" << priority << "\","
       << "\"albumType\": \"" << albumType << "\","
       << "\"albumSubType\": \"" << albumSubType << "\","
       << "\"albumDateCreated\": \"" << albumDateCreated << "\","
       << "\"albumDateAdded\": \"" << albumDateAdded << "\","
       << "\"albumDateModified\": \"" << albumDateModified << "\","
       << "\"isDelete\": \"" << isDelete << "\","
       << "\"coverUriSource\": \"" << coverUriSource << "\","
       << "\"coverCloudId\": \"" << coverCloudId << "\","
       << "}";
    return ss.str();
}

bool OnFetchRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::UnmarshallingParcelable<AlbumReqData>(this->albums, parcel), false);
    return true;
}

bool OnFetchRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::MarshallingParcelable<AlbumReqData>(this->albums, parcel), false);
    return true;
}

std::string OnFetchRecordsAlbumReqBody::ToString() const
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

bool OnFetchRecordsAlbumRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->failedRecords, parcel), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Unmarshalling<int32_t>(this->stats, parcel), false);
    return true;
}

bool OnFetchRecordsAlbumRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Marshalling<std::string>(this->failedRecords, parcel), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Marshalling<int32_t>(this->stats, parcel), false);
    return true;
}

std::string OnFetchRecordsAlbumRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"failedRecords\": [";
    for (size_t i = 0; i < failedRecords.size(); i++) {
        ss << failedRecords[i];
        if (i != failedRecords.size() - 1) {
            ss << ", ";
        }
    }
    ss << "], \"stats\": [";
    for (size_t i = 0; i < stats.size(); i++) {
        ss << stats[i];
        if (i != stats.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync