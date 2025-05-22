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

#include "get_check_records_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"

namespace OHOS::Media::CloudSync {
bool GetCheckRecordAlbumData::Unmarshalling(MessageParcel &parcel)
{
    parcel.ReadString(this->recordId);
    parcel.ReadBool(this->isDelete);
    return true;
}
bool GetCheckRecordAlbumData::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteString(this->recordId);
    parcel.WriteBool(this->isDelete);
    return true;
}

std::string GetCheckRecordAlbumData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"recordId\": \"" << recordId << "\", "
       << "\"isDelete\": \"" << isDelete << "}";
    return ss.str();
}

bool GetCheckRecordsAlbumReqBody::AddCheckAlbumsRecords(std::string &cloudId)
{
    this->cloudIds.emplace_back(cloudId);
    return true;
}

bool GetCheckRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    return IPC::ITypeMediaUtil::Unmarshalling(this->cloudIds, parcel);
}

bool GetCheckRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    return IPC::ITypeMediaUtil::Marshalling(this->cloudIds, parcel);
}

std::string GetCheckRecordsAlbumReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudIds\": [";
    for (size_t i = 0; i < cloudIds.size(); i++) {
        ss << cloudIds[i];
        if (i != cloudIds.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}

bool CheckDataAlbum::Unmarshalling(MessageParcel &parcel)
{
    parcel.ReadString(this->cloudId);
    parcel.ReadInt64(this->size);
    parcel.ReadString(this->data);
    parcel.ReadString(this->displayName);
    parcel.ReadInt32(this->mediaType);
    parcel.ReadInt32(this->cloudVersion);
    parcel.ReadInt32(this->position);
    parcel.ReadInt64(this->dateModified);
    parcel.ReadInt32(this->dirty);
    return true;
}

bool CheckDataAlbum::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteString(this->cloudId);
    parcel.WriteInt64(this->size);
    parcel.WriteString(this->data);
    parcel.WriteString(this->displayName);
    parcel.WriteInt32(this->mediaType);
    parcel.WriteInt32(this->cloudVersion);
    parcel.WriteInt32(this->position);
    parcel.WriteInt64(this->dateModified);
    parcel.WriteInt32(this->dirty);
    return true;
}

std::string CheckDataAlbum::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << this->cloudId << "\", "
       << "\"size\": " << this->size << ", "
       << "\"data\": \"" << this->data << "\", "
       << "\"displayName\": \"" << this->displayName << "\", "
       << "\"mediaType\": " << this->mediaType << ", "
       << "\"cloudVersion\": " << this->cloudVersion << ", "
       << "\"position\": " << this->position << ", "
       << "\"dateModified\": " << this->dateModified << ", "
       << "\"dirty\": " << this->dirty << "\""
       << "}";
    return ss.str();
}

bool GetCheckRecordsAlbumRespBody::Unmarshalling(MessageParcel &parcel)
{
    int32_t size = 0;
    parcel.ReadInt32(size);
    if (size <= 0) {
        return true;
    }
    for (int32_t i = 0; i < size; ++i) {
        CheckDataAlbum data;
        std::string key;
        parcel.ReadString(key);
        data.Unmarshalling(parcel);
        this->checkDataAlbumList[key] = data;
    }
    return true;
}
bool GetCheckRecordsAlbumRespBody::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteInt32(this->checkDataAlbumList.size());
    for (auto [key, value] : this->checkDataAlbumList) {
        parcel.WriteString(key);
        if (!value.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

std::string GetCheckRecordsAlbumRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"checkDataAlbumList\": [";
    auto it = checkDataAlbumList.begin();
    auto endIt = checkDataAlbumList.end();
    while (it != endIt) {
        ss << "{\"" << it->first << "\":" << it->second.ToString() << "}";
        if (std::next(it) != endIt) {
            ss << ", ";
        }
        ++it;
    }
    ss << "]"
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync