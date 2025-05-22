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

#include "on_mdirty_records_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"

namespace OHOS::Media::CloudSync {
bool OnMdirtyAlbumRecord::Unmarshalling(MessageParcel &parcel)
{
    parcel.ReadString(this->cloudId);
    parcel.ReadBool(this->isSuccess);
    return true;
}

bool OnMdirtyAlbumRecord::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteString(this->cloudId);
    parcel.WriteBool(this->isSuccess);
    return true;
}

std::string OnMdirtyAlbumRecord::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << cloudId << "\""
       << "\"isSuccess\": \"" << isSuccess << "\""
       << "}";
    return ss.str();
}

bool OnMdirtyRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    IPC::ITypeMediaUtil::UnmarshallingParcelable(this->records, parcel);
    return true;
}

bool OnMdirtyRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    IPC::ITypeMediaUtil::MarshallingParcelable(this->records, parcel);
    return true;
}

int32_t OnMdirtyRecordsAlbumReqBody::AddMdirtyRecord(const OnMdirtyAlbumRecord &record)
{
    this->records.push_back(record);
    return E_OK;
}

std::vector<OnMdirtyAlbumRecord> OnMdirtyRecordsAlbumReqBody::GetMdirtyRecords()
{
    return records;
}

std::string OnMdirtyRecordsAlbumReqBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}

bool OnMdirtyRecordsAlbumRespBody::Unmarshalling(MessageParcel &parcel)
{
    parcel.ReadInt32(this->failSize);
    return true;
}
bool OnMdirtyRecordsAlbumRespBody::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteInt32(this->failSize);
    return true;
}

std::string OnMdirtyRecordsAlbumRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"failSize\": " << failSize << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync