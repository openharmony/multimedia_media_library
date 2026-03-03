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

#include "on_delete_records_photos_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::CloudSync {
bool OnDeleteRecordsPhoto::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->dkRecordId), false, "dkRecordId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadBool(this->isSuccess), false, "isSuccess");
    return true;
}
bool OnDeleteRecordsPhoto::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->dkRecordId), false, "dkRecordId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteBool(this->isSuccess), false, "isSuccess");
    return true;
}

std::string OnDeleteRecordsPhoto::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"dkRecordId\": \"" << dkRecordId << "\","
       << "\"cloudId\": \"" << cloudId << "\","
       << "\"isSuccess\": " << std::to_string(isSuccess) << "}";
    return ss.str();
}

int32_t OnDeleteRecordsPhotosReqBody::AddDeleteRecord(const OnDeleteRecordsPhoto &record)
{
    this->records.push_back(record);
    return E_OK;
}

std::vector<OnDeleteRecordsPhoto> OnDeleteRecordsPhotosReqBody::GetDeleteRecords()
{
    return records;
}

bool OnDeleteRecordsPhotosReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::UnmarshallingParcelable<OnDeleteRecordsPhoto>(this->records, parcel), false, "records");
    return true;
}
bool OnDeleteRecordsPhotosReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::MarshallingParcelable<OnDeleteRecordsPhoto>(this->records, parcel), false, "records");
    return true;
}

std::string OnDeleteRecordsPhotosReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"records\": [";
    for (size_t i = 0; i < records.size(); i++) {
        ss << records[i].ToString();
        if (i != records.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}

bool OnDeleteRecordsPhotosRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->failSize), false, "failSize");
    return true;
}

bool OnDeleteRecordsPhotosRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->failSize), false, "failSize");
    return true;
}

std::string OnDeleteRecordsPhotosRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"failSize\": " << failSize << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync