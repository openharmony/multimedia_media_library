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

#include "on_copy_records_photos_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::CloudSync {

bool OnCopyRecord::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->fileId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->rotation), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->fileType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->size), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->createTime), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->path), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->fileName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->sourcePath), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->version), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->serverErrorCode), false);
    CHECK_AND_RETURN_RET(parcel.ReadBool(this->isSuccess), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::UnmarshallingParcelable<CloudErrorDetail>(
        this->errorDetails, parcel), false);
    int32_t copyRecordErrorType;
    CHECK_AND_RETURN_RET(parcel.ReadInt32(copyRecordErrorType), false);
    this->errorType = static_cast<ErrorType>(copyRecordErrorType);
    return true;
}
bool OnCopyRecord::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->fileId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->rotation), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->fileType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->size), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->createTime), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->path), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->fileName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->sourcePath), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->version), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->serverErrorCode), false);
    CHECK_AND_RETURN_RET(parcel.WriteBool(this->isSuccess), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::MarshallingParcelable<CloudErrorDetail>(
        this->errorDetails, parcel), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(static_cast<int32_t>(this->errorType)), false);
    return true;
}

std::string OnCopyRecord::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << cloudId << "\","
       << "\"fileId\": " << fileId << ","
       << "\"rotation\": " << rotation << ","
       << "\"fileType\": " << fileType << ","
       << "\"size\": " << size << ","
       << "\"createTime\": " << createTime << ","
       << "\"path\": \"" << path << "\","
       << "\"version\": " << version << ","
       << "\"serverErrorCode\": " << serverErrorCode << ","
       << "\"isSuccess\": " << std::to_string(isSuccess) << ","
       << "\"errorType\": " << static_cast<int32_t>(errorType) << ""
       << "}";
    return ss.str();
}

bool OnCopyRecordsPhotosReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::UnmarshallingParcelable(this->records, parcel), false);
    return true;
}

bool OnCopyRecordsPhotosReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::MarshallingParcelable(this->records, parcel), false);
    return true;
}

int32_t OnCopyRecordsPhotosReqBody::AddCopyRecord(const OnCopyRecord &record)
{
    this->records.push_back(record);
    return E_OK;
}

std::vector<OnCopyRecord> OnCopyRecordsPhotosReqBody::GetRecords()
{
    return records;
}

std::string OnCopyRecordsPhotosReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{\"records\":[";
    for (uint32_t i = 0; i < records.size(); ++i) {
        if (i != records.size() - 1) {
            ss << records[i].ToString() << ",";
            continue;
        }
        ss << records[i].ToString();
    }
    ss << "]}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync