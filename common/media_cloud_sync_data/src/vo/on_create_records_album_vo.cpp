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
#include "media_log.h"

namespace OHOS::Media::CloudSync {

bool OnCreateRecordsAlbumReqBodyAlbumData::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->newCloudId), false, "newCloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->localPath), false, "localPath");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->serverErrorCode), false, "serverErrorCode");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadBool(this->isSuccess), false, "isSuccess");
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::UnmarshallingParcelable<CloudErrorDetail>(this->errorDetails, parcel),
                             false,
                             "errorDetails");
    int32_t copyRecordErrorType;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(copyRecordErrorType), false, "copyRecordErrorType");
    this->errorType = static_cast<ErrorType>(copyRecordErrorType);
    return true;
}
bool OnCreateRecordsAlbumReqBodyAlbumData::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->cloudId), false, "cloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->newCloudId), false, "newCloudId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->localPath), false, "localPath");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->serverErrorCode), false, "serverErrorCode");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteBool(this->isSuccess), false, "isSuccess");
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::MarshallingParcelable<CloudErrorDetail>(this->errorDetails, parcel),
                             false,
                             "errorDetails");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(static_cast<int32_t>(this->errorType)), false, "errorType");
    return true;
}

std::string OnCreateRecordsAlbumReqBodyAlbumData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"newCloudId\": \"" << newCloudId << "\","
       << "\"cloudId\": \"" << cloudId << "\","
       << "\"isSuccess\": \"" << isSuccess << "\","
       << "\"serverErrorCode\": " << serverErrorCode << ","
       << "\"errorType\": \"" << static_cast<int32_t>(errorType) << "\","
       << "\"errorDetails\": [";
    for (uint32_t i = 0; i < errorDetails.size(); ++i) {
        ss << errorDetails[i].ToString();
        if (i != errorDetails.size() - 1) {
            ss << ",";
        }
    }
    ss << "]}";
    return ss.str();
}

bool OnCreateRecordsAlbumReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::UnmarshallingParcelable<OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel),
        false,
        "albums");
    return true;
}

bool OnCreateRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::MarshallingParcelable<OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel),
        false,
        "albums");
    return true;
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