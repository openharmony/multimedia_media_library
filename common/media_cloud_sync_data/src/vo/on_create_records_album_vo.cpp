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
    CHECK_AND_RETURN_RET(parcel.ReadString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->newCloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->localPath), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->serverErrorCode), false);
    CHECK_AND_RETURN_RET(parcel.ReadBool(this->isSuccess), false);
    CHECK_AND_RETURN_RET(
        IPC::ITypeMediaUtil::UnmarshallingParcelable<CloudErrorDetail>(this->errorDetails, parcel), false);
    int32_t copyRecordErrorType;
    CHECK_AND_RETURN_RET(parcel.ReadInt32(copyRecordErrorType), false);
    this->errorType = static_cast<ErrorType>(copyRecordErrorType);
    return true;
}
bool OnCreateRecordsAlbumReqBodyAlbumData::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->newCloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->localPath), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->serverErrorCode), false);
    CHECK_AND_RETURN_RET(parcel.WriteBool(this->isSuccess), false);
    CHECK_AND_RETURN_RET(
        IPC::ITypeMediaUtil::MarshallingParcelable<CloudErrorDetail>(this->errorDetails, parcel), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(static_cast<int32_t>(this->errorType)), false);
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
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::UnmarshallingParcelable<
        OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel), false);
    return true;
}

bool OnCreateRecordsAlbumReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::MarshallingParcelable<
        OnCreateRecordsAlbumReqBodyAlbumData>(this->albums, parcel), false);
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