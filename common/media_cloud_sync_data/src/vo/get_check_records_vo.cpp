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

#include "get_check_records_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool GetCheckRecordsReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Unmarshalling(this->cloudIds, parcel), false);
    return true;
}

bool GetCheckRecordsReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Marshalling(this->cloudIds, parcel), false);
    return true;
}

std::string GetCheckRecordsReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudIds\": [";
    for (size_t i = 0; i < this->cloudIds.size(); i++) {
        ss << this->cloudIds[i];
        if (i != this->cloudIds.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}

bool GetCheckRecordsRespBodyCheckData::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->size), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->data), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->displayName), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->fileName), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->mediaType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->cloudVersion), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->position), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(this->dateModified), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->dirty), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->thmStatus), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->syncStatus), false);
    int32_t attachmentSize;
    CHECK_AND_RETURN_RET(parcel.ReadInt32(attachmentSize), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->fileSourceType), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(this->storagePath), false);
    for (int32_t i = 0; i < attachmentSize; ++i) {
        CloudFileDataVo vo;
        std::string key;
        CHECK_AND_RETURN_RET(parcel.ReadString(key), false);
        CHECK_AND_RETURN_RET(vo.Unmarshalling(parcel), false);
        this->attachment[key] = vo;
    }
    return true;
}

bool GetCheckRecordsRespBodyCheckData::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteString(this->cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->size), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->data), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->displayName), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->fileName), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->mediaType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->cloudVersion), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->position), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(this->dateModified), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->dirty), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->thmStatus), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->syncStatus), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->attachment.size()), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->fileSourceType), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(this->storagePath), false);
    for (auto &[key, value] : attachment) {
        CHECK_AND_RETURN_RET(parcel.WriteString(key), false);
        CHECK_AND_RETURN_RET(value.Marshalling(parcel), false);
    }
    return true;
}

std::string GetCheckRecordsRespBodyCheckData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"cloudId\": \"" << this->cloudId << "\", "
       << "\"size\": " << this->size << ", "
       << "\"data\": \"" << this->data << "\", "
       << "\"mediaType\": " << this->mediaType << ", "
       << "\"cloudVersion\": " << this->cloudVersion << ", "
       << "\"dateModified\": " << this->dateModified << ", "
       << "\"dirty\": " << this->dirty << "\""
       << "\"thmStatus\": " << this->thmStatus << "\""
       << "\"syncStatus\": " << this->syncStatus << "\""
       << "\"fileSourceType\": " << this->fileSourceType << "\""
       << "\"storagePath\": " << this->storagePath << "\"";
    ss << ",[";
    uint32_t index = 0;
    for (const auto &[key, value] : attachment) {
        ss << "{\"" << key << "\": " << value.ToString() << "}";
        if (index != attachment.size() - 1) {
            ss << ",";
        }
        index++;
    }
    ss << "]}";
    return ss.str();
}

bool GetCheckRecordsRespBody::Unmarshalling(MessageParcel &parcel)
{
    int32_t size = 0;
    CHECK_AND_RETURN_RET(parcel.ReadInt32(size), false);
    if (size <= 0) {
        return true;
    }
    for (int32_t i = 0; i < size; ++i) {
        GetCheckRecordsRespBodyCheckData data;
        std::string key;
        CHECK_AND_RETURN_RET(parcel.ReadString(key), false);
        CHECK_AND_RETURN_RET(data.Unmarshalling(parcel), false);
        this->checkDataList[key] = data;
    }
    return true;
}

bool GetCheckRecordsRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->checkDataList.size()), false);
    for (auto [key, value] : this->checkDataList) {
        CHECK_AND_RETURN_RET(parcel.WriteString(key), false);
        if (!value.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

std::string GetCheckRecordsRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"checkDataList\": [";
    auto it = checkDataList.begin();
    auto endIt = checkDataList.end();
    while (it != endIt) {
        if (std::next(it) == endIt) {
            ss << "{\"" << it->first << "\":" << it->second.ToString() << "}";
        } else {
            ss << "{\"" << it->first << "\":" << it->second.ToString() << "},";
        }
        ++it;
    }
    ss << "]"
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync