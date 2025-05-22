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

#include "on_dentry_file_vo.h"

#include <sstream>

#include "media_itypes_utils.h"

namespace OHOS::Media::CloudSync {
bool OnDentryFileReqBody::Unmarshalling(MessageParcel &parcel)
{
    return IPC::ITypeMediaUtil::UnmarshallingParcelable<OnFetchPhotosVo>(this->records, parcel);
}

bool OnDentryFileReqBody::Marshalling(MessageParcel &parcel) const
{
    return IPC::ITypeMediaUtil::MarshallingParcelable<OnFetchPhotosVo>(this->records, parcel);
}

int32_t OnDentryFileReqBody::AddOnDentryFileRecord(const OnFetchPhotosVo &record)
{
    this->records.push_back(record);
    return 0;
}

std::vector<OnFetchPhotosVo> OnDentryFileReqBody::GetOnDentryFileRecord()
{
    return records;
}

std::string OnDentryFileReqBody::ToString() const
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

bool OnDentryFileRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool ret = IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->failedRecords, parcel);
    if (!ret) {
        return ret;
    }
    return ret;
}

bool OnDentryFileRespBody::Marshalling(MessageParcel &parcel) const
{
    return IPC::ITypeMediaUtil::Marshalling<std::string>(this->failedRecords, parcel);
}

std::string OnDentryFileRespBody::ToString() const
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
    ss << "]"
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync