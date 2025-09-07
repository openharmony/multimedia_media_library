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

#define MLOG_TAG "MediaConvertFormatVo"

#include "convert_format_vo.h"

#include <sstream>

#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool ConvertFormatReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->fileId);
    CHECK_AND_RETURN_RET_LOG(status, status, "read fileId failed");
    status = parcel.ReadString(this->title);
    CHECK_AND_RETURN_RET_LOG(status, status, "read title failed");
    status = parcel.ReadString(this->extension);
    CHECK_AND_RETURN_RET_LOG(status, status, "read extension failed");
    return true;
}

bool ConvertFormatReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->fileId);
    CHECK_AND_RETURN_RET_LOG(status, status, "write fileId failed");
    status = parcel.WriteString(this->title);
    CHECK_AND_RETURN_RET_LOG(status, status, "write title failed");
    status = parcel.WriteString(this->extension);
    CHECK_AND_RETURN_RET_LOG(status, status, "write extension failed");
    return true;
}

string ConvertFormatReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"fileId\": \"" << std::to_string(this->fileId) << "\", "
        << "\"title\": \"" << this->title << "\", "
        << "\"extension\": \"" << this->extension << "\""
        << "}";
    return ss.str();
}
bool ConvertFormatRespBody::Unmarshalling(MessageParcel &parcel)
{
    resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "resultSet Unmarshal failed");
    return true;
}

bool ConvertFormatRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(resultSet, parcel);
    CHECK_AND_RETURN_RET_LOG(!status, false, "resultSet marshal failed");
    return true;
}
} // namespace OHOS::Media