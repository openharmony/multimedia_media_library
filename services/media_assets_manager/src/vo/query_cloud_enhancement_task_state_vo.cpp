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

#define MLOG_TAG "MediaQueryCloudEnhancementTaskStateVo"

#include "query_cloud_enhancement_task_state_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool QueryCloudEnhancementTaskStateReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->photoUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool QueryCloudEnhancementTaskStateReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->photoUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

string QueryCloudEnhancementTaskStateReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"photoUri\": \"" << photoUri
       << "}";
    return ss.str();
}

bool QueryCloudEnhancementTaskStateRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->photoId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->ceAvailable);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->CEErrorCode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool QueryCloudEnhancementTaskStateRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->photoId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->ceAvailable);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->CEErrorCode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

string QueryCloudEnhancementTaskStateRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"fileId\": \"" << to_string(this->fileId) << "\""
        << ",\"photoId\": \"" << this->photoId << "\""
        << ",\"ceAvailable\": \"" << to_string(this->ceAvailable) << "\""
        << ",\"CEErrorCode\": \"" << to_string(this->CEErrorCode) << "\""
        << "}";
    return ss.str();
}
} // namespace OHOS::Media