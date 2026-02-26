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

#include "cloud_error_detail_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool CloudErrorDetail::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(domain), false, "domain");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(reason), false, "reason");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(errorCode), false, "errorCode");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(description), false, "description");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(errorPos), false, "errorPos");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(errorParam), false, "errorParam");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(detailCode), false, "detailCode");
    return true;
}

bool CloudErrorDetail::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(domain), false, "domain");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(reason), false, "reason");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(errorCode), false, "errorCode");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(description), false, "description");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(errorPos), false, "errorPos");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(errorParam), false, "errorParam");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(detailCode), false, "detailCode");
    return true;
}

std::string CloudErrorDetail::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"reason\": \"" << reason << "\","
       << "\"description\": \"" << description << "\","
       << "\"domain\": \"" << domain << "\","
       << "\"errorCode\": \"" << errorCode << "\","
       << "\"errorPos\": \"" << errorPos << "\","
       << "\"errorParam\": \"" << errorParam << "\","
       << "\"detailCode\": \"" << detailCode << "\""
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync