/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "asset_cancel_task_vo.h"
#include "media_log.h"

namespace OHOS::Media {

bool CancelTaskReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(requestId), false, "Failed to write requestId");
    return true;
}

bool CancelTaskReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(requestId), false, "Failed to read requestId");
    return true;
}

std::string CancelTaskReqBody::ToString() const
{
    std::string str = "CancelTaskReqBody{requestId=" + std::to_string(requestId) + "}";
    return str;
}

}  // namespace OHOS::Media