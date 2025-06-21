/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#include "add_visit_count_vo.h"

#include "media_log.h"

namespace OHOS::Media {

bool AddAssetVisitCountReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->fileId);
    CHECK_AND_RETURN_RET_LOG(status, status, "Read fileId failed");
    status = parcel.ReadInt32(this->visitType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Read visitType failed");
    return true;
}

bool AddAssetVisitCountReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->fileId);
    CHECK_AND_RETURN_RET_LOG(status, status, "Write fileId failed");
    status = parcel.WriteInt32(this->visitType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Write visitType failed");
    return true;
}
} // namespace OHOS::Media
