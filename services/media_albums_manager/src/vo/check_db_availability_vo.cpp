/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "check_db_availability_vo.h"

#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media {

bool CheckDbAvailabilityReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Unmarshal(parcel, isOnlyCheckPermission), false, "isOnlyCheckPermission");
    return true;
}

bool CheckDbAvailabilityReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Marshal(parcel, isOnlyCheckPermission), false, "isOnlyCheckPermission");
    return true;
}
}  // namespace OHOS::Media