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

#include "start_asset_change_scan_vo.h"

#include <sstream>
#include "media_log.h"

namespace OHOS::Media {
// LCOV_EXCL_START
using namespace std;
bool StartAssetChangeScanReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->operation);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool StartAssetChangeScanReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->operation);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
// LCOV_EXCL_STOP
};