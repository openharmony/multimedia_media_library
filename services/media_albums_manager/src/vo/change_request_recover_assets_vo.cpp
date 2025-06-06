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

#include "change_request_recover_assets_vo.h"

#include <sstream>
#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media {

bool ChangeRequestRecoverAssetsReqBody::Unmarshalling(MessageParcel &parcel)
{
    return ITypesUtil::Unmarshalling(this->assets, parcel);
}

bool ChangeRequestRecoverAssetsReqBody::Marshalling(MessageParcel &parcel) const
{
    return ITypesUtil::Marshalling(this->assets, parcel);
}
}  // namespace OHOS::Media
