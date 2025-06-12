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

#include "get_cloudmedia_asset_status_vo.h"

#include <sstream>

#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool GetCloudMediaAssetStatusReqBody::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(this->status);
}

bool GetCloudMediaAssetStatusReqBody::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(this->status);
}

string GetCloudMediaAssetStatusReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"status\": \"" << this->status << "\""
        << "}";
    return ss.str();
}
} // namespace OHOS::Media