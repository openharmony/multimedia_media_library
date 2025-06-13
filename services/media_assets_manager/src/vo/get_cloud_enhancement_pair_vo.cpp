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

#define MLOG_TAG "MediaGetCloudEnhancementPairVo"

#include "get_cloud_enhancement_pair_vo.h"

#include <sstream>

#include "media_log.h"
#include "data_ability_predicates.h"

namespace OHOS::Media {
using namespace std;
bool GetCloudEnhancementPairReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->photoUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetCloudEnhancementPairReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->photoUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

string GetCloudEnhancementPairReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"photoUri\": \"" << photoUri
       << "}";
    return ss.str();
}

bool GetCloudEnhancementPairRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    CHECK_AND_RETURN_RET_LOG(this->resultSet != nullptr, false, "resultSet is nullptr");
    return true;
}

bool GetCloudEnhancementPairRespBody::Marshalling(MessageParcel &parcel) const
{
    bool cond = this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel);
    CHECK_AND_RETURN_RET_LOG(!cond, false, "marshalling failed");
    return true;
}
} // namespace OHOS::Media