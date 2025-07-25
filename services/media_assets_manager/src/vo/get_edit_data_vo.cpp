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

#include "get_edit_data_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
// LCOV_EXCL_START
bool GetEditDataReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel)) {
        return false;
    }
    return true;
}

bool GetEditDataReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!DataShare::DataSharePredicates::Marshal(this->predicates, parcel)) {
        return false;
    }
    return true;
}


std::string GetEditDataReqBody::ToString() const
{
    std::stringstream ss;
    // todo: add the content of GetAssetsReqBody
    return ss.str();
}

bool GetEditDataRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    if (this->resultSet == nullptr) {
        MEDIA_ERR_LOG("GetEditDataRespBody ReadFromParcel failed");
        return false;
    }
    MEDIA_INFO_LOG("GetEditDataRespBody ReadFromParcel success");
    return true;
}

bool GetEditDataRespBody::Marshalling(MessageParcel &parcel) const
{
    if (this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel)) {
        MEDIA_ERR_LOG("GetEditDataRespBody Marshalling failed");
        return false;
    }
    MEDIA_INFO_LOG("GetEditDataRespBody Marshalling success");
    return true;
}

std::string GetEditDataRespBody::ToString() const
{
    std::stringstream ss;
    // todo: add the content of GetAssetsRespBody
    return ss.str();
}
// LCOV_EXCL_STOP
};