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

#include "get_albums_by_ids_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
// LCOV_EXCL_START
bool GetAlbumsByIdsReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel)) {
        return false;
    }
    if (!ITypesUtil::Unmarshalling(this->columns, parcel)) {
        return false;
    }
    return true;
}

bool GetAlbumsByIdsReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!DataShare::DataSharePredicates::Marshal(this->predicates, parcel)) {
        return false;
    }
    if (!ITypesUtil::Marshalling(this->columns, parcel)) {
        return false;
    }
    return true;
}


std::string GetAlbumsByIdsReqBody::ToString() const
{
    std::stringstream ss;
    // todo: add the content of GetAssetsReqBody
    return ss.str();
}

bool GetAlbumsByIdsRspBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    if (this->resultSet == nullptr) {
        MEDIA_ERR_LOG("GetAlbumsByIdsRspBody ReadFromParcel failed");
        return false;
    }
    MEDIA_INFO_LOG("GetAlbumsByIdsRspBody ReadFromParcel success");
    return true;
}

bool GetAlbumsByIdsRspBody::Marshalling(MessageParcel &parcel) const
{
    if (this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel)) {
        MEDIA_ERR_LOG("GetAlbumsByIdsRspBody Marshalling failed");
        return false;
    }
    MEDIA_INFO_LOG("GetAlbumsByIdsRspBody Marshalling success");
    return true;
}

std::string GetAlbumsByIdsRspBody::ToString() const
{
    std::stringstream ss;
    // todo: add the content of GetAssetsRespBody
    return ss.str();
}
// LCOV_EXCL_STOP
};