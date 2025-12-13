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

#include "get_albumid_by_lpath_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
// LCOV_EXCL_START
bool GetAlbumIdByLpathReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel)) {
        return false;
    }
    if (!ITypesUtil::Unmarshalling(this->columns, parcel)) {
        return false;
    }
    return true;
}

bool GetAlbumIdByLpathReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!DataShare::DataSharePredicates::Marshal(this->predicates, parcel)) {
        return false;
    }
    if (!ITypesUtil::Marshalling(this->columns, parcel)) {
        return false;
    }
    return true;
}


std::string GetAlbumIdByLpathReqBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}

bool GetAlbumIdByLpathRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetAlbumIdByLpathRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

std::string GetAlbumIdByLpathRespBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}
// LCOV_EXCL_STOP
};