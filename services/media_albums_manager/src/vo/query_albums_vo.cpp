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

#include "query_albums_vo.h"

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {

bool QueryAlbumsReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->albumType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Read albumType failed");
    status = parcel.ReadInt32(this->albumSubType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Read albumSubType failed");
    status = parcel.ReadInt32(this->hiddenAlbumFetchMode);
    CHECK_AND_RETURN_RET_LOG(status, status, "Read hiddenAlbumFetchMode failed");
    status = IPC::ITypeMediaUtil::Unmarshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET_LOG(status, status, "Unmarshalling columns failed");
    return DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel);
}

bool QueryAlbumsReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->albumType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Write albumType failed");
    status = parcel.WriteInt32(this->albumSubType);
    CHECK_AND_RETURN_RET_LOG(status, status, "Write albumSubType failed");
    status = parcel.WriteInt32(this->hiddenAlbumFetchMode);
    CHECK_AND_RETURN_RET_LOG(status, status, "Write hiddenAlbumFetchMode failed");
    status = IPC::ITypeMediaUtil::Marshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET_LOG(status, status, "Marshalling columns failed");
    return DataShare::DataSharePredicates::Marshal(this->predicates, parcel);
}

bool QueryAlbumsRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    CHECK_AND_RETURN_RET_LOG(this->resultSet != nullptr, false, "resultSet nullptr");
    return true;
}

bool QueryAlbumsRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(this->resultSet != nullptr, false, "resultSet nullptr");
    return DataShare::DataShareResultSet::Marshal(this->resultSet, parcel);
}
} // namespace OHOS::Media