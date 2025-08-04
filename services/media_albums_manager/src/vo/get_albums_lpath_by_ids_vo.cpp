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

#include "get_albums_lpath_by_ids_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
bool GetAlbumsLpathByIdsReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadUint32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetAlbumsLpathByIdsReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteUint32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetAlbumsLpathByIdsRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->lpath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetAlbumsLpathByIdsRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->lpath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
};