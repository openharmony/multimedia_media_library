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

#include "change_request_add_assets_vo.h"
#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {

bool ChangeRequestAddAssetsReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = IPC::ITypeMediaUtil::UnmarshalStrVec(this->assets, parcel);
    CHECK_AND_RETURN_RET(status, status);
    parcel.ReadInt32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    parcel.ReadBool(this->isHighlight);
    CHECK_AND_RETURN_RET(status, status);
    parcel.ReadBool(this->isHiddenOnly);
    CHECK_AND_RETURN_RET(status, status);

    return true;
}

bool ChangeRequestAddAssetsReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = IPC::ITypeMediaUtil::MarshalStrVec(this->assets, parcel);
    CHECK_AND_RETURN_RET(status, status);
    parcel.WriteInt32(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    parcel.WriteBool(this->isHighlight);
    CHECK_AND_RETURN_RET(status, status);
    parcel.WriteBool(this->isHiddenOnly);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool ChangeRequestAddAssetsRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->albumCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->imageCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->videoCount);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool ChangeRequestAddAssetsRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->albumCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->imageCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->videoCount);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
} // namespace OHOS::Media
