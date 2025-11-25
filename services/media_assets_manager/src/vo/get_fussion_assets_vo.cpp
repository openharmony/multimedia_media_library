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

#include "get_fussion_assets_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {

bool FussionAssetsResult::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(assetsType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(assetsCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(assetsPath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool FussionAssetsResult::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(assetsType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(assetsCount);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(assetsPath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetFussionAssetsReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(albumId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(albumType);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetFussionAssetsReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(albumId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(albumType);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

std::string GetFussionAssetsReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"this->albumId\"" << std::to_string(this->albumId) << ", "
        << "\"this->albumType\"" << std::to_string(this->albumType) << "\""
        << "}";
    return ss.str();
}

bool GetFussionAssetsRespBody::Unmarshalling(MessageParcel &parcel)
{
    return IPC::ITypeMediaUtil::UnmarshallingParcelable<FussionAssetsResult>(this->queryResult, parcel);
}

bool GetFussionAssetsRespBody::Marshalling(MessageParcel &parcel) const
{
    return IPC::ITypeMediaUtil::MarshallingParcelable<FussionAssetsResult>(this->queryResult, parcel);
}
}  // namespace OHOS::Media