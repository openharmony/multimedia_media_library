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
 
#include "change_request_move_assets_to_dir_vo.h"
#include <sstream>
 
#include "media_itypes_utils.h"
#include "media_log.h"
 
namespace OHOS::Media {
 
bool ChangeRequestMoveAssetsToDirReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!IPC::ITypeMediaUtil::UnmarshalStrVec(assets, parcel)) {
        MEDIA_ERR_LOG("Failed to unmarshall assets");
        return false;
    }
    if (!parcel.ReadString(targetDir)) {
        MEDIA_ERR_LOG("Failed to unmarshall targetDir");
        return false;
    }
    if (!parcel.ReadInt32(requestId)) {
        MEDIA_ERR_LOG("Failed to unmarshall requestId");
        return false;
    }
    if (!parcel.ReadInt32(mode)) {
        MEDIA_ERR_LOG("Failed to unmarshall mode");
        return false;
    }
    return true;
}
 
bool ChangeRequestMoveAssetsToDirReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!IPC::ITypeMediaUtil::MarshalStrVec(assets, parcel)) {
        MEDIA_ERR_LOG("Failed to marshall assets");
        return false;
    }
    if (!parcel.WriteString(targetDir)) {
        MEDIA_ERR_LOG("Failed to marshall targetDir");
        return false;
    }
    if (!parcel.WriteInt32(requestId)) {
        MEDIA_ERR_LOG("Failed to marshall requestId");
        return false;
    }
    if (!parcel.WriteInt32(mode)) {
        MEDIA_ERR_LOG("Failed to marshall mode");
        return false;
    }
    return true;
}
 
bool ChangeRequestMoveAssetsToDirRespBody::Unmarshalling(MessageParcel &parcel)
{
    if (!parcel.ReadInt32(errCode)) {
        MEDIA_ERR_LOG("Failed to unmarshall errCode");
        return false;
    }
    if (!IPC::ITypeMediaUtil::UnmarshalStrVec(resultList, parcel)) {
        MEDIA_ERR_LOG("Failed to unmarshall resultList");
        return false;
    }
    if (!parcel.ReadInt64(processedSize)) {
        MEDIA_ERR_LOG("Failed to unmarshall processedSize");
        return false;
    }
    if (!parcel.ReadInt64(remainSize)) {
        MEDIA_ERR_LOG("Failed to unmarshall remainSize");
        return false;
    }
    if (!parcel.ReadInt64(processedCount)) {
        MEDIA_ERR_LOG("Failed to unmarshall processedCount");
        return false;
    }
    if (!parcel.ReadInt64(remainCount)) {
        MEDIA_ERR_LOG("Failed to unmarshall remainCount");
        return false;
    }
    return true;
}
 
bool ChangeRequestMoveAssetsToDirRespBody::Marshalling(MessageParcel &parcel) const
{
    if (!parcel.WriteInt32(errCode)) {
        MEDIA_ERR_LOG("Failed to marshall errCode");
        return false;
    }
    if (!IPC::ITypeMediaUtil::MarshalStrVec(resultList, parcel)) {
        MEDIA_ERR_LOG("Failed to marshall resultList");
        return false;
    }
    if (!parcel.WriteInt64(processedSize)) {
        MEDIA_ERR_LOG("Failed to marshall processedSize");
        return false;
    }
    if (!parcel.WriteInt64(remainSize)) {
        MEDIA_ERR_LOG("Failed to marshall remainSize");
        return false;
    }
    if (!parcel.WriteInt64(processedCount)) {
        MEDIA_ERR_LOG("Failed to marshall processedCount");
        return false;
    }
    if (!parcel.WriteInt64(remainCount)) {
        MEDIA_ERR_LOG("Failed to marshall remainCount");
        return false;
    }
    return true;
}
} // namespace OHOS::Media