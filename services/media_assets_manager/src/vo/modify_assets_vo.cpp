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

#include "modify_assets_vo.h"

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {

bool ModifyAssetsReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->pending);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->favorite);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->hiddenStatus);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->recentShowStatus);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->userComment);
    CHECK_AND_RETURN_RET(status, status);
    return IPC::ITypeMediaUtil::Unmarshalling<int32_t>(this->fileIds, parcel);
}

bool ModifyAssetsReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->pending);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->favorite);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->hiddenStatus);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->recentShowStatus);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->title);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->userComment);
    CHECK_AND_RETURN_RET(status, status);
    return IPC::ITypeMediaUtil::Marshalling<int32_t>(this->fileIds, parcel);
}
} // namespace OHOS::Media
