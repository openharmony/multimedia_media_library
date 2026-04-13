/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaPreferredCompatibleModeVo"

#include "preferred_compatible_mode_vo.h"

#include "media_log.h"

namespace OHOS::Media {
bool SetPreferredCompatibleModeReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool SetPreferredCompatibleModeReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetPreferredCompatibleModeReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetPreferredCompatibleModeReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetPreferredCompatibleModeRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetPreferredCompatibleModeRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
} // namespace OHOS::Media