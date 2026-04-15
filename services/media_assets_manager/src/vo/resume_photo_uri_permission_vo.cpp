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

#define MLOG_TAG "ResumePhotoUriPermissionReqBodyVo"

#include "resume_photo_uri_permission_vo.h"

#include <sstream>
#include "media_log.h"

namespace OHOS::Media {
using namespace std;

bool ResumePhotoUriPermissionReqBody::Unmarshalling(MessageParcel &parcel)
{
    this->appIdentifier = parcel.ReadString();
    this->bundleName = parcel.ReadString();
    bool status = parcel.ReadUint32(this->bundleIndex);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadUint32(this->tokenId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool ResumePhotoUriPermissionReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->appIdentifier);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteUint32(this->bundleIndex);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteUint32(this->tokenId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool ResumePhotoUriPermissionRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->result);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool ResumePhotoUriPermissionRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->result);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

}  // namespace OHOS::Media
