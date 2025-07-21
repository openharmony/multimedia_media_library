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

#include "check_photo_uri_permission_inner_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
using namespace std;
bool CheckUriPermissionInnerReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt64(this->targetTokenId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->uriType);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool CheckUriPermissionInnerReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt64(this->targetTokenId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->uriType);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

void CheckUriPermissionInnerReqBody::Convert2Dto(CheckUriPermissionInnerDto &dto)
{
    dto.targetTokenId = this->targetTokenId;
    dto.uriType = this->uriType;
    dto.inFileIds = this->fileIds;
    dto.columns = this->columns;
    return;
}

bool CheckUriPermissionInnerRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = ITypesUtil::Unmarshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->permissionTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool CheckUriPermissionInnerRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = ITypesUtil::Marshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->permissionTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

void CheckUriPermissionInnerRespBody::InitByDto(const CheckUriPermissionInnerDto &dto)
{
    this->fileIds = dto.outFileIds;
    this->permissionTypes = dto.permissionTypes;
    return;
}
} // namespace OHOS::Media