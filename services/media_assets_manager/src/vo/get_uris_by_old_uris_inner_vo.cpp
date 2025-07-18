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

#include "get_uris_by_old_uris_inner_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
using namespace std;
bool GetUrisByOldUrisInnerReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = ITypesUtil::Unmarshalling(this->uris, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetUrisByOldUrisInnerReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = ITypesUtil::Marshalling(this->uris, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

void GetUrisByOldUrisInnerReqBody::Convert2Dto(GetUrisByOldUrisInnerDto &dto)
{
    dto.uris = this->uris;
    dto.columns = this->columns;
    return;
}

bool GetUrisByOldUrisInnerRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = ITypesUtil::Unmarshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->datas, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->displayNames, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->oldFileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->oldDatas, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetUrisByOldUrisInnerRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = ITypesUtil::Marshalling(this->fileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->datas, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->displayNames, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->oldFileIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->oldDatas, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

void GetUrisByOldUrisInnerRespBody::InitByDto(const GetUrisByOldUrisInnerDto &dto)
{
    this->fileIds = dto.fileIds;
    this->datas = dto.datas;
    this->displayNames = dto.displayNames;
    this->oldFileIds = dto.oldFileIds;
    this->oldDatas = dto.oldDatas;
    return;
}
} // namespace OHOS::Media