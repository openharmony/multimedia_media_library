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

#define MLOG_TAG "MediaGetResultSetFromPhotosExtendVo"

#include "get_result_set_from_photos_extend_vo.h"

#include <sstream>

#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool GetResultSetFromPhotosExtendReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->value);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetResultSetFromPhotosExtendReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->value);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->columns, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetResultSetFromPhotosExtendRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    CHECK_AND_RETURN_RET(this->resultSet != nullptr, false);
    return true;
}

bool GetResultSetFromPhotosExtendRespBody::Marshalling(MessageParcel &parcel) const
{
    bool cond = this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel);
    CHECK_AND_RETURN_RET(!cond, false);
    return true;
}
} // namespace OHOS::Media