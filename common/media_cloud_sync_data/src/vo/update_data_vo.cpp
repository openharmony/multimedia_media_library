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

#define MLOG_TAG "Media_Cloud_Vo"

#include "update_data_vo.h"

#include <sstream>

#include "media_log.h"
#include "cloud_media_sync_const.h"
#include "itypes_util.h"

namespace OHOS::Media::CloudSync {
bool UpdateDataReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(DataShare::DataSharePredicates::Unmarshal(predicates, parcel), false, "predicates");
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Unmarshal(parcel, value.valuesMap), false, "value.valuesMap");
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Unmarshal(parcel, tableName, operateName), false, "tableName, operateName");
    return true;
}

bool UpdateDataReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(DataShare::DataSharePredicates::Marshal(predicates, parcel), false, "predicates");
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Marshal(parcel, value.valuesMap), false, "value.valuesMap");
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Marshal(parcel, tableName, operateName), false, "tableName, operateName");
    return true;
}
}  // namespace OHOS::Media::CloudSync