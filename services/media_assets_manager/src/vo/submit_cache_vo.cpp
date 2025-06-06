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

#include "submit_cache_vo.h"

#include <sstream>

#include "itypes_util.h"

namespace OHOS::Media {

bool SubmitCacheReqBody::Unmarshalling(MessageParcel &parcel)
{
    return ITypesUtil::Unmarshal(parcel, isWriteGpsAdvanced, values);
}

bool SubmitCacheReqBody::Marshalling(MessageParcel &parcel) const
{
    return ITypesUtil::Marshal(parcel, isWriteGpsAdvanced, values);
}

bool SubmitCacheRspBody::Unmarshalling(MessageParcel &parcel)
{
    return ITypesUtil::Unmarshal(parcel, fileId, outUri);
}

bool SubmitCacheRspBody::Marshalling(MessageParcel &parcel) const
{
    return ITypesUtil::Marshal(parcel, fileId, outUri);
}
}  // namespace OHOS::Media