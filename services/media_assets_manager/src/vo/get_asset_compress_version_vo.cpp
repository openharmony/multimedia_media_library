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

#define MLOG_TAG "MediaGetAssetCompressVersionVo"

#include "get_asset_compress_version_vo.h"

#include <sstream>

#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media {
bool GetAssetCompressVersionRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->version);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetAssetCompressVersionRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->version);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
} // namespace OHOS::Media