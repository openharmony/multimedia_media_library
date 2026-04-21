/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <sstream>

#include "prepare_lcd_vo.h"
#include "media_log.h"
#include "media_itypes_utils.h"

namespace OHOS::Media {

bool PrepareLcdReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Marshalling(fileIds, parcel), false, "Failed to write fileIds");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteUint32(netBearerBitmap), false, "Failed to write netBearerBitmap");
    return true;
}

bool PrepareLcdReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Unmarshalling(fileIds, parcel), false, "Failed to read fileIds");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadUint32(netBearerBitmap), false, "Failed to read netBearerBitmap");
    return true;
}

std::string PrepareLcdReqBody::ToString() const
{
    std::stringstream ss;
    ss << "PrepareLcdReqBody{fileIds.size()=" << fileIds.size() << ", netBearerBitmap=" << netBearerBitmap << "}";
    return ss.str();
}

bool PrepareLcdRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(ret), false, "Failed to write ret");

    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Marshalling(results, parcel), false, "Failed to write results");

    return true;
}

bool PrepareLcdRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(ret), false, "Failed to read ret");

    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Unmarshalling(results, parcel), false, "Failed to read results");

    return true;
}

std::string PrepareLcdRespBody::ToString() const
{
    std::stringstream ss;
    ss << "PrepareLcdRespBody{ret=" << ret << ", results.size()=" << results.size() << "}";
    return ss.str();
}
}  // namespace OHOS::Media