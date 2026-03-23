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

#include "stop_active_analysis_vo.h"

#include <sstream>

#include "media_log.h"

namespace OHOS::Media {
bool StopActiveAnalysisReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32Vector(&analysisTypes), false,
        "Failed to read stop active analysis types");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadStringVector(&fileIds), false,
        "Failed to read stop active analysis fileIds");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(param), false,
        "Failed to read stop active analysis param");
    return true;
}

bool StopActiveAnalysisReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32Vector(analysisTypes), false,
        "Failed to write stop active analysis types, size: %{public}zu", analysisTypes.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteStringVector(fileIds), false,
        "Failed to write stop active analysis fileIds, size: %{public}zu", fileIds.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(param), false,
        "Failed to write stop active analysis param, size: %{public}zu", param.size());
    return true;
}

std::string StopActiveAnalysisReqBody::ToString() const
{
    std::stringstream ss;
    ss << "analysisTypeSize=" << analysisTypes.size() << ", fileIdSize=" << fileIds.size()
       << ", paramSize=" << param.size();
    return ss.str();
}

bool StopActiveAnalysisRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(result), false,
        "Failed to read stop active analysis result");
    return true;
}

bool StopActiveAnalysisRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(result), false,
        "Failed to write stop active analysis result, result: %{public}d", result);
    return true;
}

std::string StopActiveAnalysisRespBody::ToString() const
{
    std::stringstream ss;
    ss << "result=" << result;
    return ss.str();
}
} // namespace OHOS::Media
