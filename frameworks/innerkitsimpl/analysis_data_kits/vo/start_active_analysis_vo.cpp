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

#include "start_active_analysis_vo.h"

#include <sstream>

#include "media_log.h"

namespace OHOS::Media {
bool StartActiveAnalysisReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32Vector(&analysisTypes), false,
        "Failed to read start active analysis types");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadStringVector(&fileIds), false,
        "Failed to read start active analysis fileIds");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(param), false,
        "Failed to read start active analysis param");
    callbackRemote = parcel.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(callbackRemote != nullptr, false,
        "Failed to read start active analysis callback remote");
    return true;
}

bool StartActiveAnalysisReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32Vector(analysisTypes), false,
        "Failed to write start active analysis types, size: %{public}zu", analysisTypes.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteStringVector(fileIds), false,
        "Failed to write start active analysis fileIds, size: %{public}zu", fileIds.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(param), false,
        "Failed to write start active analysis param, size: %{public}zu", param.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteRemoteObject(callbackRemote), false,
        "Failed to write start active analysis callback remote");
    return true;
}

std::string StartActiveAnalysisReqBody::ToString() const
{
    std::stringstream ss;
    ss << "analysisTypeSize=" << analysisTypes.size() << ", fileIdSize=" << fileIds.size()
       << ", paramSize=" << param.size();
    return ss.str();
}

bool StartActiveAnalysisRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(result), false,
        "Failed to read start active analysis result");
    bool hasSaRemote = false;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadBool(hasSaRemote), false,
        "Failed to read start active analysis hasSaRemote flag");
    if (!hasSaRemote) {
        saRemote = nullptr;
        return true;
    }
    saRemote = parcel.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(saRemote != nullptr, false,
        "Failed to read start active analysis sa remote");
    return true;
}

bool StartActiveAnalysisRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(result), false,
        "Failed to write start active analysis result, result: %{public}d", result);
    CHECK_AND_RETURN_RET_LOG(parcel.WriteBool(saRemote != nullptr), false,
        "Failed to write start active analysis hasSaRemote flag");
    if (saRemote == nullptr) {
        return true;
    }
    CHECK_AND_RETURN_RET_LOG(parcel.WriteRemoteObject(saRemote), false,
        "Failed to write start active analysis sa remote");
    return true;
}

std::string StartActiveAnalysisRespBody::ToString() const
{
    std::stringstream ss;
    ss << "result=" << result << ", hasSaRemote=" << (saRemote != nullptr);
    return ss.str();
}
} // namespace OHOS::Media
