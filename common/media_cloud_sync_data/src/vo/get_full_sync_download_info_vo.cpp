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

#define MLOG_TAG "Media_Cloud_Vo"

#include "get_full_sync_download_info_vo.h"

#include <sstream>

#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool GetFullSyncDownloadInfoBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Unmarshalling(flagsInfo, parcel), false, "flagsInfo");
    return true;
}

bool GetFullSyncDownloadInfoBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(ITypesUtil::Marshalling(flagsInfo, parcel), false, "flagsInfo");
    return true;
}

std::string GetFullSyncDownloadInfoBody::ToString() const
{
    std::stringstream ss;
    ss << "[";
    for (auto &[key, value] : this->flagsInfo) {
        ss << "{" << key << "," << std::to_string(value) << "}";
    }
    ss << "]";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync