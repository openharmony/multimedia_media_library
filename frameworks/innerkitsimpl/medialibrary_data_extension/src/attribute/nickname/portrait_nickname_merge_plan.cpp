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

#include "portrait_nickname_merge_plan.h"

#include <sstream>

namespace OHOS::Media {
bool PortraitNickNameMergePlan::IsNoOp() const
{
    return affectedAlbumIds.size() <= 1;
}

std::vector<std::string> PortraitNickNameMergePlan::GetRemovedAlbumIds() const
{
    std::vector<std::string> removedAlbumIds;
    for (const auto &albumId : affectedAlbumIds) {
        if (albumId != retainedAlbumId) {
            removedAlbumIds.push_back(albumId);
        }
    }
    return removedAlbumIds;
}

std::string PortraitNickNameMergePlan::DebugString() const
{
    std::stringstream stream;
    stream << "retainedAlbumId=" << retainedAlbumId << ", affectedAlbumCount=" << affectedAlbumIds.size()
           << ", mergedNickNameCount=" << mergedNickNames.size();
    return stream.str();
}
} // namespace OHOS::Media
