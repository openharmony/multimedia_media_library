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

#ifndef OHOS_MEDIA_PORTRAIT_NICKNAME_MERGE_PLAN_H
#define OHOS_MEDIA_PORTRAIT_NICKNAME_MERGE_PLAN_H

#include <string>
#include <vector>

namespace OHOS::Media {
struct PortraitNickNameMergePlan {
    std::string retainedAlbumId;
    std::vector<std::string> affectedAlbumIds;
    std::vector<std::string> mergedNickNames;

    bool IsNoOp() const;
    std::vector<std::string> GetRemovedAlbumIds() const;
    std::string DebugString() const;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_PORTRAIT_NICKNAME_MERGE_PLAN_H
