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

#ifndef OHOS_MEDIA_PORTRAIT_NICKNAME_SERVICE_H
#define OHOS_MEDIA_PORTRAIT_NICKNAME_SERVICE_H

#include <memory>
#include <string>
#include <vector>

#include "portrait_nickname_merge_plan.h"
#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
struct MergeAlbumInfo;

class PortraitNickNameService {
public:
    static int32_t Operate(const std::string &albumId, const std::string &operation,
        const std::vector<std::string> &nickNames, const std::shared_ptr<MediaLibraryRdbStore> &rdbStore);
    static int32_t PrepareMergePlan(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
        const std::shared_ptr<MediaLibraryRdbStore> &rdbStore, PortraitNickNameMergePlan &mergePlan);
    static int32_t ApplyMergePlan(const PortraitNickNameMergePlan &mergePlan,
        const std::shared_ptr<MediaLibraryRdbStore> &rdbStore);
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_PORTRAIT_NICKNAME_SERVICE_H
