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

#ifndef OHOS_MEDIA_PORTRAIT_NICKNAME_RELATION_RESOLVER_H
#define OHOS_MEDIA_PORTRAIT_NICKNAME_RELATION_RESOLVER_H

#include <memory>
#include <string>
#include <vector>

#include "portrait_nickname_merge_plan.h"
#include "portrait_nickname_repository.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
class PortraitNickNameRelationResolver {
public:
    explicit PortraitNickNameRelationResolver(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore);

    int32_t ResolveRelatedAlbumIds(const std::string &albumId, std::vector<std::string> &albumIds) const;
    int32_t ResolveMinAlbumId(const std::vector<std::string> &albumIds, std::string &minAlbumId) const;
    int32_t ResolveAddTarget(const std::string &albumId, std::string &targetAlbumId,
        std::vector<std::string> &relatedAlbumIds) const;
    bool IsPortraitAlbumMerge(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
        const PortraitNickNameRepository &repository) const;
    int32_t ResolveMergePlan(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
        const PortraitNickNameRepository &repository, PortraitNickNameMergePlan &mergePlan) const;

private:
    static std::vector<std::string> DedupAlbumIds(const std::vector<std::string> &albumIds);
    int32_t QueryGroupTags(const std::string &albumId, std::vector<std::string> &groupTags) const;

private:
    std::shared_ptr<MediaLibraryRdbStore> rdbStore_;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_PORTRAIT_NICKNAME_RELATION_RESOLVER_H
