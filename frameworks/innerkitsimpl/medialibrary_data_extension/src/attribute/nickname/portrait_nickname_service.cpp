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

#define MLOG_TAG "PortraitNickService"

#include "portrait_nickname_service.h"

#include <unordered_set>

#include "analysis_album_attribute_const.h"
#include "portrait_nickname_relation_resolver.h"
#include "portrait_nickname_repository.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
namespace {
std::vector<std::string> DedupNickNames(const std::vector<std::string> &nickNames)
{
    std::vector<std::string> uniqueNickNames;
    std::unordered_set<std::string> nickNameSet;
    for (const auto &nickName : nickNames) {
        if (nickNameSet.insert(nickName).second) {
            uniqueNickNames.push_back(nickName);
        }
    }
    return uniqueNickNames;
}

int32_t MergeNickNames(const PortraitNickNameMergePlan &mergePlan, const PortraitNickNameRepository &repository)
{
    CHECK_AND_RETURN_RET_LOG(!mergePlan.retainedAlbumId.empty(), E_INVALID_VALUES, "retainedAlbumId is empty");
    CHECK_AND_RETURN_RET_LOG(!mergePlan.affectedAlbumIds.empty(), E_INVALID_VALUES, "affectedAlbumIds is empty");
    if (!mergePlan.mergedNickNames.empty()) {
        int32_t ret = repository.InsertNickNames(mergePlan.retainedAlbumId, mergePlan.mergedNickNames);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "add merged portrait nicknames failed, err: %{public}d", ret);
    }
    std::vector<std::string> removedAlbumIds = mergePlan.GetRemovedAlbumIds();
    if (removedAlbumIds.empty()) {
        MEDIA_INFO_LOG("portrait nickname merge finished without redundant albums, retainedAlbumId: %{public}s",
            mergePlan.retainedAlbumId.c_str());
        return E_OK;
    }
    int32_t ret = repository.DeleteNickNames(removedAlbumIds);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "delete removed portrait nicknames failed, err: %{public}d", ret);
    MEDIA_INFO_LOG("portrait nickname merge finished, retainedAlbumId: %{public}s, removedAlbumCount: %{public}zu",
        mergePlan.retainedAlbumId.c_str(), removedAlbumIds.size());
    return E_OK;
}

int32_t AddNickNames(const std::string &targetAlbumId, const std::vector<std::string> &relatedAlbumIds,
    const std::vector<std::string> &nickNames, const PortraitNickNameRepository &repository)
{
    CHECK_AND_RETURN_RET_LOG(!targetAlbumId.empty(), E_INVALID_VALUES, "targetAlbumId is empty");
    CHECK_AND_RETURN_RET_LOG(!relatedAlbumIds.empty(), E_INVALID_VALUES, "relatedAlbumIds is empty");
    CHECK_AND_RETURN_RET_LOG(!nickNames.empty(), E_INVALID_VALUES, "nickNames is empty");
    int32_t ret = repository.CheckNickNameLimit(targetAlbumId, nickNames);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "check portrait nickname limit failed, err: %{public}d", ret);
    ret = repository.InsertNickNames(targetAlbumId, nickNames);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "add portrait nickname failed, err: %{public}d", ret);
    MEDIA_INFO_LOG("add portrait nickname success, targetAlbumId: %{public}s, nickNameCount: %{public}zu, "
        "relatedAlbumCount: %{public}zu", targetAlbumId.c_str(), nickNames.size(), relatedAlbumIds.size());
    return E_OK;
}

int32_t RemoveNickNames(const std::string &albumId, const std::vector<std::string> &relatedAlbumIds,
    const std::vector<std::string> &nickNames, const PortraitNickNameRepository &repository)
{
    int32_t ret = repository.DeleteNickNames(relatedAlbumIds, nickNames);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "remove portrait nickname failed, err: %{public}d", ret);
    MEDIA_INFO_LOG("remove portrait nickname success, requestAlbumId: %{public}s, nickNameCount: %{public}zu, "
        "relatedAlbumCount: %{public}zu", albumId.c_str(), nickNames.size(), relatedAlbumIds.size());
    return E_OK;
}
} // namespace

int32_t PortraitNickNameService::Operate(const std::string &albumId, const std::string &operation,
    const std::vector<std::string> &nickNames, const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    PortraitNickNameRepository repository(rdbStore);
    PortraitNickNameRelationResolver relationResolver(rdbStore);
    CHECK_AND_RETURN_RET_LOG(repository.Exists(albumId), E_INVALID_VALUES, "portrait album not found");
    const std::vector<std::string> uniqueNickNames = DedupNickNames(nickNames);
    CHECK_AND_RETURN_RET(!uniqueNickNames.empty(), E_OK);
    if (operation == ANALYSIS_ALBUM_OP_ADD) {
        std::string targetAlbumId;
        std::vector<std::string> relatedAlbumIds;
        int32_t ret = relationResolver.ResolveAddTarget(albumId, targetAlbumId, relatedAlbumIds);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret,
            "get portrait album nick name add target failed, err: %{public}d", ret);
        return AddNickNames(targetAlbumId, relatedAlbumIds, uniqueNickNames, repository);
    }
    CHECK_AND_RETURN_RET_LOG(operation == ANALYSIS_ALBUM_OP_REMOVE, E_INVALID_VALUES,
        "unsupported portrait nickname operation: %{public}s", operation.c_str());
    std::vector<std::string> relatedAlbumIds;
    int32_t ret = relationResolver.ResolveRelatedAlbumIds(albumId, relatedAlbumIds);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "get related portrait album ids failed, err: %{public}d", ret);
    return RemoveNickNames(albumId, relatedAlbumIds, uniqueNickNames, repository);
}

int32_t PortraitNickNameService::PrepareMergePlan(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore, PortraitNickNameMergePlan &mergePlan)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    PortraitNickNameRepository repository(rdbStore);
    PortraitNickNameRelationResolver relationResolver(rdbStore);
    if (!relationResolver.IsPortraitAlbumMerge(mergeAlbumInfo, repository)) {
        return E_OK;
    }
    int32_t ret = relationResolver.ResolveMergePlan(mergeAlbumInfo, repository, mergePlan);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "ResolvePortraitNickNameMergePlan failed, err: %{public}d", ret);
    mergePlan.mergedNickNames = DedupNickNames(mergePlan.mergedNickNames);
    MEDIA_INFO_LOG("portrait nickname merge prepared, %{public}s", mergePlan.DebugString().c_str());
    return E_OK;
}

int32_t PortraitNickNameService::ApplyMergePlan(const PortraitNickNameMergePlan &mergePlan,
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    if (mergePlan.retainedAlbumId.empty()) {
        return E_OK;
    }
    PortraitNickNameRepository repository(rdbStore);
    return MergeNickNames(mergePlan, repository);
}
} // namespace OHOS::Media
