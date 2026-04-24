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

#define MLOG_TAG "PortraitNickResolver"

#include "portrait_nickname_relation_resolver.h"

#include <algorithm>
#include <climits>
#include <unordered_set>

#include "media_log.h"
#include "media_string_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "vision_face_tag_column.h"
#include "vision_portrait_nickname_column.h"

namespace OHOS::Media {
using namespace OHOS::NativeRdb;
namespace {
constexpr size_t PORTRAIT_MERGE_ALBUM_COUNT = 2;
}

PortraitNickNameRelationResolver::PortraitNickNameRelationResolver(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore) : rdbStore_(rdbStore)
{
}

std::vector<std::string> PortraitNickNameRelationResolver::DedupAlbumIds(const std::vector<std::string> &albumIds)
{
    std::vector<std::string> uniqueAlbumIds;
    std::unordered_set<std::string> albumIdSet;
    for (const auto &albumId : albumIds) {
        if (albumIdSet.insert(albumId).second) {
            uniqueAlbumIds.push_back(albumId);
        }
    }
    return uniqueAlbumIds;
}

int32_t PortraitNickNameRelationResolver::QueryGroupTags(const std::string &albumId,
    std::vector<std::string> &groupTags) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    const std::string sql =
        "SELECT DISTINCT group_tag FROM AnalysisAlbum WHERE album_id = ? AND group_tag IS NOT NULL AND group_tag != ''";
    std::vector<std::string> bindArgs = { albumId };
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "query groupTags failed");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        groupTags.push_back(GetStringVal(GROUP_TAG, resultSet));
    }
    return E_OK;
}

int32_t PortraitNickNameRelationResolver::ResolveRelatedAlbumIds(const std::string &albumId,
    std::vector<std::string> &albumIds) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::vector<std::string> groupTags;
    CHECK_AND_RETURN_RET_LOG(QueryGroupTags(albumId, groupTags) == E_OK,
        E_HAS_DB_ERROR, "query groupTags failed, albumId: %{public}s", albumId.c_str());
    if (groupTags.empty()) {
        MEDIA_WARN_LOG("groupTags is empty, fallback to current albumId: %{public}s", albumId.c_str());
        albumIds = { albumId };
        return E_OK;
    }

    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.In(GROUP_TAG, groupTags);
    predicates.EqualTo(ALBUM_TYPE, std::to_string(static_cast<int32_t>(PhotoAlbumType::SMART)));
    predicates.EqualTo(ALBUM_SUBTYPE, std::to_string(static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT)));
    std::vector<std::string> columns = { ALBUM_ID };
    auto resultSet = rdbStore_->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "query related portrait albums failed");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        albumIds.push_back(GetStringVal(ALBUM_ID, resultSet));
    }
    if (albumIds.empty()) {
        MEDIA_WARN_LOG("related portrait albums is empty, fallback to current albumId: %{public}s", albumId.c_str());
        albumIds = { albumId };
        return E_OK;
    }
    albumIds = DedupAlbumIds(albumIds);
    if (std::find(albumIds.begin(), albumIds.end(), albumId) == albumIds.end()) {
        MEDIA_WARN_LOG("related portrait albums miss current albumId: %{public}s, append it", albumId.c_str());
        albumIds.push_back(albumId);
    }
    return E_OK;
}

int32_t PortraitNickNameRelationResolver::ResolveMinAlbumId(const std::vector<std::string> &albumIds,
    std::string &minAlbumId) const
{
    CHECK_AND_RETURN_RET_LOG(!albumIds.empty(), E_INVALID_VALUES, "albumIds is empty");
    int32_t minAlbumIdValue = INT32_MAX;
    for (const auto &albumId : albumIds) {
        int32_t albumIdValue = 0;
        CHECK_AND_RETURN_RET_LOG(MediaStringUtils::ConvertToInt(albumId.c_str(), albumIdValue),
            E_HAS_DB_ERROR, "invalid portrait albumId: %{public}s", albumId.c_str());
        minAlbumIdValue = std::min(minAlbumIdValue, albumIdValue);
    }
    CHECK_AND_RETURN_RET_LOG(minAlbumIdValue != INT32_MAX, E_HAS_DB_ERROR, "failed to resolve min portrait albumId");
    minAlbumId = std::to_string(minAlbumIdValue);
    return E_OK;
}

int32_t PortraitNickNameRelationResolver::ResolveAddTarget(const std::string &albumId, std::string &targetAlbumId,
    std::vector<std::string> &relatedAlbumIds) const
{
    CHECK_AND_RETURN_RET_LOG(!albumId.empty(), E_INVALID_VALUES, "albumId is empty");
    CHECK_AND_RETURN_RET_LOG(ResolveRelatedAlbumIds(albumId, relatedAlbumIds) == E_OK,
        E_HAS_DB_ERROR, "resolve related portrait albumIds failed");
    return ResolveMinAlbumId(relatedAlbumIds, targetAlbumId);
}

bool PortraitNickNameRelationResolver::IsPortraitAlbumMerge(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
    const PortraitNickNameRepository &repository) const
{
    return mergeAlbumInfo.size() == PORTRAIT_MERGE_ALBUM_COUNT &&
        repository.Exists(std::to_string(mergeAlbumInfo[0].albumId)) &&
        repository.Exists(std::to_string(mergeAlbumInfo[1].albumId));
}

int32_t PortraitNickNameRelationResolver::ResolveMergePlan(const std::vector<MergeAlbumInfo> &mergeAlbumInfo,
    const PortraitNickNameRepository &repository, PortraitNickNameMergePlan &mergePlan) const
{
    CHECK_AND_RETURN_RET_LOG(IsPortraitAlbumMerge(mergeAlbumInfo, repository), E_INVALID_VALUES,
        "not portrait album merge");
    std::vector<std::string> currentRelatedAlbumIds;
    CHECK_AND_RETURN_RET_LOG(ResolveRelatedAlbumIds(std::to_string(mergeAlbumInfo[0].albumId), currentRelatedAlbumIds)
        == E_OK, E_HAS_DB_ERROR, "resolve current related portrait albumIds failed");
    std::vector<std::string> targetRelatedAlbumIds;
    CHECK_AND_RETURN_RET_LOG(ResolveRelatedAlbumIds(std::to_string(mergeAlbumInfo[1].albumId), targetRelatedAlbumIds)
        == E_OK, E_HAS_DB_ERROR, "resolve target related portrait albumIds failed");

    mergePlan.affectedAlbumIds = currentRelatedAlbumIds;
    mergePlan.affectedAlbumIds.insert(mergePlan.affectedAlbumIds.end(), targetRelatedAlbumIds.begin(),
        targetRelatedAlbumIds.end());
    mergePlan.affectedAlbumIds = DedupAlbumIds(mergePlan.affectedAlbumIds);
    CHECK_AND_RETURN_RET_LOG(!mergePlan.affectedAlbumIds.empty(), E_HAS_DB_ERROR, "affectedAlbumIds is empty");
    int32_t ret = ResolveMinAlbumId(mergePlan.affectedAlbumIds, mergePlan.retainedAlbumId);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "resolve retained albumId failed, err: %{public}d", ret);
    ret = repository.QueryNickNames(mergePlan.affectedAlbumIds, mergePlan.mergedNickNames);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "query merged portrait nicknames failed, err: %{public}d", ret);
    return E_OK;
}
} // namespace OHOS::Media
