/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#define MLOG_TAG "MediaAlbumsRdbOperations"
 
#include "media_albums_rdb_operations.h"

#include <string>

#include "abs_rdb_predicates.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "media_file_uri.h"
#include "medialibrary_errno.h"
#include "story_album_column.h"
#include "photo_album_column.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_utils.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "vision_column.h"
#include "change_request_move_assets_dto.h"
#include "vision_image_face_column.h"
#include "photo_map_column.h"
#include "media_column.h"
#include "rdb_utils.h"
#include "dfx_refresh_manager.h"
#include "refresh_business_name.h"
#include "vision_affective_column.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media {
static constexpr int32_t HIGHLIGHT_DELETED = -2;
const std::string ALBUM_LPATH_PREFIX = "/Pictures/Users/";
static const string GROUP_TAG = "group_tag";

MediaAlbumsRdbOperations::MediaAlbumsRdbOperations() {}

int32_t MediaAlbumsRdbOperations::DeleteHighlightAlbums(const vector<string>& albumIds)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR,
        "rdbStore is nullptr");
    NativeRdb::RdbPredicates predicates(HIGHLIGHT_ALBUM_TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_ID, albumIds);
    ValuesBucket values;
    values.PutInt(HIGHLIGHT_STATUS, HIGHLIGHT_DELETED);
    int32_t changedRows = 0;
    int32_t result = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG(result == NativeRdb::E_OK, E_HAS_DB_ERROR,
        "Delete highlight album failed, result is %{private}d", result);
    return changedRows;
}

int32_t MediaAlbumsRdbOperations::SetHighlightUserActionData(const SetHighlightUserActionDataDto& dto)
{
    RdbPredicates queryPredicates(HIGHLIGHT_ALBUM_TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);

    vector<string> columns = { dto.userActionType };
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(queryPredicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("highlight user action data resultSet is null");
        return E_ERR;
    }
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count == 0 || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("highlight user action data get rdbstore failed");
        resultSet->Close();
        return E_ERR;
    }
    int64_t userActionDataCount = GetInt64Val(dto.userActionType, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("userActionDataCount: %{public}" PRId64 ", dto.actionData: %{public}d",
        userActionDataCount, dto.actionData);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(dto.userActionType, to_string(userActionDataCount + dto.actionData));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Story update operation, rdbStore is null.");
        return E_HAS_DB_ERROR;
    }
    int32_t updateRows = -1;
    int32_t errCode = rdbStore->Update(updateRows, valuesBucket, queryPredicates);
    if (errCode != NativeRdb::E_OK || updateRows < 0) {
        MEDIA_ERR_LOG("Story Update db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(updateRows);
}

int32_t MediaAlbumsRdbOperations::GetFaceId(int32_t albumId, string& groupTag)
{
    NativeRdb::RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    vector<string> columns = { GROUP_TAG };
    auto resultSet = MediaLibraryRdbStore::StepQueryWithoutCheck(predicates, columns);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, E_HAS_DB_ERROR, "Failed to query group tag!");
    groupTag = GetStringVal(GROUP_TAG, resultSet);
    return E_OK;
}

shared_ptr<NativeRdb::ResultSet> MediaAlbumsRdbOperations::MoveAssetsGetAlbumInfo(
    const ChangeRequestMoveAssetsDto &moveAssetsDto)
{
    NativeRdb::RdbPredicates rdbPredicates(PhotoAlbumColumns::TABLE);
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, moveAssetsDto.albumId);
    rdbPredicates.Or();
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, moveAssetsDto.targetAlbumId);
    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    return MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, fetchColumns);
}

shared_ptr<NativeRdb::ResultSet> MediaAlbumsRdbOperations::AddAssetsGetAlbumInfo(
    const ChangeRequestAddAssetsDto &addAssetsDto)
{
    NativeRdb::RdbPredicates rdbPredicates(PhotoAlbumColumns::TABLE);
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, addAssetsDto.albumId);

    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    return MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, fetchColumns);
}

shared_ptr<NativeRdb::ResultSet> MediaAlbumsRdbOperations::RemoveAssetsGetAlbumInfo(
    const ChangeRequestRemoveAssetsDto &removeAssetsDto)
{
    NativeRdb::RdbPredicates rdbPredicates(PhotoAlbumColumns::TABLE);
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, removeAssetsDto.albumId);

    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    return MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, fetchColumns);
}

int32_t MediaAlbumsRdbOperations::GetSelectedPortraitAlbumPredicatesByEmotion(AlbumGetSelectedAssetsDto &dto)
{
    string column = "( CASE WHEN " + VISION_AFFECTIVE_TABLE + "." + VALENCE + " >= 0.5 AND " + VISION_AFFECTIVE_TABLE +
                    "." + AROUSAL + " = 0.1 THEN 1 WHEN " + VISION_AFFECTIVE_TABLE + "." + VALENCE + " = 0.1 OR " +
                    VISION_AFFECTIVE_TABLE + "." + AROUSAL + " >= 0.5 THEN -1 ELSE 0 END ) * 1000 + " +
                    VISION_IMAGE_FACE_TABLE + "." + FACE_AESTHETICS_SCORE + " AS total_score";
    dto.columns.push_back(column);
 
    string onClause = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID + " = " + ANALYSIS_PHOTO_MAP_TABLE +
                      "." + PhotoMap::ASSET_ID + " AND " + ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ALBUM_ID +
                      " = " + to_string(dto.albumId);
    vector<string> clauses = {onClause};
    dto.predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On(clauses);
    onClause = VISION_IMAGE_FACE_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE + "." +
               MediaColumn::MEDIA_ID + " AND " + VISION_IMAGE_FACE_TABLE + "." + TAG_ID + " = ( SELECT " + GROUP_TAG +
               " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " +
               to_string(dto.albumId) + " )";
    clauses = {onClause};
    dto.predicates.InnerJoin(VISION_IMAGE_FACE_TABLE)->On(clauses);
    onClause = VISION_AFFECTIVE_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE + "." +
               MediaColumn::MEDIA_ID;
    clauses = {onClause};
    dto.predicates.LeftOuterJoin(VISION_AFFECTIVE_TABLE)->On(clauses);
 
    dto.predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, 0);
    dto.predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, 0);
    dto.predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0);
    bool isTemp = false;
    dto.predicates.EqualTo(PhotoColumn::PHOTO_IS_TEMP, isTemp);
    dto.predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
        to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)));
 
    string condition =  VISION_IMAGE_FACE_TABLE + "." + FACE_AESTHETICS_SCORE;
    dto.predicates.GreaterThan(condition, 20);
    condition =  "total_score";
    dto.predicates.GreaterThan(condition, 0);
    dto.predicates.OrderByDesc("total_score");
    dto.predicates.Distinct();
    return E_SUCCESS;
}
 
std::shared_ptr<DataShare::DataShareResultSet> MediaAlbumsRdbOperations::GetSelectedAssets(
                                                    AlbumGetSelectedAssetsDto &dto)
{
    auto startTime = MediaFileUtils::UTCTimeMilliSeconds();
    MediaLibraryRdbUtils::AddVirtualColumnsOfDateType(dto.columns);
    GetSelectedPortraitAlbumPredicatesByEmotion(dto);
    NativeRdb::RdbPredicates predicates =
        RdbDataShareAdapter::RdbUtils::ToPredicates(dto.predicates, PhotoColumn::PHOTOS_TABLE);
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, dto.columns);
    auto totalCostTime = MediaFileUtils::UTCTimeMilliSeconds() - startTime;
    AccurateRefresh::DfxRefreshManager::QueryStatementReport(
        AccurateRefresh::GET_ASSETS_BUSSINESS_NAME, totalCostTime, predicates.GetStatement());
    CHECK_AND_RETURN_RET_LOG(resultSet, nullptr, "Failed to query album assets");
    auto resultSetBridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
    return make_shared<DataShare::DataShareResultSet>(resultSetBridge);
}
} // namespace OHOS::Media