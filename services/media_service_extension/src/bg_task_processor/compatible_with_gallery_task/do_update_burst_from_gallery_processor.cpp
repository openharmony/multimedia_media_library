/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaBgTask_DoUpdateBurstFromGalleryProcessor"

#include "do_update_burst_from_gallery_processor.h"

#include "abs_rdb_predicates.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_notify.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "uuid.h"
#include "asset_accurate_refresh.h"
#include "shooting_mode_column.h"

using namespace std;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace Media {
const int32_t WRONG_VALUE = 0;
const int32_t BATCH_QUERY_NUMBER = 200;
static const int32_t UUID_STR_LENGTH = 37;

int32_t DoUpdateBurstFromGalleryProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        UpdateBurst();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t DoUpdateBurstFromGalleryProcessor::Stop(const std::string &taskExtra)
{
    taskStop_ = true;
    return E_OK;
}

void DoUpdateBurstFromGalleryProcessor::UpdateBurst()
{
    UpdateBurstCoverLevelFromGallery();
    UpdateBurstFromGallery();
}

static string GenerateUuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

static std::string generateRegexpMatchForNumber(const int32_t num)
{
    std::string regexpMatchNumber = "[0-9]";
    std::string strRegexpMatch = "";
    for (int i = 0; i < num; i++) {
        strRegexpMatch += regexpMatchNumber;
    }
    return strRegexpMatch;
}

static std::string generateUpdateSql(const bool isCover, const std::string title, const int32_t ownerAlbumId,
    AccurateRefresh::AssetAccurateRefresh &assetRefresh)
{
    uint32_t index = title.find_first_of("BURST");
    std::string globMember = title.substr(0, index) + "BURST" + generateRegexpMatchForNumber(3);
    std::string globCover = globMember + "_COVER";
    std::string updateSql;
    if (isCover) {
        std::string burstkey = GenerateUuid();
        std::string sqlWhere = " WHERE " + MediaColumn::MEDIA_TYPE +
            " = " + to_string(static_cast<int32_t>(MEDIA_TYPE_IMAGE)) + " AND " + PhotoColumn::PHOTO_SUBTYPE + " != " +
            to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) + " AND " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
            " = " + to_string(ownerAlbumId) + " AND (LOWER(" + MediaColumn::MEDIA_TITLE + ") GLOB LOWER('" +
            globMember + "') OR LOWER(" + MediaColumn::MEDIA_TITLE + ") GLOB LOWER('" + globCover + "'))";
        updateSql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_SUBTYPE + " = " +
            to_string(static_cast<int32_t>(PhotoSubType::BURST)) + ", " + PhotoColumn::PHOTO_BURST_KEY + " = '" +
            burstkey + "', " + PhotoColumn::PHOTO_BURST_COVER_LEVEL + " = CASE WHEN " + MediaColumn::MEDIA_TITLE +
            " NOT LIKE '%COVER%' THEN " + to_string(static_cast<int32_t>(BurstCoverLevelType::MEMBER)) + " ELSE " +
            to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)) + " END" + sqlWhere;
        std::string initSql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE + sqlWhere;
        assetRefresh.Init(initSql, {});
    } else {
        string subWhere = "FROM " + PhotoColumn::PHOTOS_TABLE + " AS p2 WHERE LOWER(p2." + MediaColumn::MEDIA_TITLE +
            ") GLOB LOWER('" + globCover + "') AND p2." + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " +
            to_string(ownerAlbumId);

        updateSql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " AS p1 SET " + PhotoColumn::PHOTO_BURST_KEY +
            " = (SELECT CASE WHEN p2." + PhotoColumn::PHOTO_BURST_KEY + " IS NOT NULL THEN p2." +
            PhotoColumn::PHOTO_BURST_KEY + " ELSE NULL END " + subWhere + " LIMIT 1 ), " +
            PhotoColumn::PHOTO_BURST_COVER_LEVEL + " = (SELECT CASE WHEN COUNT(1) > 0 THEN " +
            to_string(static_cast<int32_t>(BurstCoverLevelType::MEMBER)) + " ELSE " +
            to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)) + " END " + subWhere + "), " +
            PhotoColumn::PHOTO_SUBTYPE + " = (SELECT CASE WHEN COUNT(1) > 0 THEN " +
            to_string(static_cast<int32_t>(PhotoSubType::BURST)) + " ELSE p1." + PhotoColumn::PHOTO_SUBTYPE + " END " +
            subWhere + ") WHERE p1." + MediaColumn::MEDIA_TITLE + " = '" + title + "' AND p1." +
            PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " + to_string(ownerAlbumId);
        std::string initSql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_TITLE +
            " = '" + title + "' AND " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " + to_string(ownerAlbumId);
        assetRefresh.Init(initSql, {});
    }
    return updateSql;
}

static void NotifyAnalysisAlbum(const string& albumId)
{
    if (albumId.empty()) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "Can not get MediaLibraryNotify Instance");
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(
        PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, albumId), NotifyType::NOTIFY_UPDATE);
}

static void UpdateAndNotifyBurstModeAlbum()
{
    int32_t albumId;
    CHECK_AND_RETURN_LOG(
        MediaLibraryRdbUtils::QueryShootingModeAlbumIdByType(ShootingModeAlbumType::BURST_MODE_ALBUM, albumId),
        "Failed to query albumId");

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbstore is nullptr");

    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, { to_string(albumId) });
    NotifyAnalysisAlbum(to_string(albumId));
}

static int32_t UpdateBurstPhoto(const bool isCover, shared_ptr<NativeRdb::ResultSet> resultSet)
{
    int32_t count;
    int32_t retCount = resultSet->GetRowCount(count);
    if (count == 0) {
        if (isCover) {
            MEDIA_INFO_LOG("No burst cover need to update");
        } else {
            MEDIA_INFO_LOG("No burst member need to update");
        }
        return E_SUCCESS;
    }
    if (retCount != E_SUCCESS || count < 0) {
        return E_ERR;
    }

    int32_t ret = E_ERR;
    AccurateRefresh::AssetAccurateRefresh assetRefresh;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int columnIndex = 0;
        string title;
        if (resultSet->GetColumnIndex(MediaColumn::MEDIA_TITLE, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetString(columnIndex, title);
        }
        int32_t ownerAlbumId = 0;
        if (resultSet->GetColumnIndex(PhotoColumn::PHOTO_OWNER_ALBUM_ID, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetInt(columnIndex, ownerAlbumId);
        }

        string updateSql = generateUpdateSql(isCover, title, ownerAlbumId, assetRefresh);
        ret = assetRefresh.ExecuteSql(updateSql, AccurateRefresh::RDB_OPERATION_UPDATE);
        if (ret != AccurateRefresh::ACCURATE_REFRESH_RET_OK) {
            MEDIA_ERR_LOG("assetRefresh ExecuteSql failed, ret = %{public}d", ret);
            ret = E_HAS_DB_ERROR;
            break;
        }
    }
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
    UpdateAndNotifyBurstModeAlbum();
    return ret;
}

static shared_ptr<NativeRdb::ResultSet> QueryBurst(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const string globNameRule1, const string globNameRule2)
{
    string querySql = "SELECT " + MediaColumn::MEDIA_TITLE + ", " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_TYPE + " = " +
        to_string(static_cast<int32_t>(MEDIA_TYPE_IMAGE)) + " AND " + PhotoColumn::PHOTO_SUBTYPE + " != " +
        to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) + " AND " + PhotoColumn::PHOTO_BURST_KEY +
        " IS NULL AND (LOWER(" + MediaColumn::MEDIA_TITLE + ") GLOB LOWER('" + globNameRule1 + "') OR LOWER(" +
        MediaColumn::MEDIA_TITLE + ") GLOB LOWER('" + globNameRule2 + "'))";

    auto resultSet = rdbStore->QueryByStep(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("failed to acquire result from visitor query.");
    }
    return resultSet;
}

int32_t DoUpdateBurstFromGalleryProcessor::UpdateBurstFromGallery()
{
    MEDIA_INFO_LOG("Begin UpdateBurstFromGallery");
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::UpdateBurstFromGallery");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is null.");

    string globNameRule = "IMG_" + generateRegexpMatchForNumber(8) + "_" + generateRegexpMatchForNumber(6) + "_";

    // regexp match IMG_xxxxxxxx_xxxxxx_BURSTxxx, 'x' represents a number
    string globMemberStr1 = globNameRule + "BURST" + generateRegexpMatchForNumber(3);
    string globMemberStr2 = globNameRule + "[0-9]_BURST" + generateRegexpMatchForNumber(3);
    // regexp match IMG_xxxxxxxx_xxxxxx_BURSTxxx_COVER, 'x' represents a number
    string globCoverStr1 = globMemberStr1 + "_COVER";
    string globCoverStr2 = globMemberStr2 + "_COVER";

    auto resultSet = QueryBurst(rdbStore, globCoverStr1, globCoverStr2);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "rdbStore is null.");
    int32_t ret = UpdateBurstPhoto(true, resultSet);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("failed to UpdateBurstPhotoByCovers.");
        return E_FAIL;
    }

    resultSet = QueryBurst(rdbStore, globMemberStr1, globMemberStr2);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "rdbStore is null.");
    ret = UpdateBurstPhoto(false, resultSet);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("failed to UpdateBurstPhotoByMembers.");
        return E_FAIL;
    }
    MEDIA_INFO_LOG("End UpdateBurstFromGallery");
    return ret;
}

static int32_t DoUpdateBurstCoverLevelOperation(AccurateRefresh::AssetAccurateRefresh &assetRefresh,
    const std::vector<std::string> &fileIdVec)
{
    AbsRdbPredicates updatePredicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    updatePredicates.In(MediaColumn::MEDIA_ID, fileIdVec);
    updatePredicates.BeginWrap();
    updatePredicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, WRONG_VALUE);
    updatePredicates.Or();
    updatePredicates.IsNull(PhotoColumn::PHOTO_BURST_COVER_LEVEL);
    updatePredicates.EndWrap();
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, static_cast<int32_t>(BurstCoverLevelType::COVER));

    int32_t changedRows = -1;
    int32_t ret = assetRefresh.Update(changedRows, values, updatePredicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changedRows > 0), E_FAIL,
        "Failed to UpdateBurstCoverLevelFromGallery, ret: %{public}d, updateRows: %{public}d", ret, changedRows);
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery success, changedRows: %{public}d, fileIdVec.size(): %{public}d.",
        changedRows, static_cast<int32_t>(fileIdVec.size()));
    return ret;
}

int32_t DoUpdateBurstFromGalleryProcessor::UpdateBurstCoverLevelFromGallery()
{
    MEDIA_INFO_LOG("Begin DoUpdateBurstCoverLevelFromGallery");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "rdbStore is null.");

    const std::vector<std::string> columns = { MediaColumn::MEDIA_ID };
    AbsRdbPredicates predicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, WRONG_VALUE);
    predicates.Or();
    predicates.IsNull(PhotoColumn::PHOTO_BURST_COVER_LEVEL);
    predicates.EndWrap();
    predicates.Limit(BATCH_QUERY_NUMBER);

    bool nextUpdate = true;
    AccurateRefresh::AssetAccurateRefresh assetRefresh;
    while (nextUpdate && !taskStop_) {
        auto resultSet = rdbStore->Query(predicates, columns);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "Failed to query resultSet");
        int32_t rowCount = 0;
        int32_t ret = resultSet->GetRowCount(rowCount);
        CHECK_AND_RETURN_RET_LOG((ret == E_OK && rowCount >= 0), E_FAIL, "Failed to GetRowCount");
        if (rowCount == 0) {
            MEDIA_INFO_LOG("No need to UpdateBurstCoverLevelFromGallery.");
            return E_OK;
        }
        if (rowCount < BATCH_QUERY_NUMBER) {
            nextUpdate = false;
        }

        std::vector<std::string> fileIdVec;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
            fileIdVec.push_back(fileId);
        }
        resultSet->Close();

        CHECK_AND_CONTINUE_ERR_LOG(DoUpdateBurstCoverLevelOperation(assetRefresh, fileIdVec) == E_OK,
            "Failed to DoUpdateBurstCoverLevelOperation");
    }
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
    return E_OK;
}
} // namespace Media
} // namespace OHOS
