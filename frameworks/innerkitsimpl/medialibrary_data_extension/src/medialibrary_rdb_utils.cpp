/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_rdb_utils.h"

#include <functional>
#include <iomanip>
#include <sstream>
#include <string>

#include "media_log.h"
#include "media_refresh_album_column.h"
#include "medialibrary_business_record_column.h"
#include "medialibrary_db_const.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_tracer.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "result_set.h"
#include "userfile_manager_types.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"

namespace OHOS::Media {
using namespace std;
using namespace NativeRdb;

constexpr int32_t E_HAS_DB_ERROR = -222;
constexpr int32_t E_SUCCESS = 0;
constexpr int32_t E_EMPTY_ALBUM_ID = 1;
constexpr size_t ALBUM_UPDATE_THRESHOLD = 1000;
constexpr int32_t SINGLE_FACE = 1;
constexpr int32_t ALBUM_COVER_SATISFIED = 1;

const std::vector<std::string> ALL_SYS_PHOTO_ALBUM = {
    std::to_string(PhotoAlbumSubType::FAVORITE),
    std::to_string(PhotoAlbumSubType::VIDEO),
    std::to_string(PhotoAlbumSubType::HIDDEN),
    std::to_string(PhotoAlbumSubType::TRASH),
    std::to_string(PhotoAlbumSubType::SCREENSHOT),
    std::to_string(PhotoAlbumSubType::CAMERA),
    std::to_string(PhotoAlbumSubType::IMAGE),
    std::to_string(PhotoAlbumSubType::SOURCE_GENERIC),
};

const std::vector<std::string> ALL_ANALYSIS_ALBUM = {
    std::to_string(PhotoAlbumSubType::CLASSIFY),
    std::to_string(PhotoAlbumSubType::GEOGRAPHY_LOCATION),
    std::to_string(PhotoAlbumSubType::GEOGRAPHY_CITY),
    std::to_string(PhotoAlbumSubType::SHOOTING_MODE),
    std::to_string(PhotoAlbumSubType::PORTRAIT),
};

struct BussinessRecordValue {
    string bussinessType;
    string key;
    string value;
};

enum UpdateAlbumType {
    UPDATE_SYSTEM_ALBUM = 400,
    UPDATE_HIDDEN_ALBUM,
    UPDATE_USER_ALBUM,
    UPDATE_SOURCE_ALBUM,
    UPDATE_ANALYSIS_ALBUM,
};

atomic<bool> MediaLibraryRdbUtils::isNeedRefreshAlbum = false;
atomic<bool> MediaLibraryRdbUtils::isInRefreshTask = false;

const string ANALYSIS_REFRESH_BUSINESS_TYPE = "ANALYSIS_ALBUM_REFRESH";

static inline string GetStringValFromColumn(const shared_ptr<ResultSet> &resultSet, const int index)
{
    string value;
    if (resultSet->GetString(index, value)) {
        return "";
    }
    return value;
}

static inline int32_t GetIntValFromColumn(const shared_ptr<ResultSet> &resultSet, const int index)
{
    int32_t value = 0;
    if (resultSet->GetInt(index, value)) {
        return 0;
    }
    return value;
}

static inline string GetStringValFromColumn(const shared_ptr<ResultSet> &resultSet, const string &columnName)
{
    int32_t index = 0;
    if (resultSet->GetColumnIndex(columnName, index)) {
        return "";
    }

    return GetStringValFromColumn(resultSet, index);
}

static inline int32_t GetIntValFromColumn(const shared_ptr<ResultSet> &resultSet, const string &columnName)
{
    int32_t index = 0;
    if (resultSet->GetColumnIndex(columnName, index)) {
        return 0;
    }

    return GetIntValFromColumn(resultSet, index);
}

static inline shared_ptr<ResultSet> GetUserAlbum(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &userAlbumIds, const vector<string> &columns)
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    if (userAlbumIds.empty()) {
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC));
    } else {
        predicates.In(PhotoAlbumColumns::ALBUM_ID, userAlbumIds);
    }
    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(predicates, columns);
}

static inline shared_ptr<ResultSet> GetAnalysisAlbum(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &analysisAlbumIds, const vector<string> &columns)
{
    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    if (!analysisAlbumIds.empty()) {
        predicates.In(PhotoAlbumColumns::ALBUM_ID, analysisAlbumIds);
    }
    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(predicates, columns);
}

static inline shared_ptr<ResultSet> GetSourceAlbum(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &sourceAlbumIds, const vector<string> &columns)
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    if (!sourceAlbumIds.empty()) {
        predicates.In(PhotoAlbumColumns::ALBUM_ID, sourceAlbumIds);
    } else {
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::SOURCE_GENERIC));
    }
    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(predicates, columns);
}

static inline shared_ptr<ResultSet> GetAnalysisAlbumBySubtype(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &subtypes, const vector<string> &columns)
{
    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    if (!subtypes.empty()) {
        predicates.In(ALBUM_SUBTYPE, subtypes);
    } else {
        predicates.In(ALBUM_SUBTYPE, ALL_ANALYSIS_ALBUM);
    }

    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(predicates, columns);
}

static string GetQueryFilter(const string &tableName)
{
    if (tableName == MEDIALIBRARY_TABLE) {
        return MEDIALIBRARY_TABLE + "." + MEDIA_DATA_DB_SYNC_STATUS + " = " +
            to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE));
    }
    if (tableName == PhotoColumn::PHOTOS_TABLE) {
        return PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_SYNC_STATUS + " = " +
            to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)) + " AND " +
            PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_CLEAN_FLAG + " = " +
            to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    }
    if (tableName == PhotoAlbumColumns::TABLE) {
        return PhotoAlbumColumns::TABLE + "." + PhotoAlbumColumns::ALBUM_DIRTY + " != " +
            to_string(static_cast<int32_t>(DirtyTypes::TYPE_DELETED));
    }
    if (tableName == PhotoMap::TABLE) {
        return PhotoMap::TABLE + "." + PhotoMap::DIRTY + " != " + to_string(static_cast<int32_t>(
            DirtyTypes::TYPE_DELETED));
    }
    return "";
}

void MediaLibraryRdbUtils::AddQueryFilter(AbsRdbPredicates &predicates)
{
    /* build all-table vector */
    string tableName = predicates.GetTableName();
    vector<string> joinTables = predicates.GetJoinTableNames();
    joinTables.push_back(tableName);
    /* add filters */
    string filters;
    for (auto &t : joinTables) {
        string filter = GetQueryFilter(t);
        if (filter.empty()) {
            continue;
        }
        if (filters.empty()) {
            filters += filter;
        } else {
            filters += " AND " + filter;
        }
    }
    if (filters.empty()) {
        return;
    }

    /* rebuild */
    string queryCondition = predicates.GetWhereClause();
    queryCondition = queryCondition.empty() ? filters : filters + " AND " + queryCondition;
    predicates.SetWhereClause(queryCondition);
}

static shared_ptr<AbsSharedResultSet> Query(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const AbsRdbPredicates &predicates, const vector<string> &columns)
{
    MediaLibraryRdbUtils::AddQueryFilter(const_cast<AbsRdbPredicates &>(predicates));
    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(predicates, columns);
}

static shared_ptr<ResultSet> QueryGoToFirst(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const RdbPredicates &predicates, const vector<string> &columns)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryGoToFirst");
    auto resultSet = Query(rdbStore, predicates, columns);
    if (resultSet == nullptr) {
        return nullptr;
    }

    MediaLibraryTracer goToFirst;
    goToFirst.Start("GoToFirstRow");
    resultSet->GoToFirstRow();
    return resultSet;
}

static int32_t ForEachRow(const shared_ptr<RdbStore> &rdbStore, const shared_ptr<ResultSet> &resultSet,
    const bool hiddenState, unordered_map<int32_t, int32_t> &updateResult, const function<int32_t(
        const shared_ptr<RdbStore> &rdbStore, const shared_ptr<ResultSet> &albumResult, const bool hiddenState,
            unordered_map<int32_t, int32_t> &updateResult)> &func)
{
    TransactionOperations transactionOprn(rdbStore);
    int32_t err = transactionOprn.Start();
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to begin transaction, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    while (resultSet->GoToNextRow() == E_OK) {
        // Ignore failure here, try to iterate rows as much as possible.
        func(rdbStore, resultSet, hiddenState, updateResult);
    }
    transactionOprn.Finish();
    return E_SUCCESS;
}

static inline int32_t GetFileCount(const shared_ptr<ResultSet> &resultSet)
{
    return GetIntValFromColumn(resultSet, MEDIA_COLUMN_COUNT_1);
}

static inline int32_t GetPortraitFileCount(const shared_ptr<ResultSet> &resultSet)
{
    return GetIntValFromColumn(resultSet, MEDIA_COLUMN_COUNT_DISTINCT_FILE_ID);
}

static inline int32_t GetAlbumCount(const shared_ptr<ResultSet> &resultSet, const string &column)
{
    return GetIntValFromColumn(resultSet, column);
}

static inline string GetAlbumCover(const shared_ptr<ResultSet> &resultSet, const string &column)
{
    return GetStringValFromColumn(resultSet, column);
}

static inline int32_t GetAlbumId(const shared_ptr<ResultSet> &resultSet)
{
    return GetIntValFromColumn(resultSet, PhotoAlbumColumns::ALBUM_ID);
}

static inline int32_t GetAlbumSubType(const shared_ptr<ResultSet> &resultSet)
{
    return GetIntValFromColumn(resultSet, PhotoAlbumColumns::ALBUM_SUBTYPE);
}

static inline int32_t GetIsCoverSatisfied(const shared_ptr<ResultSet> &resultSet)
{
    return GetIntValFromColumn(resultSet, IS_COVER_SATISFIED);
}

static string GetFileName(const string &filePath)
{
    string fileName;

    size_t lastSlash = filePath.rfind('/');
    if (lastSlash == string::npos) {
        return fileName;
    }
    if (filePath.size() > (lastSlash + 1)) {
        fileName = filePath.substr(lastSlash + 1);
    }
    return fileName;
}

static string GetTitleFromDisplayName(const string &displayName)
{
    auto pos = displayName.find_last_of('.');
    if (pos == string::npos) {
        return "";
    }
    return displayName.substr(0, pos);
}

static string Encode(const string &uri)
{
    const unordered_set<char> uriCompentsSet = {
        ';', ',', '/', '?', ':', '@', '&',
        '=', '+', '$', '-', '_', '.', '!',
        '~', '*', '(', ')', '#', '\''
    };
    constexpr int32_t encodeLen = 2;
    ostringstream outPutStream;
    outPutStream.fill('0');
    outPutStream << std::hex;

    for (unsigned char tmpChar : uri) {
        if (std::isalnum(tmpChar) || uriCompentsSet.find(tmpChar) != uriCompentsSet.end()) {
            outPutStream << tmpChar;
        } else {
            outPutStream << std::uppercase;
            outPutStream << '%' << std::setw(encodeLen) << static_cast<unsigned int>(tmpChar);
            outPutStream << std::nouppercase;
        }
    }

    return outPutStream.str();
}

static string GetExtraUri(const string &displayName, const string &path)
{
    string extraUri = "/" + GetTitleFromDisplayName(GetFileName(path)) + "/" + displayName;
    return Encode(extraUri);
}

static string GetUriByExtrConditions(const string &prefix, const string &fileId, const string &suffix)
{
    return prefix + fileId + suffix;
}

static inline string GetCover(const shared_ptr<ResultSet> &resultSet)
{
    string coverUri;
    int32_t fileId = GetIntValFromColumn(resultSet, PhotoColumn::MEDIA_ID);
    if (fileId <= 0) {
        return coverUri;
    }

    string extrUri = GetExtraUri(GetStringValFromColumn(resultSet, PhotoColumn::MEDIA_NAME),
        GetStringValFromColumn(resultSet, PhotoColumn::MEDIA_FILE_PATH));
    return GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileId), extrUri);
}

static int32_t SetCount(const shared_ptr<ResultSet> &fileResult, const shared_ptr<ResultSet> &albumResult,
    ValuesBucket &values, const bool hiddenState, PhotoAlbumSubType subtype)
{
    const string &targetColumn = hiddenState ? PhotoAlbumColumns::HIDDEN_COUNT : PhotoAlbumColumns::ALBUM_COUNT;
    int32_t oldCount = GetAlbumCount(albumResult, targetColumn);
    int32_t newCount;
    if (subtype == PORTRAIT) {
        newCount = GetPortraitFileCount(fileResult);
    } else {
        newCount = GetFileCount(fileResult);
    }
    if (oldCount != newCount) {
        MEDIA_INFO_LOG("Update album %{public}s, oldCount: %{public}d, newCount: %{public}d",
            targetColumn.c_str(), oldCount, newCount);
        values.PutInt(targetColumn, newCount);
        if (hiddenState) {
            MEDIA_INFO_LOG("Update album contains hidden: %{public}d", newCount != 0);
            values.PutInt(PhotoAlbumColumns::CONTAINS_HIDDEN, newCount != 0);
        }
    }
    return newCount;
}

static void SetPortraitCover(const shared_ptr<ResultSet> &fileResult, const shared_ptr<ResultSet> &albumResult,
    ValuesBucket &values, int newCount)
{
    string newCover;
    if (newCount != 0) {
        newCover = GetCover(fileResult);
    }
    const string &targetColumn = PhotoAlbumColumns::ALBUM_COVER_URI;
    string oldCover = GetAlbumCover(albumResult, targetColumn);
    if (oldCover != newCover) {
        int totalFaces = GetIntValFromColumn(fileResult, TOTAL_FACES);
        int isCoverSatisfied = totalFaces == SINGLE_FACE ? ALBUM_COVER_SATISFIED : 0;
        values.PutInt(IS_COVER_SATISFIED, isCoverSatisfied);
        values.PutString(targetColumn, newCover);
        MEDIA_INFO_LOG("Update album %{public}s. oldCover: %{private}s, newCover: %{private}s, satisfied: %{public}d",
            targetColumn.c_str(), oldCover.c_str(), newCover.c_str(), isCoverSatisfied);
    }
}

static void SetCover(const shared_ptr<ResultSet> &fileResult, const shared_ptr<ResultSet> &albumResult,
    ValuesBucket &values, const bool hiddenState, PhotoAlbumSubType subtype)
{
    string newCover;
    int32_t newCount = GetFileCount(fileResult);
    if (newCount != 0) {
        newCover = GetCover(fileResult);
    }
    const string &targetColumn = hiddenState ? PhotoAlbumColumns::HIDDEN_COVER : PhotoAlbumColumns::ALBUM_COVER_URI;
    string oldCover = GetAlbumCover(albumResult, targetColumn);
    if (oldCover != newCover) {
        MEDIA_INFO_LOG("Update album %{public}s. oldCover: %{private}s, newCover: %{private}s",
            targetColumn.c_str(), oldCover.c_str(), newCover.c_str());
        values.PutString(targetColumn, newCover);
    }
}

static void GetAlbumPredicates(PhotoAlbumSubType subtype, const shared_ptr<ResultSet> &albumResult,
    NativeRdb::RdbPredicates &predicates, const bool hiddenState)
{
    if (!subtype) {
        PhotoAlbumColumns::GetUserAlbumPredicates(GetAlbumId(albumResult), predicates, hiddenState);
    } else if (subtype == PhotoAlbumSubType::PORTRAIT) {
        PhotoAlbumColumns::GetPortraitAlbumPredicates(GetAlbumId(albumResult), predicates, hiddenState);
    } else if (subtype >= PhotoAlbumSubType::ANALYSIS_START && subtype <= PhotoAlbumSubType::ANALYSIS_END) {
        PhotoAlbumColumns::GetAnalysisAlbumPredicates(GetAlbumId(albumResult), predicates, hiddenState);
    } else if (subtype == PhotoAlbumSubType::SOURCE_GENERIC) {
        PhotoAlbumColumns::GetSourceAlbumPredicates(GetAlbumId(albumResult), predicates, hiddenState);
    } else {
        PhotoAlbumColumns::GetSystemAlbumPredicates(subtype, predicates, hiddenState);
    }
}

static void SetImageVideoCount(int32_t newTotalCount,
    const shared_ptr<ResultSet> &fileResultVideo, const shared_ptr<ResultSet> &albumResult,
    ValuesBucket &values)
{
    int32_t oldVideoCount = GetAlbumCount(albumResult, PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
    int32_t newVideoCount = GetFileCount(fileResultVideo);
    if (oldVideoCount != newVideoCount) {
        MEDIA_INFO_LOG("Update album %{public}s, oldCount: %{public}d, newCount: %{public}d",
            PhotoAlbumColumns::ALBUM_VIDEO_COUNT.c_str(), oldVideoCount, newVideoCount);
        values.PutInt(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, newVideoCount);
    }
    int32_t oldImageCount = GetAlbumCount(albumResult, PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
    int32_t newImageCount = newTotalCount - newVideoCount;
    if (oldImageCount != newImageCount) {
        MEDIA_INFO_LOG("Update album %{public}s, oldCount: %{public}d, newCount: %{public}d",
            PhotoAlbumColumns::ALBUM_IMAGE_COUNT.c_str(), oldImageCount, newImageCount);
        values.PutInt(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, newImageCount);
    }
}

static int32_t QueryAlbumCount(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype)
{
    const vector<string> columns = { MEDIA_COLUMN_COUNT_1 };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    if (subtype == PhotoAlbumSubType::USER_GENERIC) {
        GetAlbumPredicates(static_cast<PhotoAlbumSubType>(0), albumResult, predicates, false);
    } else {
        GetAlbumPredicates(subtype, albumResult, predicates, false);
    }
    auto fetchResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fetchResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return GetFileCount(fetchResult);
}

static int32_t QueryAlbumVideoCount(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype)
{
    const vector<string> columns = { MEDIA_COLUMN_COUNT_1 };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    if (subtype == PhotoAlbumSubType::USER_GENERIC) {
        GetAlbumPredicates(static_cast<PhotoAlbumSubType>(0), albumResult, predicates, false);
    } else {
        GetAlbumPredicates(subtype, albumResult, predicates, false);
    }
    predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_MEDIA_TYPE_INDEX);
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO));
    auto fetchResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fetchResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return GetFileCount(fetchResult);
}

static int32_t QueryAlbumHiddenCount(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype)
{
    const vector<string> columns = { MEDIA_COLUMN_COUNT_1 };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    if (subtype == PhotoAlbumSubType::USER_GENERIC) {
        GetAlbumPredicates(static_cast<PhotoAlbumSubType>(0), albumResult, predicates, true);
    } else {
        GetAlbumPredicates(subtype, albumResult, predicates, true);
    }
    auto fetchResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fetchResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return GetFileCount(fetchResult);
}

static int32_t SetAlbumCounts(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype, AlbumCounts &albumCounts)
{
    int ret = QueryAlbumCount(rdbStore, albumResult, subtype);
    if (ret < E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to QueryAlbumCount, ret:%{public}d", ret);
        return ret;
    }
    albumCounts.count = ret;

    ret = QueryAlbumVideoCount(rdbStore, albumResult, subtype);
    if (ret < E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to QueryAlbumVideoCount, ret:%{public}d", ret);
        return ret;
    }
    albumCounts.videoCount = ret;
    albumCounts.imageCount = albumCounts.count - albumCounts.videoCount;

    ret = QueryAlbumHiddenCount(rdbStore, albumResult, subtype);
    if (ret < E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to QueryAlbumCount, ret:%{public}d", ret);
        return ret;
    }
    albumCounts.hiddenCount = ret;
    return E_SUCCESS;
}

static int32_t SetAlbumCoverUri(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype, string &uri)
{
    const vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_NAME
    };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    if (subtype == PhotoAlbumSubType::HIDDEN) {
        GetAlbumPredicates(subtype, albumResult, predicates, true);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_HIDDEN_TIME_INDEX);
    } else if (subtype == PhotoAlbumSubType::USER_GENERIC) {
        GetAlbumPredicates(static_cast<PhotoAlbumSubType>(0), albumResult, predicates, false);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_ADDED_INDEX);
    } else {
        GetAlbumPredicates(subtype, albumResult, predicates, false);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_ADDED_INDEX);
    }
    predicates.Limit(1);

    auto fetchResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fetchResult == nullptr) {
        MEDIA_ERR_LOG("QueryGoToFirst failed");
        return E_HAS_DB_ERROR;
    }
    uri = GetCover(fetchResult);
    return E_SUCCESS;
}

static int32_t SetAlbumCoverHiddenUri(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype, string &uri)
{
    const vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_NAME
    };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    if (subtype == PhotoAlbumSubType::USER_GENERIC) {
        GetAlbumPredicates(static_cast<PhotoAlbumSubType>(0), albumResult, predicates, true);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_HIDDEN_TIME_INDEX);
    } else {
        GetAlbumPredicates(subtype, albumResult, predicates, true);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_HIDDEN_TIME_INDEX);
    }
    predicates.Limit(1);
    auto fetchResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fetchResult == nullptr) {
        MEDIA_ERR_LOG("QueryGoToFirst failed");
        return E_HAS_DB_ERROR;
    }
    uri = GetCover(fetchResult);
    return E_SUCCESS;
}

static int32_t FillOneAlbumCountAndCoverUri(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, PhotoAlbumSubType subtype, string &sql)
{
    AlbumCounts albumCounts = { 0, 0, 0, 0 };
    int32_t ret = SetAlbumCounts(rdbStore, albumResult, subtype, albumCounts);
    if (ret != E_SUCCESS) {
        return ret;
    }
    string coverUri;
    ret = SetAlbumCoverUri(rdbStore, albumResult, subtype, coverUri);
    if (ret != E_SUCCESS) {
        return ret;
    }
    string coverHiddenUri;
    if (albumCounts.hiddenCount != 0) {
        ret = SetAlbumCoverHiddenUri(rdbStore, albumResult, subtype, coverHiddenUri);
        if (ret != E_SUCCESS) {
            return ret;
        }
    }

    int32_t albumId = GetAlbumId(albumResult);
    if (albumId < 0) {
        MEDIA_ERR_LOG("Can not get correct albumId, error albumId is %{public}d", albumId);
        return E_HAS_DB_ERROR;
    }
    string coverUriSql = PhotoAlbumColumns::ALBUM_COVER_URI;
    if (coverUri.empty()) {
        coverUriSql += " = NULL";
    } else {
        coverUriSql += " = '" + coverUri + "'";
    }
    string coverHiddenUriSql = PhotoAlbumColumns::HIDDEN_COVER;
    if (coverHiddenUri.empty()) {
        coverHiddenUriSql += " = NULL";
    } else {
        coverHiddenUriSql += " = '" + coverHiddenUri + "'";
    }

    sql = "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_COUNT + " = " + to_string(albumCounts.count) + ", " +
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT + " = " +  to_string(albumCounts.imageCount) + ", " +
        PhotoAlbumColumns::ALBUM_VIDEO_COUNT + " = " + to_string(albumCounts.videoCount) + ", " +
        PhotoAlbumColumns::HIDDEN_COUNT + " = " + to_string(albumCounts.hiddenCount) + ", " +
        PhotoAlbumColumns::CONTAINS_HIDDEN + " = " + to_string((albumCounts.hiddenCount == 0) ? 0 : 1) + ", " +
        coverUriSql + ", " + coverHiddenUriSql + " WHERE " +
        PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumId) + ";";
    return E_SUCCESS;
}

static std::string GetPhotoId(const std::string &uri)
{
    if (uri.compare(0, PhotoColumn::PHOTO_URI_PREFIX.size(),
        PhotoColumn::PHOTO_URI_PREFIX) != 0) {
        return "";
    }
    std::string tmp = uri.substr(PhotoColumn::PHOTO_URI_PREFIX.size());
    return tmp.substr(0, tmp.find_first_of('/'));
}

static int32_t RefreshAlbums(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult,
    function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler)
{
    while (albumResult->GoToNextRow() == NativeRdb::E_OK) {
        auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
        int32_t albumId = GetAlbumId(albumResult);
        string sql;
        int32_t ret = FillOneAlbumCountAndCoverUri(rdbStore, albumResult, subtype, sql);
        if (ret != E_SUCCESS) {
            return ret;
        }

        ret = rdbStore->ExecuteSql(sql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to execute sql:%{private}s", sql.c_str());
            return E_HAS_DB_ERROR;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", sql.c_str());
        refreshProcessHandler(PhotoAlbumType::SYSTEM, subtype, albumId);
    }

    string updateRefreshTableSql = "DELETE FROM " + ALBUM_REFRESH_TABLE;
    int32_t ret = rdbStore->ExecuteSql(updateRefreshTableSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to execute sql:%{private}s", updateRefreshTableSql.c_str());
        return E_HAS_DB_ERROR;
    }
    MEDIA_DEBUG_LOG("Delete AlbumRefreshTable success");
    return E_SUCCESS;
}

static int32_t GetAllRefreshAlbumIds(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    vector<string> &albumIds)
{
    RdbPredicates predicates(ALBUM_REFRESH_TABLE);
    vector<string> columns = { REFRESHED_ALBUM_ID };
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not query ALBUM_REFRESH_TABLE");
        return E_HAS_DB_ERROR;
    }

    int32_t count = 0;
    int32_t ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount failed ret:%{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    if (count == 0) {
        MEDIA_DEBUG_LOG("count is zero, break");
        return E_SUCCESS;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex = 0;
        ret = resultSet->GetColumnIndex(REFRESHED_ALBUM_ID, columnIndex);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("GetColumnIndex failed ret:%{public}d", ret);
            return E_HAS_DB_ERROR;
        }
        int32_t refreshAlbumId = 0;
        ret = resultSet->GetInt(columnIndex, refreshAlbumId);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("GetInt failed ret:%{public}d", ret);
            return E_HAS_DB_ERROR;
        }
        albumIds.push_back(to_string(refreshAlbumId));
    }
    return E_SUCCESS;
}

shared_ptr<AbsSharedResultSet> QueryAlbumById(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &albumIds)
{
    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE
    };
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_ID, albumIds);
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not Query from rdb");
        return nullptr;
    }
    return resultSet;
}

int32_t MediaLibraryRdbUtils::IsNeedRefreshByCheckTable(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    bool &signal)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb is nullptr");
        return E_HAS_DB_ERROR;
    }

    RdbPredicates predicates(ALBUM_REFRESH_TABLE);
    vector<string> columns = { REFRESHED_ALBUM_ID };
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not query ALBUM_REFRESH_TABLE");
        return E_HAS_DB_ERROR;
    }

    int32_t count = 0;
    int32_t ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount failed ret:%{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    if (count == 0) {
        MEDIA_DEBUG_LOG("count is zero, should not refresh");
        signal = false;
    } else {
        MEDIA_DEBUG_LOG("count is %{public}d, should refresh", count);
        signal = true;
    }
    return E_SUCCESS;
}

bool MediaLibraryRdbUtils::IsNeedRefreshAlbum()
{
    return isNeedRefreshAlbum.load();
}

void MediaLibraryRdbUtils::SetNeedRefreshAlbum(bool isNeedRefresh)
{
    isNeedRefreshAlbum = isNeedRefresh;
}

bool MediaLibraryRdbUtils::IsInRefreshTask()
{
    return isInRefreshTask.load();
}

static void GetPortraitAlbumCoverPredicates(const string &coverId, RdbPredicates &predicates)
{
    string imageFaceFileId = VISION_IMAGE_FACE_TABLE + "." + MediaColumn::MEDIA_ID;
    string imageFaceTotalFaces = VISION_IMAGE_FACE_TABLE + "." + TOTAL_FACES;
    string photosDateAdded = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_DATE_ADDED;
    string photosFileId = PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::MEDIA_ID;

    string clause = imageFaceFileId + " = " + photosFileId;
    predicates.InnerJoin(VISION_IMAGE_FACE_TABLE)->On({ clause });
    string order = "CASE WHEN " + photosFileId + " = " + coverId + " THEN 0 " +
        "WHEN " + imageFaceTotalFaces + " = " + to_string(SINGLE_FACE) + " THEN 1 ELSE 2 END ";
    predicates.OrderByAsc(order);
    predicates.OrderByDesc(photosDateAdded);
}

static void GetPortraitAlbumCountPredicates(const string &albumId, RdbPredicates &predicates)
{
    string anaAlbumGroupTag = ANALYSIS_ALBUM_TABLE + "." + GROUP_TAG;
    string anaAlbumId = ANALYSIS_ALBUM_TABLE + "." + ALBUM_ID;
    string anaPhotoMapAlbum = ANALYSIS_PHOTO_MAP_TABLE + "." + MAP_ALBUM;
    string anaPhotoMapAsset = ANALYSIS_PHOTO_MAP_TABLE + "." + MAP_ASSET;
    string photosDateTrashed = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_DATE_TRASHED;
    string photosFileId = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID;
    string photosHidden = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_HIDDEN;
    string photosTimePending = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_TIME_PENDING;

    string clause = anaPhotoMapAsset + " = " + photosFileId;
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ clause });
    clause = anaAlbumId + " = " + anaPhotoMapAlbum;
    predicates.InnerJoin(ANALYSIS_ALBUM_TABLE)->On({ clause });

    clause = "( " + anaAlbumGroupTag + " IN ( SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = " + albumId + " ))";
    predicates.SetWhereClause(clause + " AND ");
    predicates.BeginWrap();
    predicates.EqualTo(photosDateTrashed, to_string(0));
    predicates.EqualTo(photosHidden, to_string(0));
    predicates.EqualTo(photosTimePending, to_string(0));
    predicates.EndWrap();
    predicates.Distinct();
}

static int32_t SetPortraitUpdateValues(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, const vector<string> &fileIds, ValuesBucket &values)
{
    const vector<string> countColumns = {
        MEDIA_COLUMN_COUNT_DISTINCT_FILE_ID
    };

    const vector<string> coverColumns = {
        PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::MEDIA_ID,
        PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::MEDIA_NAME,
        VISION_IMAGE_FACE_TABLE + "." + TOTAL_FACES
    };

    string coverUri = GetAlbumCover(albumResult, PhotoAlbumColumns::ALBUM_COVER_URI);
    string coverId = GetPhotoId(coverUri);
    int isCoverSatisfied = GetIsCoverSatisfied(albumResult);

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    string albumId = to_string(GetAlbumId(albumResult));
    GetPortraitAlbumCountPredicates(albumId, predicates);
    shared_ptr<ResultSet> countResult = QueryGoToFirst(rdbStore, predicates, countColumns);
    if (countResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t newCount = SetCount(countResult, albumResult, values, false, PhotoAlbumSubType::PORTRAIT);
    if (std::find(fileIds.begin(), fileIds.end(), coverId) == fileIds.end() &&
        isCoverSatisfied == ALBUM_COVER_SATISFIED) {
        return E_SUCCESS;
    }
    GetPortraitAlbumCoverPredicates(coverId, predicates);
    shared_ptr<ResultSet> coverResult = QueryGoToFirst(rdbStore, predicates, coverColumns);
    if (coverResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    SetPortraitCover(coverResult, albumResult, values, newCount);
    return E_SUCCESS;
}

static int32_t SetUpdateValues(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, ValuesBucket &values, PhotoAlbumSubType subtype, const bool hiddenState)
{
    const vector<string> columns = {
        MEDIA_COLUMN_COUNT_1,
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_NAME
    };

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    GetAlbumPredicates(subtype, albumResult, predicates, hiddenState);
    if (subtype == PhotoAlbumSubType::HIDDEN || hiddenState) {
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_HIDDEN_TIME_INDEX);
    } else if (subtype == PhotoAlbumSubType::VIDEO || subtype == PhotoAlbumSubType::IMAGE) {
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_MEDIA_TYPE_INDEX);
    } else if (subtype == PhotoAlbumSubType::FAVORITE) {
        predicates.IndexedBy(PhotoColumn::PHOTO_FAVORITE_INDEX);
    } else {
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_ADDED_INDEX);
    }
    auto fileResult = QueryGoToFirst(rdbStore, predicates, columns);
    if (fileResult == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t newCount = SetCount(fileResult, albumResult, values, hiddenState, subtype);
    SetCover(fileResult, albumResult, values, hiddenState, subtype);
    if (hiddenState == 0 && (subtype < PhotoAlbumSubType::ANALYSIS_START ||
        subtype > PhotoAlbumSubType::ANALYSIS_END)) {
        predicates.Clear();
        GetAlbumPredicates(subtype, albumResult, predicates, hiddenState);
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_MEDIA_TYPE_INDEX);
        predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO));
        auto fileResultVideo = QueryGoToFirst(rdbStore, predicates, columns);
        if (fileResultVideo == nullptr) {
            return E_HAS_DB_ERROR;
        }
        SetImageVideoCount(newCount, fileResultVideo, albumResult, values);
    }
    return E_SUCCESS;
}

static void QueryAlbumId(const shared_ptr<RdbStore> &rdbStore, const RdbPredicates predicates,
    vector<string> &albumId)
{
    const vector<string> columns = {
        "Distinct " + PhotoMap::ALBUM_ID
    };
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_WARN_LOG("Failed to Query");
        return;
    }
    while (resultSet->GoToNextRow() == E_OK) {
        albumId.push_back(to_string(GetIntValFromColumn(resultSet, 0)));
    }
}

static int32_t UpdateUserAlbumIfNeeded(const shared_ptr<RdbStore> &rdbStore, const shared_ptr<ResultSet> &albumResult,
    const bool hiddenState, unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateUserAlbumIfNeeded");
    ValuesBucket values;
    int err = SetUpdateValues(rdbStore, albumResult, values, static_cast<PhotoAlbumSubType>(0), hiddenState);
    if (err < 0) {
        return err;
    }
    if (values.IsEmpty()) {
        return E_SUCCESS;
    }

    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(GetAlbumId(albumResult)));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC));
    int32_t changedRows = 0;
    err = rdbStore->Update(changedRows, values, predicates);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to update album count and cover! err: %{public}d", err);
    }
    if (hiddenState) {
        updateResult[UpdateAlbumType::UPDATE_HIDDEN_ALBUM] += changedRows;
    } else {
        updateResult[UpdateAlbumType::UPDATE_USER_ALBUM] += changedRows;
    }
    return E_SUCCESS;
}

static int32_t UpdatePortraitAlbumIfNeeded(const shared_ptr<RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, const vector<string> &fileIds,
    unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdatePortraitAlbumIfNeeded");
    auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
    if (subtype != PhotoAlbumSubType::PORTRAIT) {
        return E_SUCCESS;
    }

    ValuesBucket values;
    int err = SetPortraitUpdateValues(rdbStore, albumResult, fileIds, values);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to set portrait update value! err: %{public}d", err);
        return err;
    }
    if (values.IsEmpty()) {
        return E_SUCCESS;
    }

    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(GetAlbumId(albumResult)));
    int32_t changedRows = 0;
    err = rdbStore->Update(changedRows, values, predicates);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to update album count and cover! err: %{public}d", err);
        return err;
    }
    updateResult[UpdateAlbumType::UPDATE_ANALYSIS_ALBUM] += changedRows;
    return E_SUCCESS;
}

static int32_t UpdateAnalysisAlbumIfNeeded(const shared_ptr<RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, const bool hiddenState, unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAnalysisAlbumIfNeeded");
    ValuesBucket values;
    auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
    int err = SetUpdateValues(rdbStore, albumResult, values, subtype, hiddenState);
    if (err < 0) {
        return err;
    }
    if (values.IsEmpty()) {
        return E_SUCCESS;
    }

    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(GetAlbumId(albumResult)));
    int32_t changedRows = 0;
    err = rdbStore->Update(changedRows, values, predicates);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to update album count and cover! err: %{public}d", err);
        return err;
    }
    if (hiddenState) {
        updateResult[UpdateAlbumType::UPDATE_HIDDEN_ALBUM] += changedRows;
    } else {
        updateResult[UpdateAlbumType::UPDATE_ANALYSIS_ALBUM] += changedRows;
    }
    return E_SUCCESS;
}

static int32_t UpdateSourceAlbumIfNeeded(const shared_ptr<RdbStore> &rdbStore, const shared_ptr<ResultSet> &albumResult,
    const bool hiddenState, std::unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSourceAlbumIfNeeded");
    ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_IS_LOCAL, 1); // local album is 1.
    auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
    int err = SetUpdateValues(rdbStore, albumResult, values, subtype, hiddenState);
    if (err < 0) {
        return err;
    }
    if (values.IsEmpty()) {
        return E_SUCCESS;
    }

    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(GetAlbumId(albumResult)));
    int32_t changedRows = 0;
    err = rdbStore->Update(changedRows, values, predicates);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to update album count and cover! err: %{public}d", err);
        return err;
    }
    if (hiddenState) {
        updateResult[UpdateAlbumType::UPDATE_HIDDEN_ALBUM] += changedRows;
    } else {
        updateResult[UpdateAlbumType::UPDATE_SOURCE_ALBUM] += changedRows;
    }
    return E_SUCCESS;
}

static int32_t UpdateSysAlbumIfNeeded(const shared_ptr<RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult, const bool hiddenState, unordered_map<int32_t, int32_t> &updateResult)
{
    ValuesBucket values;
    auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSysAlbum: " + to_string(subtype));
    int err = SetUpdateValues(rdbStore, albumResult, values, subtype, hiddenState);
    if (err < 0) {
        return err;
    }
    if (values.IsEmpty()) {
        return E_SUCCESS;
    }

    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subtype));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(GetAlbumId(albumResult)));
    int32_t changedRows = 0;
    err = rdbStore->Update(changedRows, values, predicates);
    if (err < 0) {
        MEDIA_WARN_LOG("Failed to update album count and cover! err: %{public}d", err);
    }
        if (hiddenState) {
        updateResult[UpdateAlbumType::UPDATE_HIDDEN_ALBUM] += changedRows;
    } else {
        updateResult[UpdateAlbumType::UPDATE_SYSTEM_ALBUM] += changedRows;
    }
    return E_SUCCESS;
}

void MediaLibraryRdbUtils::UpdateUserAlbumByUri(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t>  &updateResult, const vector<string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateUserAlbumByUri");

    if (uris.size() == 0) {
        UpdateUserAlbumInternal(rdbStore);
    }
    vector<string> albumIds;
    string idArgs;
    for (size_t i = 0; i < uris.size(); i++) {
        string fileId = GetPhotoId(uris[i]);
        if (fileId.size() > 0) {
            idArgs.append(fileId).append(",");
        }
        if ((i == 0 || i % ALBUM_UPDATE_THRESHOLD != 0) && i < uris.size() - 1) {
            continue;
        }
        if (idArgs.size() == 0) {
            continue;
        }
        idArgs = idArgs.substr(0, idArgs.size() - 1);
        RdbPredicates predicates(PhotoMap::TABLE);
        predicates.SetWhereClause(PhotoMap::ASSET_ID + " in(" + idArgs + ") and " +
            PhotoMap::ALBUM_ID + " in(select " + PhotoAlbumColumns::ALBUM_ID + " from " +
            PhotoAlbumColumns::TABLE + " where " + PhotoAlbumColumns::ALBUM_TYPE + " = " +
            to_string(PhotoAlbumType::USER) + ")");
        QueryAlbumId(rdbStore, predicates, albumIds);
        idArgs.clear();
    }
    if (albumIds.size() > 0) {
        UpdateUserAlbumInternal(rdbStore, albumIds);
    }
}

void MediaLibraryRdbUtils::UpdateUserAlbumInternal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &userAlbumIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateUserAlbumInternal");

    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_COVER_URI,
        PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
        PhotoAlbumColumns::ALBUM_VIDEO_COUNT,
    };
    auto albumResult = GetUserAlbum(rdbStore, userAlbumIds, columns);
    if (albumResult == nullptr) {
        return;
    }
    std::unordered_map<int32_t, int32_t>  updateResult;
    ForEachRow(rdbStore, albumResult, false, updateResult, UpdateUserAlbumIfNeeded);
}

void MediaLibraryRdbUtils::UpdateAnalysisAlbumByUri(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult, const vector<string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAnalysisAlbumByUri");

    if (uris.size() == 0) {
        UpdateAnalysisAlbumInternal(rdbStore, updateResult);
    }
    vector<string> albumIds;
    vector<string> idArgs;
    vector<string> fileIds;
    for (size_t i = 0; i < uris.size(); i++) {
        string fileId = GetPhotoId(uris[i]);
        if (fileId.size() > 0) {
            idArgs.push_back(fileId);
            fileIds.push_back(fileId);
        }
        if (idArgs.size() == ALBUM_UPDATE_THRESHOLD || i == uris.size() - 1) {
            RdbPredicates predicates(ANALYSIS_PHOTO_MAP_TABLE);
            predicates.In(PhotoMap::ASSET_ID, idArgs);
            QueryAlbumId(rdbStore, predicates, albumIds);
            idArgs.clear();
        }
    }
    if (albumIds.size() > 0) {
        UpdateAnalysisAlbumInternal(rdbStore, updateResult, albumIds, fileIds);
    }
}

int32_t MediaLibraryRdbUtils::GetAlbumIdsForPortrait(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    vector<string> &portraitAlbumIds)
{
    std::stringstream labelIds;
    unordered_set<string> resultAlbumIds;
    for (size_t i = 0; i < portraitAlbumIds.size(); i++) {
        labelIds << portraitAlbumIds[i];
        if (i != portraitAlbumIds.size() - 1) {
            labelIds << ",";
        }
        resultAlbumIds.insert(portraitAlbumIds[i]);
    }

    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.SetWhereClause(GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " IN (" + labelIds.str() + ") AND " + ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) +")");
    vector<string> columns = {
        ALBUM_ID,
    };
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string albumId = to_string(GetIntValFromColumn(resultSet, ALBUM_ID));
        if (resultAlbumIds.find(albumId) == resultAlbumIds.end()) {
            resultAlbumIds.insert(albumId);
            portraitAlbumIds.push_back(albumId);
        }
    }
    return E_OK;
}

void MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult, const vector<string> &anaAlbumAlbumIds,
    const vector<string> &fileIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAnalysisAlbumInternal");
    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::ALBUM_COVER_URI,
        PhotoAlbumColumns::ALBUM_COUNT,
        IS_COVER_SATISFIED
    };
    vector<string> tempAlbumId = anaAlbumAlbumIds;
    if (tempAlbumId.size() > 0) {
        GetAlbumIdsForPortrait(rdbStore, tempAlbumId);
    }
    auto albumResult = GetAnalysisAlbum(rdbStore, tempAlbumId, columns);
    if (albumResult == nullptr) {
        return;
    }

    // For each row
    TransactionOperations transactionOprn(rdbStore);
    int32_t err = transactionOprn.Start();
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to begin transaction, err: %{public}d", err);
        return;
    }
    while (albumResult->GoToNextRow() == E_OK) {
        auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
        if (subtype == PhotoAlbumSubType::PORTRAIT) {
            UpdatePortraitAlbumIfNeeded(rdbStore, albumResult, fileIds, updateResult);
        } else {
            UpdateAnalysisAlbumIfNeeded(rdbStore, albumResult, false, updateResult);
        }
    }
    transactionOprn.Finish();
}

void MediaLibraryRdbUtils::UpdateAnalysisAlbumByFile(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &fileIds, const vector<int> &albumTypes)
{
    if (fileIds.empty()) {
        MEDIA_ERR_LOG("Failed to UpdateAnalysisAlbumByFile cause fileIds empty");
        return;
    }
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAnalysisAlbumByFile");
    vector<string> columns = {
        PhotoMap::ALBUM_ID,
        PhotoMap::ASSET_ID,
    };
    RdbPredicates predicates(ANALYSIS_PHOTO_MAP_TABLE);
    if (!albumTypes.empty()) {
        std::string files;
        for (std::string fileId : fileIds) {
            files.append(fileId).append(",");
        }
        files = files.substr(0, files.length() - 1);
        std::string subTypes;
        for (int subtype : albumTypes) {
            subTypes.append(to_string(subtype)).append(",");
        }
        subTypes = subTypes.substr(0, subTypes.length() - 1);
        predicates.SetWhereClause(PhotoMap::ASSET_ID + " in(" + files + ") and " + PhotoMap::ALBUM_ID +
            " in(select album_id from AnalysisAlbum where album_subtype in(" + subTypes + "))");
    } else {
        predicates.In(PhotoMap::ASSET_ID, fileIds);
    }
    shared_ptr<ResultSet> mapResult = rdbStore->Query(predicates, columns);
    if (mapResult == nullptr) {
        MEDIA_ERR_LOG("Failed query AnalysisAlbum");
        return;
    }
    vector<string> albumIds;
    while (mapResult->GoToNextRow() == E_OK) {
        albumIds.push_back(to_string(GetIntValFromColumn(mapResult, PhotoMap::ALBUM_ID)));
    }
    int err = E_HAS_DB_ERROR;
    int32_t deletedRows = 0;
    err = rdbStore->Delete(deletedRows, predicates);
    if (err != E_OK || deletedRows <= 0) {
        MEDIA_ERR_LOG("Failed Delete AnalysisPhotoMap");
        return;
    }
    unordered_map<int32_t, int32_t> updateResult;
    UpdateAnalysisAlbumInternal(rdbStore, updateResult, albumIds, fileIds);
}

void MediaLibraryRdbUtils::UpdateSourceAlbumByUri(const shared_ptr<RdbStore> &rdbStore,
    unordered_map<int32_t, int32_t> &updateResult, const vector<string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSourceAlbumByUri");

    if (uris.size() == 0) {
        UpdateSourceAlbumInternal(rdbStore, updateResult);
    }
    vector<string> albumIds;
    string idArgs;
    for (size_t i = 0; i < uris.size(); i++) {
        string fileId = GetPhotoId(uris[i]);
        if (fileId.size() > 0) {
            idArgs.append(fileId).append(",");
        }
        if ((i == 0 || i % ALBUM_UPDATE_THRESHOLD != 0) && i < uris.size() - 1) {
            continue;
        }
        if (idArgs.size() == 0) {
            continue;
        }
        idArgs = idArgs.substr(0, idArgs.size() - 1);
        RdbPredicates predicates(PhotoMap::TABLE);
        predicates.SetWhereClause(PhotoMap::ASSET_ID + " in(" + idArgs + ") and " +
            PhotoMap::ALBUM_ID + " in(select " + PhotoAlbumColumns::ALBUM_ID + " from " +
            PhotoAlbumColumns::TABLE + " where " + PhotoAlbumColumns::ALBUM_TYPE + " = " +
            to_string(PhotoAlbumType::SOURCE) + ")");
        QueryAlbumId(rdbStore, predicates, albumIds);
        idArgs.clear();
    }
    if (albumIds.size() > 0) {
        UpdateSourceAlbumInternal(rdbStore, updateResult, albumIds);
    }
}

void MediaLibraryRdbUtils::UpdateSourceAlbumInternal(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult, const vector<string> &sourceAlbumIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSourceAlbumInternal");

    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::ALBUM_COVER_URI,
        PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
        PhotoAlbumColumns::ALBUM_VIDEO_COUNT,
    };
    auto albumResult = GetSourceAlbum(rdbStore, sourceAlbumIds, columns);
    if (albumResult == nullptr) {
        return;
    }

    ForEachRow(rdbStore, albumResult, false, updateResult, UpdateSourceAlbumIfNeeded);
}

static inline shared_ptr<ResultSet> GetSystemAlbum(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &subtypes, const vector<string> &columns)
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    if (subtypes.empty()) {
        predicates.In(PhotoAlbumColumns::ALBUM_SUBTYPE, ALL_SYS_PHOTO_ALBUM);
    } else {
        predicates.In(PhotoAlbumColumns::ALBUM_SUBTYPE, subtypes);
    }
    return Query(rdbStore, predicates, columns);
}

void MediaLibraryRdbUtils::UpdateSystemAlbumInternal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &subtypes)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSystemAlbumInternal");

    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::ALBUM_COVER_URI,
        PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
        PhotoAlbumColumns::ALBUM_VIDEO_COUNT,
    };
    auto albumResult = GetSystemAlbum(rdbStore, subtypes, columns);
    if (albumResult == nullptr) {
        return;
    }
    std::unordered_map<int32_t, int32_t> updateResult;
    ForEachRow(rdbStore, albumResult, false, updateResult, UpdateSysAlbumIfNeeded);
}

static void UpdateUserAlbumHiddenState(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t>  &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateUserAlbumHiddenState");
    vector<string> userAlbumIds;

    auto albumResult = GetUserAlbum(rdbStore, userAlbumIds, {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::CONTAINS_HIDDEN,
        PhotoAlbumColumns::HIDDEN_COUNT,
        PhotoAlbumColumns::HIDDEN_COVER,
    });
    if (albumResult == nullptr) {
        return;
    }
    ForEachRow(rdbStore, albumResult, true, updateResult, UpdateUserAlbumIfNeeded);
}

static void UpdateSysAlbumHiddenState(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSysAlbumHiddenState");

    auto albumResult = GetSystemAlbum(rdbStore, {
        to_string(PhotoAlbumSubType::IMAGE),
        to_string(PhotoAlbumSubType::VIDEO),
        to_string(PhotoAlbumSubType::FAVORITE),
        to_string(PhotoAlbumSubType::SCREENSHOT),
        to_string(PhotoAlbumSubType::CAMERA),
    }, {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::CONTAINS_HIDDEN,
        PhotoAlbumColumns::HIDDEN_COUNT,
        PhotoAlbumColumns::HIDDEN_COVER,
    });
    if (albumResult == nullptr) {
        return;
    }
    ForEachRow(rdbStore, albumResult, true, updateResult, UpdateSysAlbumIfNeeded);
}

static void UpdateSourceAlbumHiddenState(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSourceAlbumHiddenState");
    vector<string> sourceAlbumIds;

    auto albumResult = GetSourceAlbum(rdbStore, sourceAlbumIds, {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::CONTAINS_HIDDEN,
        PhotoAlbumColumns::HIDDEN_COUNT,
        PhotoAlbumColumns::HIDDEN_COVER,
    });
    if (albumResult == nullptr) {
        return;
    }
    ForEachRow(rdbStore, albumResult, true, updateResult, UpdateSourceAlbumIfNeeded);
}

void MediaLibraryRdbUtils::UpdateHiddenAlbumInternal(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t> &updateResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateHiddenAlbumInternal");

    UpdateUserAlbumHiddenState(rdbStore, updateResult);
    UpdateSysAlbumHiddenState(rdbStore, updateResult);
    UpdateSourceAlbumHiddenState(rdbStore, updateResult);
}

void MediaLibraryRdbUtils::UpdateAllAlbums(const shared_ptr<RdbStore> &rdbStore,
    std::unordered_map<int32_t, int32_t>  &updateResult, const vector<string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAllAlbums");

    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateHiddenAlbumInternal(rdbStore, updateResult);
    MediaLibraryRdbUtils::UpdateUserAlbumByUri(rdbStore, updateResult, uris);
    MediaLibraryRdbUtils::UpdateSourceAlbumByUri(rdbStore, updateResult, uris);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumByUri(rdbStore, updateResult, uris);
}

static int32_t UpdateAlbumReplacedSignal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &albumIdVector)
{
    if (albumIdVector.empty()) {
        return E_SUCCESS;
    }

    ValuesBucket refreshValues;
    string insertRefreshTableSql = "INSERT OR IGNORE INTO " + ALBUM_REFRESH_TABLE + " VALUES ";
    for (size_t i = 0; i < albumIdVector.size(); ++i) {
        if (i != albumIdVector.size() - 1) {
            insertRefreshTableSql += "(" + albumIdVector[i] + "), ";
        } else {
            insertRefreshTableSql += "(" + albumIdVector[i] + ");";
        }
    }
    MEDIA_DEBUG_LOG("output insertRefreshTableSql:%{public}s", insertRefreshTableSql.c_str());

    int32_t ret = rdbStore->ExecuteSql(insertRefreshTableSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not insert refreshed table, ret:%{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return E_SUCCESS;
}

static int32_t UpdateBussinessRecord(const shared_ptr<RdbStore> &rdbStore,
    const vector<BussinessRecordValue> &updateValue)
{
    if (updateValue.empty()) {
        return E_SUCCESS;
    }

    ValuesBucket refreshValues;
    string insertTableSql = "INSERT OR IGNORE INTO " + MedialibraryBusinessRecordColumn::TABLE + "(" +
        MedialibraryBusinessRecordColumn::BUSINESS_TYPE + "," + MedialibraryBusinessRecordColumn::KEY + "," +
        MedialibraryBusinessRecordColumn::VALUE + ") VALUES ";
    for (size_t i = 0; i < updateValue.size(); ++i) {
        if (i != updateValue.size() - 1) {
            insertTableSql += "('" + updateValue[i].bussinessType + "', '" + updateValue[i].key + "', '" +
                updateValue[i].value + "'), ";
        } else {
            insertTableSql += "('" + updateValue[i].bussinessType + "', '" + updateValue[i].key + "', '" +
                updateValue[i].value + "');";
        }
    }
    MEDIA_DEBUG_LOG("output insertTableSql:%{public}s", insertTableSql.c_str());

    int32_t ret = rdbStore->ExecuteSql(insertTableSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not insert bussinessRecord table, ret:%{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return E_SUCCESS;
}

void MediaLibraryRdbUtils::UpdateSystemAlbumCountInternal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &subtypes)
{
    // Only use in dfs
    MediaLibraryTracer tracer;
    tracer.Start("UpdateSystemAlbumCountInternal");

    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    auto albumResult = GetSystemAlbum(rdbStore, subtypes, columns);
    if (albumResult == nullptr) {
        return;
    }

    vector<string> replaceSignalAlbumVector;
    while (albumResult->GoToNextRow() == NativeRdb::E_OK) {
        int32_t ret = GetIntValFromColumn(albumResult, PhotoAlbumColumns::ALBUM_ID);
        if (ret <= 0) {
            MEDIA_WARN_LOG("Can not get ret:%{public}d", ret);
        } else {
            replaceSignalAlbumVector.push_back(to_string(ret));
        }
    }
    if (!replaceSignalAlbumVector.empty()) {
        int32_t ret = UpdateAlbumReplacedSignal(rdbStore, replaceSignalAlbumVector);
        if (ret != E_OK) {
            MEDIA_WARN_LOG("Update sysalbum replaced signal failed ret:%{public}d", ret);
        }
    }
    // Do not call SetNeedRefreshAlbum in this function
    // This is set by the notification from dfs
    // and is set by the media library observer after receiving the notification
}

void MediaLibraryRdbUtils::UpdateUserAlbumCountInternal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &userAlbumIds)
{
    // only use in dfs
    MediaLibraryTracer tracer;
    tracer.Start("UpdateUserAlbumCountInternal");

    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    auto albumResult = GetUserAlbum(rdbStore, userAlbumIds, columns);
    if (albumResult == nullptr) {
        return;
    }

    vector<string> replaceSignalAlbumVector;
    while (albumResult->GoToNextRow() == NativeRdb::E_OK) {
        int32_t ret = GetIntValFromColumn(albumResult, PhotoAlbumColumns::ALBUM_ID);
        if (ret <= 0) {
            MEDIA_WARN_LOG("Can not get ret:%{public}d", ret);
        } else {
            replaceSignalAlbumVector.push_back(to_string(ret));
        }
    }
    if (!replaceSignalAlbumVector.empty()) {
        int32_t ret = UpdateAlbumReplacedSignal(rdbStore, replaceSignalAlbumVector);
        if (ret != E_OK) {
            MEDIA_WARN_LOG("Update user album replaced signal failed ret:%{public}d", ret);
            return;
        }
    }
    // Do not call SetNeedRefreshAlbum in this function
    // This is set by the notification from dfs
    // and is set by the media library observer after receiving the notification
}

void MediaLibraryRdbUtils::UpdateAnalysisAlbumCountInternal(const shared_ptr<RdbStore> &rdbStore,
    const vector<string> &subtypes)
{
    // only use in dfs
    MediaLibraryTracer tracer;
    tracer.Start("UpdateAnalysisAlbumCountInternal");

    vector<string> columns = { ALBUM_ID, ALBUM_SUBTYPE };
    auto albumResult = GetAnalysisAlbumBySubtype(rdbStore, subtypes, columns);
    if (albumResult == nullptr) {
        return;
    }

    vector<BussinessRecordValue> updateAlbumIdList;
    while (albumResult->GoToNextRow() == NativeRdb::E_OK) {
        int32_t albumId = GetIntValFromColumn(albumResult, ALBUM_ID);
        int32_t subtype = GetIntValFromColumn(albumResult, ALBUM_SUBTYPE);
        if (albumId <= 0) {
            MEDIA_WARN_LOG("Can not get ret:%{public}d", albumId);
        } else {
            updateAlbumIdList.push_back({ ANALYSIS_REFRESH_BUSINESS_TYPE, to_string(subtype), to_string(albumId) });
        }
    }
    if (!updateAlbumIdList.empty()) {
        int32_t ret = UpdateBussinessRecord(rdbStore, updateAlbumIdList);
        if (ret != E_OK) {
            MEDIA_WARN_LOG("Update sysalbum replaced signal failed ret:%{public}d", ret);
        }
    }
    // Do not call SetNeedRefreshAlbum in this function
    // This is set by the notification from dfs
    // and is set by the media library observer after receiving the notification
}

int RefreshPhotoAlbums(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler)
{
    vector<string> albumIds;
    int ret = GetAllRefreshAlbumIds(rdbStore, albumIds);
    if (ret != E_SUCCESS) {
        return ret;
    }
    if (albumIds.empty()) {
        MEDIA_DEBUG_LOG("albumIds is empty");
        return E_EMPTY_ALBUM_ID;
    }
    MEDIA_INFO_LOG("Start refreshing photo albums, number of albums to refresh: %{public}zu", albumIds.size());
    auto resultSet = QueryAlbumById(rdbStore, albumIds);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("RefreshPhotoAlbums resultSet is null");
        return E_HAS_DB_ERROR;
    }
    ret = RefreshAlbums(rdbStore, resultSet, refreshProcessHandler);
    return ret;
}

static int32_t RefreshAnalysisAlbums(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &albumResult,
    function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler,
    const vector<string> &subtypes)
{
    while (albumResult->GoToNextRow() == NativeRdb::E_OK) {
        std::unordered_map<int32_t, int32_t>  updateResult;
        int ret = UpdateAnalysisAlbumIfNeeded(rdbStore, albumResult, false, updateResult);
        if (ret != E_SUCCESS) {
            MEDIA_ERR_LOG("UpdateAnalysisAlbumIfNeeded fail");
            return E_HAS_DB_ERROR;
        }
        auto subtype = static_cast<PhotoAlbumSubType>(GetAlbumSubType(albumResult));
        int32_t albumId = GetAlbumId(albumResult);
        refreshProcessHandler(PhotoAlbumType::SMART, subtype, albumId);
    }

    string deleteRefreshTableSql = "DELETE FROM " + MedialibraryBusinessRecordColumn::TABLE + " WHERE " +
        MedialibraryBusinessRecordColumn::BUSINESS_TYPE + " = '" + ANALYSIS_REFRESH_BUSINESS_TYPE + "'";
    int32_t ret = rdbStore->ExecuteSql(deleteRefreshTableSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to execute sql:%{private}s", deleteRefreshTableSql.c_str());
        return E_HAS_DB_ERROR;
    }
    MEDIA_DEBUG_LOG("Delete RefreshAnalysisAlbums success");
    return E_SUCCESS;
}

static int32_t GetRefreshAnalysisAlbumIds(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    vector<string> &albumIds, const vector<string> &subtypes)
{
    RdbPredicates predicates(MedialibraryBusinessRecordColumn::TABLE);
    if (!subtypes.empty()) {
        predicates.In(MedialibraryBusinessRecordColumn::KEY, subtypes);
    } else {
        predicates.In(MedialibraryBusinessRecordColumn::KEY, ALL_ANALYSIS_ALBUM);
    }
    predicates.EqualTo(MedialibraryBusinessRecordColumn::BUSINESS_TYPE, ANALYSIS_REFRESH_BUSINESS_TYPE);

    vector<string> columns = { MedialibraryBusinessRecordColumn::VALUE };
    auto resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not query ALBUM_REFRESH_TABLE");
        return E_HAS_DB_ERROR;
    }

    int32_t count = 0;
    int32_t ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount failed ret:%{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    if (count == 0) {
        MEDIA_DEBUG_LOG("count is zero, break");
        return E_SUCCESS;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex = 0;
        ret = resultSet->GetColumnIndex(MedialibraryBusinessRecordColumn::VALUE, columnIndex);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("GetColumnIndex failed ret:%{public}d", ret);
            return E_HAS_DB_ERROR;
        }
        string refreshAlbumId;
        ret = resultSet->GetString(columnIndex, refreshAlbumId);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("GetString failed ret:%{public}d", ret);
            return E_HAS_DB_ERROR;
        }
        albumIds.push_back(refreshAlbumId);
    }
    return E_SUCCESS;
}

int RefreshAnalysisPhotoAlbums(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler, const vector<string> &subtypes)
{
    vector<string> albumIds;
    int ret = GetRefreshAnalysisAlbumIds(rdbStore, albumIds, subtypes);
    if (ret != E_SUCCESS) {
        return ret;
    }
    if (albumIds.empty()) {
        MEDIA_DEBUG_LOG("albumIds is empty");
        return E_EMPTY_ALBUM_ID;
    }
    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SUBTYPE,
        PhotoAlbumColumns::ALBUM_COVER_URI,
        PhotoAlbumColumns::ALBUM_COUNT,
    };
    auto resultSet = GetAnalysisAlbum(rdbStore, albumIds, columns);
    if (resultSet == nullptr) {
        ret = E_HAS_DB_ERROR;
        return E_HAS_DB_ERROR;
    }
    ret = RefreshAnalysisAlbums(rdbStore, resultSet, refreshProcessHandler, subtypes);
    return ret;
}

int32_t MediaLibraryRdbUtils::RefreshAllAlbums(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler, function<void()> refreshCallback)
{
    isInRefreshTask = true;

    MediaLibraryTracer tracer;
    tracer.Start("RefreshAllAlbums");

    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdb");
        return E_HAS_DB_ERROR;
    }

    int ret = E_SUCCESS;
    bool isRefresh = false;
    while (IsNeedRefreshAlbum()) {
        SetNeedRefreshAlbum(false);
        ret = RefreshPhotoAlbums(rdbStore, refreshProcessHandler);
        if (ret == E_EMPTY_ALBUM_ID) {
            ret = E_SUCCESS;
            continue;
        }
        if (ret != E_SUCCESS) {
            break;
        }
        vector<string> subtype = { std::to_string(PhotoAlbumSubType::SHOOTING_MODE) };
        ret = RefreshAnalysisPhotoAlbums(rdbStore, refreshProcessHandler, subtype);
        if (ret == E_EMPTY_ALBUM_ID) {
            ret = E_SUCCESS;
            continue;
        }
        if (ret != E_SUCCESS) {
            break;
        }
        isRefresh = true;
    }

    if (ret != E_SUCCESS) {
        // refresh failed and set flag, try to refresh next time
        SetNeedRefreshAlbum(true);
    } else {
        // refresh task is successful
        SetNeedRefreshAlbum(false);
    }
    isInRefreshTask = false;
    if (isRefresh) {
        refreshCallback();
    }

    return ret;
}

void MediaLibraryRdbUtils::UpdateAllAlbumsForCloud(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore);
    unordered_map<int32_t, int32_t> updateResult;
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, updateResult);
}

void MediaLibraryRdbUtils::UpdateAllAlbumsCountForCloud(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    MediaLibraryRdbUtils::UpdateSystemAlbumCountInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateUserAlbumCountInternal(rdbStore);
    vector<string> subtype = { "4101" };
    MediaLibraryRdbUtils::UpdateAnalysisAlbumCountInternal(rdbStore, subtype);
}
} // namespace OHOS::Media
