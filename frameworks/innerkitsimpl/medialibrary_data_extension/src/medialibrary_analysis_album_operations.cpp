/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "AnalysisAlbumOperation"

#include "medialibrary_analysis_album_operations.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <sstream>

#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdb_transaction.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "values_bucket.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "vision_album_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"
#include "vision_total_column.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS::Media {
constexpr int32_t E_INDEX = -1;
constexpr int32_t ALBUM_IS_ME = 1;
constexpr int32_t ALBUM_IS_NOT_ME = 0;
constexpr int32_t ALBUM_IS_REMOVED = 1;
constexpr int32_t SINGLE_FACE = 1;
constexpr int32_t LOCAL_ALBUM = 1;
constexpr int32_t ALBUM_NOT_FOUND = 0;
constexpr int32_t QUERY_GROUP_PHOTO_ALBUM_RELATED_TO_ME = 1;
const string GROUP_PHOTO_TAG = "group_photo_tag";
const string GROUP_PHOTO_IS_ME = "group_photo_is_me";
const string GROUP_PHOTO_ALBUM_NAME = "album_name";
const string GROUP_MERGE_SQL_PRE = "SELECT " + ALBUM_ID + ", " + COVER_URI + ", " + IS_COVER_SATISFIED + ", "
    + TAG_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_SUBTYPE + " = " + to_string(GROUP_PHOTO) +
    " AND (INSTR(" + TAG_ID + ", '";

static std::mutex updateGroupPhotoAlbumMutex;

static int32_t ExecSqls(const vector<string> &sqls, const shared_ptr<MediaLibraryUnistore> &store)
{
    int32_t err = NativeRdb::E_OK;
    for (const auto &sql : sqls) {
        err = store->ExecuteSql(sql);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to exec: %{private}s", sql.c_str());
            break;
        }
    }
    return err;
}

static int32_t GetArgsValueByName(const string &valueName, const string &whereClause, const vector<string> &whereArgs)
{
    size_t pos = whereClause.find(valueName);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("whereClause is invalid");
        return E_INDEX;
    }
    size_t argsIndex = 0;
    for (size_t i = 0; i < pos; i++) {
        if (whereClause[i] == '?') {
            argsIndex++;
        }
    }
    if (argsIndex > whereArgs.size() - 1) {
        MEDIA_ERR_LOG("whereArgs is invalid");
        return E_INDEX;
    }
    return atoi(whereArgs[argsIndex].c_str());
}

static int32_t GetAlbumId(const string &whereClause, const vector<string> &whereArgs)
{
    size_t pos = whereClause.find(PhotoAlbumColumns::ALBUM_ID);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("whereClause is invalid");
        return E_INDEX;
    }
    size_t argsIndex = 0;
    for (size_t i = 0; i < pos; i++) {
        if (whereClause[i] == '?') {
            argsIndex++;
        }
    }
    if (argsIndex > whereArgs.size() - 1) {
        MEDIA_ERR_LOG("whereArgs is invalid");
        return E_INDEX;
    }
    auto albumId = whereArgs[argsIndex];
    if (MediaLibraryDataManagerUtils::IsNumber(albumId)) {
        return atoi(albumId.c_str());
    }
    return E_INDEX;
}

static int32_t GetIntValueFromResultSet(shared_ptr<NativeRdb::ResultSet> resultSet, const string &column, int &value)
{
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    CHECK_AND_RETURN_RET(index != E_INDEX, E_HAS_DB_ERROR);
    CHECK_AND_RETURN_RET(resultSet->GetInt(index, value) == NativeRdb::E_OK, E_HAS_DB_ERROR);
    return E_OK;
}

static int32_t GetStringValueFromResultSet(shared_ptr<NativeRdb::ResultSet> resultSet, const string &column,
    string &value)
{
    CHECK_AND_RETURN_RET(resultSet != nullptr, E_HAS_DB_ERROR);
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    CHECK_AND_RETURN_RET(index != E_INDEX, E_HAS_DB_ERROR);
    CHECK_AND_RETURN_RET(resultSet->GetString(index, value) == NativeRdb::E_OK, E_HAS_DB_ERROR);
    return E_OK;
}

static string GetCoverUri(int32_t fileId, const string &path, const string &displayName)
{
    string fileName;
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash != string::npos && path.size() > (lastSlash + 1)) {
        fileName = path.substr(lastSlash + 1);
    }
    string fileTitle = fileName;
    size_t lastDot = fileName.find_last_of('.');
    if (lastDot != string::npos) {
        fileTitle = fileName.substr(0, lastDot);
    }
    return PhotoColumn::PHOTO_URI_PREFIX + to_string(fileId) + "/" + fileTitle + "/" + displayName;
}

inline int32_t GetStringObject(const ValuesBucket &values, const string &key, string &value)
{
    value = "";
    ValueObject valueObject;
    if (values.GetObject(key, valueObject)) {
        valueObject.GetString(value);
    } else {
        return -EINVAL;
    }
    return E_OK;
}

static void NotifyGroupAlbum(const vector<int32_t> &changedAlbumIds)
{
    if (changedAlbumIds.size() <= 0) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "Can not get MediaLibraryNotify Instance");
    for (int32_t albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, to_string(albumId)), NotifyType::NOTIFY_UPDATE);
    }
}

static void ClearEmptyGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &clearAlbums)
{
    if (clearAlbums.empty()) {
        return;
    }
    ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_COUNT, 0);
    values.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, "");
    values.PutInt(IS_COVER_SATISFIED, static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING));
    values.PutInt(IS_ME, ALBUM_IS_NOT_ME);

    RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
    stringstream ss;
    for (size_t i = 0; i < clearAlbums.size(); i++) {
        ss << clearAlbums[i].albumId;
        if (i != clearAlbums.size() - 1) {
            ss << ", ";
        }
    }
    string clause = PhotoAlbumColumns::ALBUM_ID + " IN (" + ss.str() + ") AND ";
    rdbPredicates.SetWhereClause(clause);
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SMART));
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::GROUP_PHOTO));
    auto ret = MediaLibraryRdbStore::UpdateWithDateTime(values, rdbPredicates);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Clear empty group photo album info failed! Error: %{public}d", ret);
}

static string BuildUpdateGroupPhotoAlbumSql(const GroupPhotoAlbumInfo &albumInfo)
{
    string withSql;
    string coverUriValueSql;
    string isCoverSatisfiedValueSql;
    if (albumInfo.isCoverSatisfied == static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING)) {
        coverUriValueSql = "'" + albumInfo.candidateUri + "'";
        isCoverSatisfiedValueSql = to_string(static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING));
    } else {
        string oldCoverId = MediaFileUri::GetPhotoId(albumInfo.coverUri);
        if (!oldCoverId.empty() && MediaLibraryDataManagerUtils::IsNumber(oldCoverId)) {
            withSql = "WITH is_cover_exist AS (SELECT 1 FROM " + ANALYSIS_ALBUM_TABLE +
                " INNER JOIN " + ANALYSIS_PHOTO_MAP_TABLE + " ON " +
                MAP_ALBUM + " = " + ALBUM_ID + " AND INSTR('" + albumInfo.tagId + "', " + GROUP_TAG + ") > 0" +
                " INNER JOIN " + PhotoColumn::PHOTOS_TABLE + " ON " +
                MAP_ASSET + " = " + MediaColumn::MEDIA_ID + " AND " +
                MediaColumn::MEDIA_DATE_TRASHED + " = 0 AND " +
                MediaColumn::MEDIA_HIDDEN + " = 0 AND " +
                MediaColumn::MEDIA_TIME_PENDING + " = 0 AND " +
                MediaColumn::MEDIA_ID + " = " + oldCoverId + ")";
            coverUriValueSql = "CASE (SELECT 1 FROM is_cover_exist) WHEN 1 THEN '" + albumInfo.coverUri +
                "' ELSE '" + albumInfo.candidateUri + "' END";
            isCoverSatisfiedValueSql = "CASE (SELECT 1 FROM is_cover_exist) WHEN 1 THEN " +
                to_string(albumInfo.isCoverSatisfied) + " ELSE " +
                to_string(static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING)) + " END";
        } else {
            coverUriValueSql = "'" + albumInfo.candidateUri + "'";
            isCoverSatisfiedValueSql = to_string(static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING));
        }
    }
    string albumNameArg = "";
    if (!albumInfo.albumName.empty()) {
        albumNameArg = ", " + GROUP_PHOTO_ALBUM_NAME + " = '" + albumInfo.albumName + "'";
    }
    string updateSql = withSql + " UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_COUNT + " = " + to_string(albumInfo.count) + ", " +
        IS_ME + " = " + to_string(albumInfo.isMe) + ", " +
        PhotoAlbumColumns::ALBUM_COVER_URI + " = " + coverUriValueSql + ", " +
        IS_REMOVED + " = " + to_string(albumInfo.isRemoved) + ", " +
        RENAME_OPERATION + " = " + to_string(albumInfo.renameOperation) + ", " +
        IS_COVER_SATISFIED + " = " + isCoverSatisfiedValueSql + albumNameArg +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumInfo.albumId) + ";";
    return updateSql;
}

static void UpdateGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &updateAlbums)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Update group photo album info failed. rdbStore is null");

    for (auto album : updateAlbums) {
        string sql = BuildUpdateGroupPhotoAlbumSql(album);
        auto ret = rdbStore->ExecuteSql(sql);
        CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Update group photo album failed! Error: %{public}d", ret);
    }
}

static void InsertGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &insertAlbums, vector<int32_t> &insertAlbumsId)
{
    if (insertAlbums.empty()) {
        return;
    }
    vector<DataShare::DataShareValuesBucket> insertValues;
    for (auto album : insertAlbums) {
        DataShare::DataShareValuesBucket values;
        values.Put(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::SMART);
        values.Put(PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumSubType::GROUP_PHOTO);
        values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, album.candidateUri);
        values.Put(PhotoAlbumColumns::ALBUM_COUNT, album.count);
        values.Put(TAG_ID, album.tagId);
        values.Put(GROUP_TAG, album.tagId);
        values.Put(IS_ME, album.isMe);
        values.Put(IS_LOCAL, LOCAL_ALBUM);
        values.Put(IS_COVER_SATISFIED, static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING));
        insertValues.push_back(values);
    }
    Uri uri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(uri);
    auto ret = MediaLibraryDataManager::GetInstance()->BatchInsert(cmd, insertValues);
    if (ret >= 0) {
        MEDIA_INFO_LOG("Insert %{public}d group photo album info.", ret);
        RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
        rdbPredicates.SetWhereClause(PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?");
        rdbPredicates.SetWhereArgs({ to_string(PhotoAlbumSubType::GROUP_PHOTO) });
        rdbPredicates.OrderByDesc(PhotoAlbumColumns::ALBUM_ID);
        std::vector<std::string> columns = { PhotoAlbumColumns::ALBUM_ID };
        auto resultSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
        if (resultSet == nullptr) {
            return;
        }
        for (auto i = 0; i < ret; i++) {
            resultSet->GoTo(i);
            insertAlbumsId.push_back(GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet));
        }
    } else {
        MEDIA_ERR_LOG("Insert group photo album info failed! Error: %{public}d.", ret);
    }
}

static string GetGroupPhotoAlbumSql()
{
    string innerJoinAnalysisAlbum = "INNER JOIN " + ANALYSIS_ALBUM_TABLE + " AA ON F." +
        TAG_ID + " = AA." + TAG_ID + " AND " + TOTAL_FACES + " > " + to_string(SINGLE_FACE) +
        " AND (" + ALBUM_NAME + " IS NOT NULL OR " + IS_ME + " = " + to_string(ALBUM_IS_ME) + ")";
    string innerJoinAnalysisPhotoMap = "INNER JOIN " + ANALYSIS_PHOTO_MAP_TABLE + " ON " +
        MAP_ALBUM + " = AA." + PhotoAlbumColumns::ALBUM_ID + " AND " +
        MAP_ASSET + " = F." + MediaColumn::MEDIA_ID;
    string innerJoinPhotos = "INNER JOIN " + PhotoColumn::PHOTOS_TABLE + " P ON F." +
        MediaColumn::MEDIA_ID + " = P." + MediaColumn::MEDIA_ID + " AND " +
        MediaColumn::MEDIA_DATE_TRASHED + " = 0 AND " +
        MediaColumn::MEDIA_HIDDEN + " = 0 AND " +
        MediaColumn::MEDIA_TIME_PENDING + " = 0";
    string innerSql = "SELECT F." + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
        MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", " +
        TOTAL_FACES + ", " + GROUP_TAG + ", " + IS_ME + " FROM " + VISION_IMAGE_FACE_TABLE + " F " +
        innerJoinAnalysisAlbum + " " + innerJoinAnalysisPhotoMap + " " + innerJoinPhotos +
        " ORDER BY F." + MediaColumn::MEDIA_ID + ", " + GROUP_TAG;
    string groupPhotoTagSql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
        MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", " + IS_ME +
        ", GROUP_CONCAT(DISTINCT " + GROUP_TAG + ") AS " + GROUP_PHOTO_TAG +
        " FROM (" + innerSql + ") GROUP BY " + MediaColumn::MEDIA_ID +
        " HAVING COUNT(" + GROUP_TAG +") = " + TOTAL_FACES + " AND COUNT(DISTINCT " + GROUP_TAG + ") > " +
        to_string(SINGLE_FACE);
    string leftJoinAnalysisAlbum = "LEFT JOIN " + ANALYSIS_ALBUM_TABLE + " AA ON " +
        GROUP_PHOTO_TAG + " = AA." + TAG_ID + " AND AA." + ALBUM_SUBTYPE + " = " +
        to_string(PhotoAlbumSubType::GROUP_PHOTO);
    string queryGroupPhotoIsMe = "CASE WHEN MAX(GP." + IS_ME + ") = " + to_string(ALBUM_IS_ME) + " THEN " +
        to_string(ALBUM_IS_ME) + " ELSE " + to_string(ALBUM_IS_NOT_ME) + " END AS " + GROUP_PHOTO_IS_ME;
    string fullSql = "SELECT " + GROUP_PHOTO_TAG + ", " + PhotoAlbumColumns::ALBUM_ID + ", " +
        PhotoAlbumColumns::ALBUM_COVER_URI + ", " + IS_COVER_SATISFIED + ", " +
        MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_NAME + ", " +
        GROUP_PHOTO_ALBUM_NAME + ", " + IS_REMOVED + ", " + RENAME_OPERATION + ", " +
        "COUNT (DISTINCT " + MediaColumn::MEDIA_ID + ") AS " + PhotoAlbumColumns::ALBUM_COUNT + ", " +
        queryGroupPhotoIsMe + ", " + "MAX(" + MediaColumn::MEDIA_DATE_ADDED + ") FROM (" + groupPhotoTagSql +
        ") AS GP " + leftJoinAnalysisAlbum + " GROUP BY " + GROUP_PHOTO_TAG + ";";
    return fullSql;
}

static bool CheckGroupPhotoAlbumInfo(const GroupPhotoAlbumInfo &info, const GroupPhotoAlbumInfo &lastInfo)
{
    bool hasUpdated = ((info.albumName.compare(lastInfo.albumName) != 0) ||
        (info.coverUri.compare(lastInfo.coverUri) != 0) ||
        (info.count != lastInfo.count) ||
        (info.isMe != lastInfo.isMe) ||
        (info.isRemoved != lastInfo.isRemoved) ||
        (info.renameOperation != lastInfo.renameOperation) ||
        (info.isCoverSatisfied != lastInfo.isCoverSatisfied));
    return hasUpdated;
}

static GroupPhotoAlbumInfo AssemblyInfo(shared_ptr<NativeRdb::ResultSet> resultSet)
{
    string tagId = GetStringVal(GROUP_PHOTO_TAG, resultSet);
    int32_t isCoverSatisfied = GetInt32Val(IS_COVER_SATISFIED, resultSet);
    int32_t count = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
    int32_t isMe = GetInt32Val(GROUP_PHOTO_IS_ME, resultSet);
    int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    string coverUri = GetStringVal(PhotoAlbumColumns::ALBUM_COVER_URI, resultSet);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    string candidateUri = GetCoverUri(fileId, path, displayName);
    string albumName = GetStringVal(GROUP_PHOTO_ALBUM_NAME, resultSet);
    int32_t isRemoved = GetInt32Val(IS_REMOVED, resultSet);
    int32_t renameOperation = GetInt32Val(RENAME_OPERATION, resultSet);
    GroupPhotoAlbumInfo info {albumId, tagId, coverUri, isCoverSatisfied, count, fileId, candidateUri, isMe,
        albumName, isRemoved, renameOperation};
    return info;
}

static std::map<int32_t, GroupPhotoAlbumInfo> GetAnalysisAlbumInfo()
{
    std::map<int32_t, GroupPhotoAlbumInfo> lastResultMap;
    const string queryAnalysisAlbumSql = "SELECT * FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SMART) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::GROUP_PHOTO);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, lastResultMap, "Get AnalysisAlbum failed. rdbStore is null");

    auto resultSet = rdbStore->QuerySql(queryAnalysisAlbumSql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, lastResultMap, "Get AnalysisAlbum failed, query resultSet is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        lastResultMap[albumId].albumId = albumId;
        lastResultMap[albumId].albumName = GetStringVal(GROUP_PHOTO_ALBUM_NAME, resultSet);
        lastResultMap[albumId].coverUri = GetStringVal(PhotoAlbumColumns::ALBUM_COVER_URI, resultSet);
        lastResultMap[albumId].count = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
        lastResultMap[albumId].isMe = GetInt32Val(IS_ME, resultSet);
        lastResultMap[albumId].isRemoved = GetInt32Val(IS_REMOVED, resultSet);
        lastResultMap[albumId].renameOperation = GetInt32Val(RENAME_OPERATION, resultSet);
        lastResultMap[albumId].isCoverSatisfied = GetInt32Val(IS_COVER_SATISFIED, resultSet);
    }
    return lastResultMap;
}

static bool UpdateGroupPhotoAlbum(vector<GroupPhotoAlbumInfo> &updateAlbums, vector<GroupPhotoAlbumInfo> &insertAlbums,
    vector<GroupPhotoAlbumInfo> &clearAlbums, vector<int32_t> &insertAlbumsId)
{
    auto lastResultMap = GetAnalysisAlbumInfo();
    const string querySql = GetGroupPhotoAlbumSql();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "Update group photo album failed, rdbStore is null.");
    auto resultSet = rdbStore->QuerySql(querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "Update group photo album failed, query resultSet is null.");

    bool hasUpdated = false;
    while (resultSet->GoToNextRow() == E_OK) {
        int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        auto info = AssemblyInfo(resultSet);
        if (albumId == ALBUM_NOT_FOUND) {
            insertAlbums.push_back(info);
            hasUpdated = true;
        } else {
            if (CheckGroupPhotoAlbumInfo(info, lastResultMap[albumId])) {
                hasUpdated = true;
                updateAlbums.push_back(info);
            }
            lastResultMap.erase(albumId);
        }
    }

    UpdateGroupPhotoAlbumInfo(updateAlbums);
    InsertGroupPhotoAlbumInfo(insertAlbums, insertAlbumsId);
    if (lastResultMap.size() > 0) {
        hasUpdated = true;
        for (auto iter = lastResultMap.begin(); iter != lastResultMap.end(); ++iter) {
            clearAlbums.push_back(iter->second);
        }
        ClearEmptyGroupPhotoAlbumInfo(clearAlbums);
    }
    return hasUpdated;
}

static void UpdateGroupPhotoAlbumAsync(AsyncTaskData *data)
{
    lock_guard<mutex> lock(updateGroupPhotoAlbumMutex);
    vector<GroupPhotoAlbumInfo> updateAlbums;
    vector<GroupPhotoAlbumInfo> insertAlbums;
    vector<GroupPhotoAlbumInfo> clearAlbums;
    vector<int32_t> insertAlbumsId;
    bool hasUpdated = UpdateGroupPhotoAlbum(updateAlbums, insertAlbums, clearAlbums, insertAlbumsId);
    if (hasUpdated) {
        vector<int32_t> changeAlbumIds {};
        for (auto info : updateAlbums) {
            changeAlbumIds.push_back(info.albumId);
        }
        for (auto albumId : insertAlbumsId) {
            changeAlbumIds.push_back(albumId);
        }
        for (auto info : clearAlbums) {
            changeAlbumIds.push_back(info.albumId);
        }
        NotifyGroupAlbum(changeAlbumIds);
    }
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(
    MediaLibraryCommand &cmd, const std::vector<std::string> &columns)
{
    auto whereClause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    auto whereArgs = cmd.GetAbsRdbPredicates()->GetWhereArgs();
    RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
    auto albumId = GetAlbumId(whereClause, whereArgs);

    string clause = "";
    if (albumId != E_INDEX) {
        clause = PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SMART) + " AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::GROUP_PHOTO) + " AND " +
            PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumId) + " AND " +
            IS_REMOVED + " IS NOT " + to_string(ALBUM_IS_REMOVED);
    } else {
        clause = PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SMART) + " AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::GROUP_PHOTO) + " AND " +
            IS_REMOVED + " IS NOT " + to_string(ALBUM_IS_REMOVED);
        if (whereClause.find(IS_ME) != string::npos) {
            int32_t value = GetArgsValueByName(IS_ME, whereClause, whereArgs);
            if (value == QUERY_GROUP_PHOTO_ALBUM_RELATED_TO_ME) {
                clause += " AND " + IS_ME + " = " + to_string(ALBUM_IS_ME);
            }
        }
    }

    rdbPredicates.SetWhereClause(clause);
    rdbPredicates.OrderByDesc(RENAME_OPERATION);
    rdbPredicates.OrderByDesc("(SELECT LENGTH(" + TAG_ID + ") - LENGTH([REPLACE](" + TAG_ID + ", ',', '')))");
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    CHECK_AND_RETURN_RET(albumId == E_INDEX, resultSet);

    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        auto updateGroupTask = make_shared<MediaLibraryAsyncTask>(UpdateGroupPhotoAlbumAsync, nullptr);
        if (updateGroupTask != nullptr) {
            asyncWorker->AddTask(updateGroupTask, true);
        } else {
            MEDIA_ERR_LOG("Failed to create async task for query group photo album.");
        }
    } else {
        MEDIA_ERR_LOG("Can not get asyncWorker");
    }
    return resultSet;
}

static int32_t GetMergeAlbumCoverUri(MergeAlbumInfo &updateAlbumInfo, const MergeAlbumInfo &currentAlbum,
    const MergeAlbumInfo &targetAlbum)
{
    string currentFileId = MediaFileUri::GetPhotoId(currentAlbum.coverUri);
    string targetFileId = MediaFileUri::GetPhotoId(targetAlbum.coverUri);
    bool cond = (currentFileId.empty() || targetFileId.empty());
    CHECK_AND_RETURN_RET(!cond, E_DB_FAIL);

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_DB_FAIL,
        "uniStore is nullptr! failed query get merge album cover uri");

    string candidateIds;
    if (currentAlbum.isCoverSatisfied == targetAlbum.isCoverSatisfied) {
        candidateIds = currentFileId + ", " + targetFileId;
    } else {
        candidateIds = currentAlbum.isCoverSatisfied != static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING) ?
            currentFileId :
            targetFileId;
    }
    const std::string queryAlbumInfo = "SELECT " + MediaColumn::MEDIA_ID + "," + MediaColumn::MEDIA_TITLE + "," +
        MediaColumn::MEDIA_NAME + ", MAX(" + MediaColumn::MEDIA_DATE_ADDED + ") FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_ID + " IN (" + candidateIds + " )";

    auto resultSet = uniStore->QuerySql(queryAlbumInfo);
    cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, E_HAS_DB_ERROR, "Failed to query merge album cover uri");

    int mergeFileId;
    string mergeTitle;
    string mergeDisplayName;
    CHECK_AND_RETURN_RET_LOG(GetIntValueFromResultSet(resultSet,
        MediaColumn::MEDIA_ID, mergeFileId) == NativeRdb::E_OK,
        E_HAS_DB_ERROR, "Failed to get file id of merge album cover uri.");
   
    CHECK_AND_RETURN_RET_LOG(GetStringValueFromResultSet(resultSet,
        MediaColumn::MEDIA_TITLE, mergeTitle) == NativeRdb::E_OK,
        E_HAS_DB_ERROR, "Failed to get title of merge album cover uri.");
    
    CHECK_AND_RETURN_RET_LOG(GetStringValueFromResultSet(resultSet,
        MediaColumn::MEDIA_NAME, mergeDisplayName) == NativeRdb::E_OK,
        E_HAS_DB_ERROR, "Failed to get display name of merge album cover uri.");
    updateAlbumInfo.coverUri = "file://media/Photo/" + to_string(mergeFileId) + "/" + mergeTitle + "/" +
        mergeDisplayName;
    return E_OK;
}

static int32_t UpdateForMergeGroupAlbums(const shared_ptr<MediaLibraryRdbStore> store, const vector<int> &deleteId,
    const std::unordered_map<string, MergeAlbumInfo> updateMap)
{
    for (auto it : deleteId) {
        RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
        rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(it));
        MediaLibraryRdbStore::Delete(rdbPredicates);
    }
    vector<string> updateSqls;
    for (auto it : updateMap) {
        string sql = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + TAG_ID + " = '" + it.first + "', " +
            GROUP_TAG + " = '" + it.first + "', " + COVER_URI + " = '" + it.second.coverUri + "', " +
            IS_REMOVED + " = 0, " + IS_COVER_SATISFIED  + " = " + to_string(it.second.isCoverSatisfied) +
            " WHERE " + ALBUM_ID + " = " + to_string(it.second.albumId);
        updateSqls.push_back(sql);
    }
    return ExecSqls(updateSqls, store);
}

static string ReorderTagId(string target, const vector<MergeAlbumInfo> &mergeAlbumInfo)
{
    string reordererTagId;
    vector<string> splitResult;
    if (target.empty()) {
        return reordererTagId;
    }
    string pattern = ",";
    string strs = target + pattern;
    size_t pos = strs.find(pattern);
    while (pos != strs.npos) {
        string groupTag = strs.substr(0, pos);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(pattern);
        if (groupTag.compare(mergeAlbumInfo[0].groupTag) != 0 && groupTag.compare(mergeAlbumInfo[1].groupTag) != 0) {
            splitResult.push_back(groupTag);
        }
    }

    CHECK_AND_RETURN_RET(!splitResult.empty(), reordererTagId);
    string newTagId = mergeAlbumInfo[0].groupTag + "|" + mergeAlbumInfo[1].groupTag;
    splitResult.push_back(newTagId);
    std::sort(splitResult.begin(), splitResult.end());
    for (auto tagId : splitResult) {
        reordererTagId += (tagId + ",");
    }
    reordererTagId = reordererTagId.substr(0, reordererTagId.size() - 1);
    return reordererTagId;
}

int32_t GetMergeAlbumInfo(shared_ptr<NativeRdb::ResultSet> resultSet, MergeAlbumInfo &info)
{
    int isCoverSatisfied = 0;
    bool cond = (GetIntValueFromResultSet(resultSet, ALBUM_ID, info.albumId) != E_OK ||
        GetStringValueFromResultSet(resultSet, TAG_ID, info.tagId) != E_OK ||
        GetStringValueFromResultSet(resultSet, COVER_URI, info.coverUri) != E_OK ||
        GetIntValueFromResultSet(resultSet, IS_COVER_SATISFIED, isCoverSatisfied) != E_OK);
    CHECK_AND_RETURN_RET(!cond, E_HAS_DB_ERROR);

    info.isCoverSatisfied = static_cast<uint8_t>(isCoverSatisfied);
    return E_OK;
}

int32_t MediaLibraryAnalysisAlbumOperations::UpdateMergeGroupAlbumsInfo(const vector<MergeAlbumInfo> &mergeAlbumInfo)
{
    if (mergeAlbumInfo.size() <= 1) {
        MEDIA_ERR_LOG("mergeAlbumInfo size is not enough.");
        return E_INVALID_VALUES;
    }

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_DB_FAIL, "UniStore is nullptr! Query album order failed.");
    string queryTagId = GROUP_MERGE_SQL_PRE + mergeAlbumInfo[0].groupTag + "') > 0 OR INSTR(" + TAG_ID + ", '" +
        mergeAlbumInfo[1].groupTag + "') > 0)";
    auto resultSet = uniStore->QuerySql(queryTagId);
    CHECK_AND_RETURN_RET(resultSet != nullptr, E_HAS_DB_ERROR);

    std::vector<int> deleteId;
    std::unordered_map<string, MergeAlbumInfo> updateMap;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        MergeAlbumInfo info;
        CHECK_AND_RETURN_RET(GetMergeAlbumInfo(resultSet, info) == E_OK, E_HAS_DB_ERROR);

        string reorderedTagId = ReorderTagId(info.tagId, mergeAlbumInfo);
        auto it = updateMap.find(reorderedTagId);
        if (reorderedTagId.empty()) {
            deleteId.push_back(info.albumId);
        } else if (it == updateMap.end()) {
            updateMap.insert(std::make_pair(reorderedTagId, info));
        } else {
            MergeAlbumInfo newInfo;
            if (it->second.coverUri.empty()) {
                updateMap[reorderedTagId].coverUri = info.coverUri;
                updateMap[reorderedTagId].isCoverSatisfied = info.isCoverSatisfied;
                deleteId.push_back(info.albumId);
                continue;
            } else if (info.coverUri.empty()) {
                deleteId.push_back(info.albumId);
                continue;
            } else if (GetMergeAlbumCoverUri(newInfo, info, it->second) != E_OK) {
                return E_HAS_DB_ERROR;
            }
            if (info.isCoverSatisfied != static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING) ||
                it->second.isCoverSatisfied != static_cast<uint8_t>(CoverSatisfiedType::NO_SETTING)) {
                updateMap[reorderedTagId].isCoverSatisfied = static_cast<uint8_t>(CoverSatisfiedType::DEFAULT_SETTING);
            }
            updateMap[reorderedTagId].coverUri = newInfo.coverUri;
            deleteId.push_back(info.albumId);
        }
    }
    return UpdateForMergeGroupAlbums(uniStore, deleteId, updateMap);
}

static int32_t SetGroupAlbumName(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_DB_FAIL, "uniStore is nullptr! failed update for set album name");

    string albumName;
    int err = GetStringObject(values, ALBUM_NAME, albumName);
    if (err < 0 || albumName.empty()) {
        MEDIA_ERR_LOG("invalid album name");
        return E_INVALID_VALUES;
    }
    std::string updateForSetAlbumName = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + ALBUM_NAME + " = '" + albumName +
        "' , " + RENAME_OPERATION + " = 1 WHERE " + ALBUM_ID + " = " + targetAlbumId;
    vector<string> updateSqls = { updateForSetAlbumName };
    err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyGroupAlbum(changeAlbumIds);
    }
    return err;
}

static int32_t SetGroupCoverUri(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_DB_FAIL,
        "uniStore is nullptr! failed update for set album cover uri");

    string coverUri;
    int err = GetStringObject(values, COVER_URI, coverUri);
    if (err < 0 || coverUri.empty()) {
        MEDIA_ERR_LOG("invalid album cover uri");
        return E_INVALID_VALUES;
    }
    std::string updateForSetCoverUri = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + COVER_URI + " = '" + coverUri +
        "', " + IS_COVER_SATISFIED + " = " + to_string(static_cast<uint8_t>(CoverSatisfiedType::DEFAULT_SETTING)) +
        " WHERE " + ALBUM_ID + " = " + targetAlbumId;
    vector<string> updateSqls = { updateForSetCoverUri };
    err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyGroupAlbum(changeAlbumIds);
    }
    return err;
}

static int32_t DismissGroupPhotoAlbum(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_DB_FAIL,
        "uniStore is nullptr! failed update for set album cover uri");

    std::string updateForDeleteGroupAlbum = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + IS_REMOVED + " = 1 WHERE " +
        ALBUM_ID + " = " + targetAlbumId;
    vector<string> updateSqls = { updateForDeleteGroupAlbum };
    int err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyGroupAlbum(changeAlbumIds);
    }
    return err;
}

int32_t MediaLibraryAnalysisAlbumOperations::HandleGroupPhotoAlbum(const OperationType &opType,
    const NativeRdb::ValuesBucket &values, const DataShare::DataSharePredicates &predicates)
{
    switch (opType) {
        case OperationType::DISMISS:
            return DismissGroupPhotoAlbum(values, predicates);
        case OperationType::GROUP_ALBUM_NAME:
            return SetGroupAlbumName(values, predicates);
        case OperationType::GROUP_COVER_URI:
            return SetGroupCoverUri(values, predicates);
        default:
            MEDIA_ERR_LOG("Unknown operation type: %{public}d", opType);
            return E_ERR;
    }
}

void MediaLibraryAnalysisAlbumOperations::UpdateGroupPhotoAlbumById(int32_t albumId)
{
    const string &querySql = GetGroupPhotoAlbumSql();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr,
        "Update group photo album by id: %{public}d failed, rdbStore is null.", albumId);
    auto resultSet = rdbStore->QuerySql(querySql);
    CHECK_AND_RETURN_LOG(resultSet != nullptr,
        "Update group photo album by id: %{public}d failed, query resultSet is null.", albumId);

    vector<GroupPhotoAlbumInfo> updateAlbums;
    while (resultSet->GoToNextRow() == E_OK) {
        int32_t id = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        if (id == albumId) {
            auto info = AssemblyInfo(resultSet);
            updateAlbums.push_back(info);
            break;
        }
    }
    UpdateGroupPhotoAlbumInfo(updateAlbums);
}

void MediaLibraryAnalysisAlbumOperations::UpdatePortraitAlbumCoverSatisfied(int32_t fileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr,
        "UpdatePortraitAlbumCoverSatisfied failed, fileId: %{public}d, rdbStore is null.", fileId);

    const string coverUriPrefix = "'" + PhotoColumn::PHOTO_URI_PREFIX + to_string(fileId) + "/%'";

    const string updateSql = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + IS_COVER_SATISFIED + " = " +
        IS_COVER_SATISFIED + " | " + to_string(static_cast<uint8_t>(CoverSatisfiedType::DEFAULT_SETTING)) + " WHERE " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT)) +
        " AND " + PhotoAlbumColumns::ALBUM_COVER_URI + " LIKE " + coverUriPrefix;

    int32_t ret = rdbStore->ExecuteSql(updateSql);
    CHECK_AND_RETURN_LOG(ret == E_OK, "ExecuteSql error, fileId: %{public}d, ret: %{public}d.", fileId, ret);
}

int32_t MediaLibraryAnalysisAlbumOperations::SetAnalysisAlbumOrderPosition(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "get rdbStore fail");

    stringstream updatePositionSql;
    auto valueBucket = cmd.GetValueBucket();
    const string orderPositionColumn = ORDER_POSITION;
    ValueObject orderPositionValue;
    valueBucket.GetObject(orderPositionColumn, orderPositionValue);
    string orderPositionStr;
    orderPositionValue.GetString(orderPositionStr);

    updatePositionSql << "UPDATE " << cmd.GetTableName() << " SET " << orderPositionColumn << " = " << orderPositionStr
                      << " WHERE " << cmd.GetAbsRdbPredicates()->GetWhereClause();

    std::string sqlStr = updatePositionSql.str();
    auto args = cmd.GetAbsRdbPredicates()->GetBindArgs();

    int ret = rdbStore->ExecuteSql(sqlStr, args);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret, "Update orderPositions failed, error id: %{public}d", ret);
    return ret;
}
} // namespace OHOS::Media
