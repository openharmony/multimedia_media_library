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

#include "directory_ex.h"
#include "iservice_registry.h"
#include "media_actively_calling_analyse.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "multistages_capture_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"

#include "result_set_utils.h"
#include "values_bucket.h"
#include "medialibrary_formmap_operations.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
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
constexpr int32_t ALBUM_COVER_SATISFIED = 1;
constexpr int32_t ALBUM_COVER_NOT_SATISFIED = 0;
constexpr int32_t ALBUM_IS_ME = 1;
constexpr int32_t ALBUM_IS_NOT_ME = 0;
constexpr int32_t ALBUM_IS_REMOVED = 1;
constexpr int32_t SINGLE_FACE = 1;
constexpr int32_t LOCAL_ALBUM = 1;
constexpr int32_t ALBUM_NOT_FOUND = 0;
constexpr int32_t QUERY_GROUP_PHOTO_ALBUM_RELATED_TO_ME = 1;
const string GROUP_PHOTO_TAG = "group_photo_tag";
const string GROUP_PHOTO_COUNT = "group_photo_count";
const string GROUP_PHOTO_IS_ME = "group_photo_is_me";

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

static string ParseFileIdFromCoverUri(const string &uri)
{
    if (PhotoColumn::PHOTO_URI_PREFIX.size() >= uri.size()) {
        return "";
    }
    string midStr = uri.substr(PhotoColumn::PHOTO_URI_PREFIX.size());
    string delimiter = "/";
    size_t pos = midStr.find(delimiter);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("ParseFileIdFromCoverUri fail");
        return "";
    }
    return midStr.substr(0, pos);
}

static int32_t GetPortraitSubtype(const string &subtypeName, const string &whereClause, const vector<string> &whereArgs)
{
    size_t pos = whereClause.find(subtypeName);
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

static int32_t GetIntValueFromResultSet(shared_ptr<ResultSet> resultSet, const string &column, int &value)
{
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    if (index == E_INDEX) {
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GetInt(index, value) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t GetStringValueFromResultSet(shared_ptr<ResultSet> resultSet, const string &column, string &value)
{
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    if (index == E_INDEX) {
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GetString(index, value) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
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

inline int32_t GetStringVal(const ValuesBucket &values, const string &key, string &value)
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
    for (int32_t albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, to_string(albumId)), NotifyType::NOTIFY_UPDATE);
    }
}

static void ClearEmptyGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &updateAlbums)
{
    ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_COUNT, 0);
    values.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, "");
    values.PutInt(IS_COVER_SATISFIED, ALBUM_COVER_NOT_SATISFIED);
    values.PutInt(IS_ME, ALBUM_IS_NOT_ME);

    RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
    if (!updateAlbums.empty()) {
        stringstream ss;
        for (size_t i = 0; i < updateAlbums.size(); i++) {
            ss << updateAlbums[i].albumId;
            if (i != updateAlbums.size() - 1) {
                ss << ", ";
            }
        }
        string clause = PhotoAlbumColumns::ALBUM_ID + " NOT IN (" + ss.str() + ") AND ";
        rdbPredicates.SetWhereClause(clause);
    }
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SMART));
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::GROUP_PHOTO));
    MediaLibraryRdbStore::Update(values, rdbPredicates);
}

static string BuildUpdateGroupPhotoAlbumSql(const GroupPhotoAlbumInfo &albumInfo)
{
    string withSql;
    string coverUriValueSql;
    string isCoverSatisfiedValueSql;
    if (albumInfo.isCoverSatisfied == ALBUM_COVER_NOT_SATISFIED) {
        coverUriValueSql = "'" + albumInfo.candidateUri + "'";
        isCoverSatisfiedValueSql = to_string(ALBUM_COVER_NOT_SATISFIED);
    } else {
        string oldCoverId = ParseFileIdFromCoverUri(albumInfo.coverUri);
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
                to_string(albumInfo.isCoverSatisfied) + " ELSE " + to_string(ALBUM_COVER_NOT_SATISFIED) + " END";
        } else {
            coverUriValueSql = "'" + albumInfo.candidateUri + "'";
            isCoverSatisfiedValueSql = to_string(ALBUM_COVER_NOT_SATISFIED);
        }
    }
    string updateSql = withSql + " UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_COUNT + " = " + to_string(albumInfo.count) + ", " +
        IS_ME + " = " + to_string(albumInfo.isMe) + ", " +
        PhotoAlbumColumns::ALBUM_COVER_URI + " = " + coverUriValueSql + ", " +
        IS_COVER_SATISFIED + " = " + isCoverSatisfiedValueSql +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumInfo.albumId) + ";";
    return updateSql;
}

static void UpdateGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &updateAlbums)
{
    ClearEmptyGroupPhotoAlbumInfo(updateAlbums);
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    for (auto album : updateAlbums) {
        string sql = BuildUpdateGroupPhotoAlbumSql(album);
        auto ret = uniStore->ExecuteSql(sql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Update group photo album failed! Error: %{public}d", ret);
        }
    }
}

static void InsertGroupPhotoAlbumInfo(const vector<GroupPhotoAlbumInfo> &insertAlbums)
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
        values.Put(IS_ME, album.isMe);
        values.Put(IS_LOCAL, LOCAL_ALBUM);
        values.Put(IS_COVER_SATISFIED, ALBUM_COVER_NOT_SATISFIED);
        insertValues.push_back(values);
    }
    Uri uri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(uri);
    MediaLibraryDataManager::GetInstance()->BatchInsert(cmd, insertValues);
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
        MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_NAME +
        ", COUNT (DISTINCT " + MediaColumn::MEDIA_ID + ") AS " + GROUP_PHOTO_COUNT + ", " + queryGroupPhotoIsMe +
        ", MAX(" + MediaColumn::MEDIA_DATE_ADDED + ") FROM (" + groupPhotoTagSql + ") AS GP " +
        leftJoinAnalysisAlbum + " GROUP BY " + GROUP_PHOTO_TAG + ";";
    return fullSql;
}

static void UpdateGroupPhotoAlbum()
{
    const string &querySql = GetGroupPhotoAlbumSql();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        return;
    }

    vector<GroupPhotoAlbumInfo> updateAlbums;
    vector<GroupPhotoAlbumInfo> insertAlbums;
    while (resultSet->GoToNextRow() == E_OK) {
        string tagId = GetStringVal(GROUP_PHOTO_TAG, resultSet);
        int32_t isCoverSatisfied = GetInt32Val(IS_COVER_SATISFIED, resultSet);
        int32_t count = GetInt32Val(GROUP_PHOTO_COUNT, resultSet);
        int32_t isMe = GetInt32Val(GROUP_PHOTO_IS_ME, resultSet);
        int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        string coverUri = GetStringVal(PhotoAlbumColumns::ALBUM_COVER_URI, resultSet);
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        string path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        string candidateUri = GetCoverUri(fileId, path, displayName);
        GroupPhotoAlbumInfo info {albumId, tagId, coverUri, isCoverSatisfied, count, fileId, candidateUri, isMe};
        if (albumId == ALBUM_NOT_FOUND) {
            insertAlbums.push_back(info);
        } else {
            updateAlbums.push_back(info);
        }
    }

    UpdateGroupPhotoAlbumInfo(updateAlbums);
    InsertGroupPhotoAlbumInfo(insertAlbums);
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(
    MediaLibraryCommand &cmd, const std::vector<std::string> &columns)
{
    UpdateGroupPhotoAlbum();
    auto whereClause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    auto whereArgs = cmd.GetAbsRdbPredicates()->GetWhereArgs();
    RdbPredicates rdbPredicates(ANALYSIS_ALBUM_TABLE);
    string clause = PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SMART) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::GROUP_PHOTO) + " AND " +
        IS_REMOVED + " IS NOT " + to_string(ALBUM_IS_REMOVED);
    if (whereClause.find(IS_ME) != string::npos) {
        int32_t value = GetPortraitSubtype(IS_ME, whereClause, whereArgs);
        if (value == QUERY_GROUP_PHOTO_ALBUM_RELATED_TO_ME) {
            clause += " AND " + IS_ME + " = " + to_string(ALBUM_IS_ME);
        }
    }
    rdbPredicates.SetWhereClause(clause);
    rdbPredicates.OrderByDesc(RENAME_OPERATION);
    rdbPredicates.OrderByDesc("(SELECT LENGTH(" + TAG_ID + ") - LENGTH([REPLACE](" + TAG_ID + ", ',', '')))");
    return MediaLibraryRdbStore::Query(rdbPredicates, columns);
}

static int32_t GetMergeAlbumCoverUri(MergeAlbumInfo &updateAlbumInfo, const MergeAlbumInfo &currentAlbum,
    const MergeAlbumInfo &targetAlbum)
{
    string currentFileId = ParseFileIdFromCoverUri(currentAlbum.coverUri);
    string targetFileId = ParseFileIdFromCoverUri(targetAlbum.coverUri);
    if (currentFileId.empty() || targetFileId.empty()) {
        return E_DB_FAIL;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query get merge album cover uri");
        return E_DB_FAIL;
    }
    string candidateIds;
    if (currentAlbum.isCoverSatisfied == targetAlbum.isCoverSatisfied) {
        candidateIds = currentFileId + ", " + targetFileId;
    } else {
        candidateIds = currentAlbum.isCoverSatisfied == ALBUM_COVER_SATISFIED ? currentFileId : targetFileId;
    }
    const std::string queryAlbumInfo = "SELECT " + MediaColumn::MEDIA_ID + "," + MediaColumn::MEDIA_TITLE + "," +
        MediaColumn::MEDIA_NAME + ", MAX(" + MediaColumn::MEDIA_DATE_ADDED + ") FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_ID + " IN (" + candidateIds + " )";

    auto resultSet = uniStore->QuerySql(queryAlbumInfo);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is nullptr! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }
    int mergeFileId;
    if (GetIntValueFromResultSet(resultSet, MediaColumn::MEDIA_ID, mergeFileId) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }

    string mergeTitle;
    if (GetStringValueFromResultSet(resultSet, MediaColumn::MEDIA_TITLE, mergeTitle) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }

    string mergeDisplayName;
    if (GetStringValueFromResultSet(resultSet, MediaColumn::MEDIA_NAME, mergeDisplayName) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }
    updateAlbumInfo.coverUri = "file://media/Photo/" + to_string(mergeFileId) + "/" + mergeTitle + "/" +
        mergeDisplayName;
    return E_OK;
}

int32_t UpdateForMergeGroupAlbums(const shared_ptr<MediaLibraryUnistore> &store, const vector<int> &deleteId,
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
            COVER_URI + " = '" + it.second.coverUri + "', " + IS_REMOVED + " = 0, " + IS_COVER_SATISFIED  + " = " +
            to_string(it.second.isCoverSatisfied) + " WHERE " + ALBUM_ID + " = " + to_string(it.second.albumId);
        updateSqls.push_back(sql);
    }
    return ExecSqls(updateSqls, store);
}

string ReorderTagId(string target, const vector<MergeAlbumInfo> &mergeAlbumInfo)
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
        string temp = strs.substr(0, pos);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(pattern);
        if (temp.compare(mergeAlbumInfo[0].groupTag) != 0 && temp.compare(mergeAlbumInfo[1].groupTag) != 0) {
            splitResult.push_back(temp);
        }
    }
    if (splitResult.empty()) {
        return reordererTagId;
    }
    string newTagId = mergeAlbumInfo[0].groupTag + "|" + mergeAlbumInfo[1].groupTag;
    splitResult.push_back(newTagId);
    std::sort(splitResult.begin(), splitResult.end());
    for (auto tagId : splitResult) {
        reordererTagId += (tagId + ",");
    }
    reordererTagId = reordererTagId.substr(0, reordererTagId.size() - 1);
    return reordererTagId;
}

int32_t MediaLibraryAnalysisAlbumOperations::UpdateMergeGroupAlbumsInfo(const vector<MergeAlbumInfo> &mergeAlbumInfo)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr! Query album order failed.");
        return E_DB_FAIL;
    }
    string queryTagId = "SELECT " + ALBUM_ID + ", " + COVER_URI + ", " + IS_COVER_SATISFIED + ", " + TAG_ID +
        " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_SUBTYPE + " = " + to_string(GROUP_PHOTO) +
        " AND (INSTR(" + TAG_ID + ", '" + mergeAlbumInfo[0].groupTag + "') > 0 OR INSTR(" + TAG_ID + ", '" +
        mergeAlbumInfo[1].groupTag + "') > 0)";
    auto resultSet = uniStore->QuerySql(queryTagId);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }

    std::vector<int> deleteId;
    std::unordered_map<string, MergeAlbumInfo> updateMap;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        MergeAlbumInfo info;
        if (GetIntValueFromResultSet(resultSet, ALBUM_ID, info.albumId) != E_OK ||
            GetStringValueFromResultSet(resultSet, TAG_ID, info.tagId) != E_OK  ||
            GetStringValueFromResultSet(resultSet, COVER_URI, info.coverUri) != E_OK ||
            GetIntValueFromResultSet(resultSet, IS_COVER_SATISFIED, info.isCoverSatisfied) != E_OK) {
            return E_HAS_DB_ERROR;
        }
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
            updateMap[reorderedTagId].isCoverSatisfied = static_cast<uint32_t>(info.isCoverSatisfied) |
                it->second.isCoverSatisfied;
            updateMap[reorderedTagId].coverUri = newInfo.coverUri;
            deleteId.push_back(info.albumId);
        }
    }
    return UpdateForMergeGroupAlbums(uniStore, deleteId, updateMap);
}

/**
 * set target group photo album name
 * @param values album_name
 * @param predicates target group photo album
 */
int32_t SetGroupAlbumName(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for set album name");
        return E_DB_FAIL;
    }
    string albumName;
    int err = GetStringVal(values, ALBUM_NAME, albumName);
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

/**
 * set target group photo album uri
 * @param values cover_uri
 * @param predicates target group photo album
 */
int32_t SetGroupCoverUri(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for set album cover uri");
        return E_DB_FAIL;
    }
    string coverUri;
    int err = GetStringVal(values, COVER_URI, coverUri);
    if (err < 0 || coverUri.empty()) {
        MEDIA_ERR_LOG("invalid album cover uri");
        return E_INVALID_VALUES;
    }
    std::string updateForSetCoverUri = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + COVER_URI + " = '" +
        coverUri + "', " + IS_COVER_SATISFIED + " = " + to_string(ALBUM_COVER_SATISFIED) + " WHERE " +
        ALBUM_ID + " = " + targetAlbumId;
    vector<string> updateSqls = { updateForSetCoverUri };
    err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyGroupAlbum(changeAlbumIds);
    }
    return err;
}

/**
 * set target group photo album is removed
 * @param values is_removed
 * @param predicates target group photo album
 */
int32_t DismissGroupPhotoAlbum(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for set album cover uri");
        return E_DB_FAIL;
    }
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
} // namespace OHOS::Media
