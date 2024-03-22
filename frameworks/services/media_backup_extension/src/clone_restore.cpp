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

#define MLOG_TAG "MediaLibraryCloneRestore"

#include "clone_restore.h"

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"

using namespace std;
namespace OHOS {
namespace Media {
const string MEDIA_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const unordered_map<string, unordered_set<string>> NEEDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE, 
        {
            MediaColumn::MEDIA_ID,
            MediaColumn::MEDIA_FILE_PATH,
            MediaColumn::MEDIA_SIZE,
            MediaColumn::MEDIA_TYPE,
            MediaColumn::MEDIA_NAME,
        }},
    { PhotoAlbumColumns::TABLE,  
        {
            PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_TYPE,
            PhotoAlbumColumns::ALBUM_SUBTYPE,
            PhotoAlbumColumns::ALBUM_NAME,
        }},
    { PhotoMap::TABLE,
        {
            PhotoMap::ALBUM_ID,
            PhotoMap::ASSET_ID,
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_TYPE,
            PhotoAlbumColumns::ALBUM_SUBTYPE,
            PhotoAlbumColumns::ALBUM_NAME,
        }},
    { ANALYSIS_PHOTO_MAP_TABLE,
        {
            PhotoMap::ALBUM_ID,
            PhotoMap::ASSET_ID,
        }},
};
const unordered_map<string, unordered_set<string>> EXCLUDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE, 
        {
            PhotoColumn::PHOTO_CLOUD_ID, PhotoColumn::PHOTO_DIRTY, PhotoColumn::PHOTO_META_DATE_MODIFIED,
            PhotoColumn::PHOTO_SYNC_STATUS, PhotoColumn::PHOTO_CLOUD_VERSION, PhotoColumn::PHOTO_POSITION,
            PhotoColumn::PHOTO_THUMB_STATUS, PhotoColumn::PHOTO_CLEAN_FLAG, // cloud related
            PhotoColumn::PHOTO_HAS_ASTC, // astc related
        }},
    { PhotoAlbumColumns::TABLE,  
        {
            PhotoAlbumColumns::ALBUM_COVER_URI, PhotoAlbumColumns::ALBUM_COUNT, PhotoAlbumColumns::CONTAINS_HIDDEN,
            PhotoAlbumColumns::HIDDEN_COUNT, PhotoAlbumColumns::HIDDEN_COVER, PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
            PhotoAlbumColumns::ALBUM_VIDEO_COUNT, // updated by album udpate
            PhotoAlbumColumns::ALBUM_DIRTY, PhotoAlbumColumns::ALBUM_CLOUD_ID, // cloud related
            PhotoAlbumColumns::ALBUM_ORDER, // created by trigger
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            PhotoAlbumColumns::ALBUM_COVER_URI,
            PhotoAlbumColumns::ALBUM_COUNT,
        }},
};
const unordered_map<string, unordered_map<string, string>> TABLE_QUERY_WHERE_CLAUSE_MAP = {
    { PhotoColumn::PHOTOS_TABLE, 
        {
            { PhotoColumn::PHOTO_POSITION, PhotoColumn::PHOTO_POSITION + " IN (1, 3)" },
        }},
    { PhotoAlbumColumns::TABLE,  
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumColumns::ALBUM_TYPE + " != " +
                to_string(PhotoAlbumType::SYSTEM)},
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumColumns::ALBUM_SUBTYPE + " IN (" +
                to_string(PhotoAlbumSubType::SHOOTING_MODE) + ")" },
        }},
};
const vector<string> CLONE_ALBUMS = { PhotoAlbumColumns::TABLE, ANALYSIS_ALBUM_TABLE };
const unordered_map<string, string> CLONE_ALBUM_MAP = {
    { PhotoAlbumColumns::TABLE, PhotoMap::TABLE },
    { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE },
};
const vector<vector<string>> CLONE_TABLE_LISTS = {
    { PhotoColumn::PHOTOS_TABLE },
    { PhotoAlbumColumns::TABLE, PhotoMap::TABLE },
    { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE },
};
const unordered_map<string, ResultSetDataType> COLUMN_TYPE_MAP = {
    { "INT", ResultSetDataType::TYPE_INT32 },
    { "INTEGER", ResultSetDataType::TYPE_INT32 },
    { "BIGINT", ResultSetDataType::TYPE_INT64 },
    { "DOUBLE", ResultSetDataType::TYPE_DOUBLE },
    { "TEXT", ResultSetDataType::TYPE_STRING },
};

template<typename Key, typename Value>
Value GetValueFromMap(const unordered_map<Key, Value> &map, const Key &key, const Value &defaultValue = Value())
{
    auto it = map.find(key);
    if (it == map.end()) {
        return defaultValue;
    }
    return it->second;
}

void CloneRestore::StartRestore(const string &backupRetoreDir, const string &upgradePath)
{
    int32_t errorCode = Init(backupRetoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        CheckTableColumnStatus();
        RestoreAlbum();
        RestorePhoto();
        MEDIA_INFO_LOG("migrate database photo number: %{public}lld, file number: %{public}lld, album number: "
            "%{public}lld, map number: %{public}lld", (long long)migrateDatabaseNumber_, (long long)migrateFileNumber_,
            (long long)migrateDatabaseAlbumNumber_, (long long)migrateDatabaseMapNumber_);
        unordered_map<int32_t, int32_t> updateResult;
        MediaLibraryRdbUtils::UpdateAllAlbums(mediaLibraryRdb_, updateResult);
    }
    HandleRestData();
}

int32_t CloneRestore::Init(const string &backupRetoreDir, const string &upgradePath, bool isUpgrade)
{
    dbPath_ = BACKUP_RESTORE_DIR + MEDIA_DB_PATH;
    filePath_ = BACKUP_RESTORE_DIR + "/storage/cloud/files";
    if (!MediaFileUtils::IsFileExists(dbPath_)) {
        MEDIA_ERR_LOG("Media db is not exist.");
        return E_FAIL;
    }
    if (isUpgrade && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }
    int32_t err = BackupDatabaseUtils::InitDb(mediaRdb_, MEDIA_DATA_ABILITY_DB_NAME, dbPath_, BUNDLE_NAME, true);
    if (mediaRdb_ == nullptr) {
        MEDIA_ERR_LOG("Init remote medialibrary rdb fail, err = %{public}d", err);
        return E_FAIL;
    }
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void CloneRestore::RestorePhoto(void)
{
    if (!IsReadyForRestore(PhotoColumn::PHOTOS_TABLE)) {
        MEDIA_ERR_LOG("Column status is not ready for restore photo, quit");
        return;
    }
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_,
        PhotoColumn::PHOTOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
        PhotoColumn::PHOTOS_TABLE);
    if (!PrepareCommonColumnInfoMap(PhotoColumn::PHOTOS_TABLE, srcColumnInfoMap, dstColumnInfoMap)) {
        MEDIA_ERR_LOG("Prepare common column info failed");
        return;
    }
    int32_t totalNumber = QueryTotalNumber();
    MEDIA_INFO_LOG("QueryTotalNumber, totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        vector<FileInfo> fileInfos = QueryFileInfos(offset);
        InsertPhoto(fileInfos);
        BatchNotifyPhoto(fileInfos);
    }
    (void)NativeRdb::RdbHelper::DeleteRdbStore(dbPath_);
}

void CloneRestore::RestoreAlbum(void)
{
    for (const auto &tableName : CLONE_ALBUMS) {
        if (!IsReadyForRestore(tableName)) {
            MEDIA_ERR_LOG("Column status of %{private}s is not ready for restore album, quit", tableName.c_str());
            continue;
        }
        unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
        unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
            tableName);
        if (!PrepareCommonColumnInfoMap(tableName, srcColumnInfoMap, dstColumnInfoMap)) {
            MEDIA_ERR_LOG("Prepare common column info failed");
            return;
        }
        GetAlbumExtraQueryWhereClause(tableName);
        int32_t totalNumber = QueryAlbumTotalNumber(tableName);
        MEDIA_INFO_LOG("QueryAlbumTotalNumber, totalNumber = %{public}d", totalNumber);
        for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
            vector<AlbumInfo> albumInfos = QueryAlbumInfos(tableName, offset);
            InsertAlbum(albumInfos, tableName);
        }
    }
}

void CloneRestore::InsertPhoto(vector<FileInfo> &fileInfos)
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startInsertPhoto = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(CLONE_RESTORE_ID, fileInfos, SourceType::PHOTOS);
    int64_t photoRowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, photoRowNum);
    if (errCode != E_OK) {
        return;
    }
    migrateDatabaseNumber_ += photoRowNum;

    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryPhoto(fileInfos);
    int64_t startInsertMap = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t mapRowNum = 0;
    BatchInsertMap(fileInfos, mapRowNum);
    migrateDatabaseMapNumber_ += mapRowNum;

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t fileMoveCount = 0;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath) || fileInfos[i].cloudPath.empty()) {
            continue;
        }
        if (MoveSingleFile(fileInfos[i]) != E_OK) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, CLONE_RESTORE_ID).c_str());
            continue;
        }
        fileMoveCount++;
    }
    migrateFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("insert %{public}ld assets cost %{public}ld, query cost %{public}ld, insert %{public}ld maps "
        "cost %{public}ld, and move %{public}ld files cost %{public}ld.", (long)photoRowNum,
        (long)(startQuery - startInsertPhoto), (long)(startInsertMap - startQuery), (long)mapRowNum,
        (long)(startMove - startInsertMap), (long)fileMoveCount, (long)(end - startMove));
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(int32_t sceneCode, vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        fileInfos[i].cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfos[i].relativePath);
        if (fileInfos[i].cloudPath.empty()) {
            MEDIA_ERR_LOG("Get cloudPath empty");
            continue;
        }
        if (IsSameFile(fileInfos[i])) {
            (void)MediaFileUtils::DeleteFile(fileInfos[i].filePath);
            MEDIA_WARN_LOG("File %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        if (MediaFileUtils::IsFileExists(fileInfos[i].cloudPath) && BackupFileUtils::CreatePath(fileInfos[i].fileType,
            fileInfos[i].displayName, fileInfos[i].cloudPath) != E_OK) {
            MEDIA_ERR_LOG("Destination file path %{public}s exists, create new path failed",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        if (BackupFileUtils::PreparePath(fileInfos[i].cloudPath) != E_OK) {
            MEDIA_ERR_LOG("Prepare cloudPath failed");
            fileInfos[i].cloudPath.clear();
            continue;
        }
        NativeRdb::ValuesBucket value = GetInsertValue(fileInfos[i], fileInfos[i].cloudPath, sourceType);
        fileInfos[i].isNew = true;
        values.emplace_back(value);
    }
    return values;
}

void CloneRestore::HandleRestData(void)
{}

int32_t CloneRestore::QueryTotalNumber(void)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + PhotoColumn::PHOTOS_TABLE;
    if (tableQueryWhereClauseMap_.count(PhotoColumn::PHOTOS_TABLE)) {
        querySql += " WHERE " + tableQueryWhereClauseMap_.at(PhotoColumn::PHOTOS_TABLE);
    }
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    return result;
}

vector<FileInfo> CloneRestore::QueryFileInfos(int32_t offset)
{
    vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    string querySql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE;
    if (tableQueryWhereClauseMap_.count(PhotoColumn::PHOTOS_TABLE)) {
        querySql += " WHERE " + tableQueryWhereClauseMap_.at(PhotoColumn::PHOTOS_TABLE);
    }
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        if (ParseResultSet(resultSet, fileInfo)) {
            QueryTableAlbumSetMap(fileInfo);
            result.emplace_back(fileInfo);
        }
    }
    return result;
}

bool CloneRestore::ParseResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo)
{
    // only parse image and video
    string oldPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (!ConvertPathToRealPath(oldPath, filePath_, fileInfo.filePath, fileInfo.relativePath)) {
        return false;
    }

    fileInfo.fileIdOld = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    fileInfo.fileSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultSet);
    fileInfo.fileType =  GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    fileInfo.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    
    auto commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, PhotoColumn::PHOTOS_TABLE);
    for (auto it = commonColumnInfoMap.begin(); it != commonColumnInfoMap.end(); ++it) {
        string columnName = it->first;
        string columnType = it->second;
        GetValFromResultSet(resultSet, fileInfo.valMap, columnName, columnType);
    }
    return true;
}

int32_t CloneRestore::QueryAlbumTotalNumber(const string &tableName)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName;
    if (tableQueryWhereClauseMap_.count(tableName)) {
        querySql += " WHERE " + tableQueryWhereClauseMap_.at(tableName);
    }
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    return result;
}

vector<AlbumInfo> CloneRestore::QueryAlbumInfos(const string &tableName, int32_t offset)
{
    vector<AlbumInfo> result;
    result.reserve(QUERY_COUNT);
    string querySql = "SELECT * FROM " + tableName;
    if (tableQueryWhereClauseMap_.count(tableName)) {
        querySql += " WHERE " + tableQueryWhereClauseMap_.at(tableName);
    }
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AlbumInfo albumInfo;
        if (ParseAlbumResultSet(tableName, resultSet, albumInfo)) {
            result.emplace_back(albumInfo);
        }
    }
    return result;
}

bool CloneRestore::ParseAlbumResultSet(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    AlbumInfo &albumInfo)
{
    albumInfo.albumIdOld = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    albumInfo.albumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
    albumInfo.albumType = static_cast<PhotoAlbumType>(GetInt32Val(PhotoAlbumColumns::ALBUM_TYPE, resultSet));
    albumInfo.albumSubType = static_cast<PhotoAlbumSubType>(GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet));
    
    auto commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = commonColumnInfoMap.begin(); it != commonColumnInfoMap.end(); ++it) {
        string columnName = it->first;
        string columnType = it->second;
        GetValFromResultSet(resultSet, albumInfo.valMap, columnName, columnType);
    }
    return true;
}

void CloneRestore::AnalyzeSource()
{
    MEDIA_INFO_LOG("analyze source later");
}

int32_t CloneRestore::MoveSingleFile(FileInfo &fileInfo)
{
    string localPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL, fileInfo.relativePath);
    if (MoveFile(fileInfo.filePath, localPath) != E_OK) {
        MEDIA_ERR_LOG("Move photo file failed");
        return E_FAIL;
    }
    
    string srcEditDataPath = BACKUP_RESTORE_DIR +
        BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD_EDIT_DATA, fileInfo.relativePath);
    string dstEditDataPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL_EDIT_DATA,
        fileInfo.relativePath);
    if (IsFilePathExist(srcEditDataPath) && MoveDirectory(srcEditDataPath, dstEditDataPath) != E_OK) {
        MEDIA_ERR_LOG("Move editData file failed");
        return E_FAIL;
    }
    return E_OK;
}

bool CloneRestore::IsFilePathExist(const string &filePath)
{
    if (!MediaFileUtils::IsFileExists(filePath)) {
        MEDIA_ERR_LOG("%{private}s doesn't exist", filePath.c_str());
        return false;
    }
    if (MediaFileUtils::IsDirectory(filePath) && MediaFileUtils::IsDirEmpty(filePath)) {
        MEDIA_ERR_LOG("%{private}s is an empty directory", filePath.c_str());
        return false;
    }
    return true;
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const FileInfo &fileInfo, const string &newPath,
    int32_t sourceType) const
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);

    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, 
        PhotoColumn::PHOTOS_TABLE);
    for (auto it = fileInfo.valMap.begin(); it != fileInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    return values;
}

bool CloneRestore::PrepareCommonColumnInfoMap(const string &tableName,
    const unordered_map<string, string> &srcColumnInfoMap, const unordered_map<string, string> &dstColumnInfoMap)
{
    auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
    auto excludedColumns = GetValueFromMap(EXCLUDED_COLUMNS_MAP, tableName);
    auto &commonColumnInfoMap = tableCommonColumnInfoMap_[tableName];
    if (!HasColumns(dstColumnInfoMap, neededColumns)) {
        MEDIA_ERR_LOG("Destination lack needed columns");
        return false;
    }
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        if (!HasSameColumn(srcColumnInfoMap, it->first, it->second) || neededColumns.count(it->first) > 0 ||
            excludedColumns.count(it->first) > 0) {
            continue;
        }
        commonColumnInfoMap[it->first] = it->second;
    }
    MEDIA_INFO_LOG("Table %{private}s has %{public}zu common columns", tableName.c_str(), commonColumnInfoMap.size());
    return true;
}

bool CloneRestore::HasSameColumn(const unordered_map<string, string> &columnInfoMap, const string &columnName,
    const string &columnType)
{
    auto it = columnInfoMap.find(columnName);
    return it != columnInfoMap.end() && it->second == columnType;
}

void CloneRestore::GetValFromResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet,
    unordered_map<string, variant<int32_t, int64_t, double, string>> &valMap, const string &columnName,
    const string &columnType)
{
    int32_t columnIndex = 0;
    int32_t errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    if (errCode) {
        MEDIA_ERR_LOG("Get column index errCode: %{public}d", errCode);
        return;
    }
    bool isNull = false;
    errCode = resultSet->IsColumnNull(columnIndex, isNull);
    if (errCode || isNull) {
        return;
    }
    ResultSetDataType dataType = GetValueFromMap(COLUMN_TYPE_MAP, columnType, ResultSetDataType::TYPE_NULL);
    switch (dataType) {
        case ResultSetDataType::TYPE_INT32: {
            int32_t int32Val;
            if (resultSet->GetInt(columnIndex, int32Val) == E_OK) {
                valMap[columnName] = int32Val;
            }
            break;
        }
        case ResultSetDataType::TYPE_INT64: {
            int64_t int64Val;
            if (resultSet->GetLong(columnIndex, int64Val) == E_OK) {
                valMap[columnName] = int64Val;
            }
            break;
        }
        case ResultSetDataType::TYPE_DOUBLE: {
            double doubleVal;
            if (resultSet->GetDouble(columnIndex, doubleVal) == E_OK) {
                valMap[columnName] = doubleVal;
            }
            break;
        }
        case ResultSetDataType::TYPE_STRING: {
            string stringVal;
            if (resultSet->GetString(columnIndex, stringVal) == E_OK) {
                valMap[columnName] = stringVal;
            }
            break;
        }
        default:
            MEDIA_ERR_LOG("No such column type: %{public}s", columnType.c_str());
    }
}

void CloneRestore::PrepareCommonColumnVal(NativeRdb::ValuesBucket &values, const string &columnName,
    const variant<int32_t, int64_t, double, string> &columnVal,
    const unordered_map<string, string> &commonColumnInfoMap) const
{
    string columnType = GetValueFromMap(commonColumnInfoMap, columnName);
    if (columnType.empty()) {
        MEDIA_ERR_LOG("No such column %{public}s", columnName.c_str());
        return;
    }
    ResultSetDataType dataType = GetValueFromMap(COLUMN_TYPE_MAP, columnType, ResultSetDataType::TYPE_NULL);
    switch (dataType) {
        case ResultSetDataType::TYPE_INT32: {
            values.PutInt(columnName, get<int32_t>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_INT64: {
            values.PutLong(columnName, get<int64_t>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_DOUBLE: {
            values.PutDouble(columnName, get<double>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_STRING: {
            values.PutString(columnName, get<string>(columnVal));
            break;
        }
        default:
            MEDIA_ERR_LOG("No such column type: %{public}s", columnType.c_str());
    }
}

void CloneRestore::GetQueryWhereClause(const string &tableName, const unordered_map<string, string> &columnInfoMap)
{
    auto queryWhereClauseMap = GetValueFromMap(TABLE_QUERY_WHERE_CLAUSE_MAP, tableName);
    string &queryWhereClause = tableQueryWhereClauseMap_[tableName];
    queryWhereClause.clear();
    for (auto it = queryWhereClauseMap.begin(); it != queryWhereClauseMap.end(); ++it) {
        if (columnInfoMap.count(it->first) == 0) {
            continue;
        }
        if (!queryWhereClause.empty()) {
            queryWhereClause += " AND ";
        }
        queryWhereClause += it->second + " ";
    }
}

void CloneRestore::GetAlbumExtraQueryWhereClause(const string &tableName)
{
    string mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
    if (mapTableName.empty()) {
        MEDIA_ERR_LOG("Get map for table %{private}s failed", tableName.c_str());
        return;
    }
    string &albumQueryWhereClause = tableQueryWhereClauseMap_[tableName];
    if (!albumQueryWhereClause.empty()) {
        albumQueryWhereClause += " AND ";
    }
    albumQueryWhereClause += "EXISTS (SELECT " + PhotoMap::ASSET_ID + " FROM " + mapTableName + " WHERE " +
        PhotoMap::ALBUM_ID + " = " + PhotoAlbumColumns::ALBUM_ID + " AND EXISTS (SELECT " + MediaColumn::MEDIA_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    string photoQueryWhereClause = GetValueFromMap(tableQueryWhereClauseMap_, PhotoColumn::PHOTOS_TABLE);
    if (!photoQueryWhereClause.empty()) {
        albumQueryWhereClause += " AND " + photoQueryWhereClause;
    }
    albumQueryWhereClause += "))";
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const AlbumInfo &albumInfo, const string &tableName) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, static_cast<int32_t>(albumInfo.albumType));
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, static_cast<int32_t>(albumInfo.albumSubType));
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumInfo.albumName);

    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = albumInfo.valMap.begin(); it != albumInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    return values;
}

void CloneRestore::QueryTableAlbumSetMap(FileInfo &fileInfo)
{
    for (const auto &tableName : CLONE_ALBUMS) {
        auto mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
        if (mapTableName.empty()) {
            MEDIA_ERR_LOG("Get map for table %{private}s failed", tableName.c_str());
            return;
        }
        auto albumIdMap = GetValueFromMap(tableAlbumIdMap_, tableName);
        auto &albumSet = fileInfo.tableAlbumSetMap[tableName];
        string querySql = "SELECT " + PhotoMap::ALBUM_ID + " FROM " + mapTableName + " WHERE " + PhotoMap::ASSET_ID +
            " = " + to_string(fileInfo.fileIdOld);
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            return;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t albumIdOld = GetInt32Val(PhotoMap::ALBUM_ID, resultSet);
            if (albumIdOld <= 0 || albumIdMap.count(albumIdOld) == 0) {
                continue;
            }
            int32_t albumIdNew = albumIdMap.at(albumIdOld);
            albumSet.insert(albumIdNew);
        }
    }
}

void CloneRestore::BatchQueryPhoto(vector<FileInfo> &fileInfos)
{
    for (auto &fileInfo : fileInfos) {
        if (fileInfo.cloudPath.empty()) {
            continue;
        }
        string querySql = "SELECT " + MediaColumn::MEDIA_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
            MediaColumn::MEDIA_FILE_PATH + " = '" + fileInfo.cloudPath + "'";
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            continue;
        }
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        if (fileId <= 0) {
            MEDIA_ERR_LOG("Get fileId invalid: %{public}d", fileId);
            continue;
        }
        fileInfo.fileIdNew = fileId;
    }
}

void CloneRestore::BatchNotifyPhoto(const vector<FileInfo> &fileInfos)
{
    auto watch = MediaLibraryNotify::GetInstance();
    for (const auto &fileInfo : fileInfos) {
        if (!fileInfo.isNew || fileInfo.cloudPath.empty()) {
            continue;
        }
        string extraUri = MediaFileUtils::GetExtraUri(fileInfo.displayName, fileInfo.cloudPath);
        string notifyUri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX,
            to_string(fileInfo.fileIdNew), extraUri);
        watch->Notify(notifyUri, NotifyType::NOTIFY_ADD);
    }
}

bool CloneRestore::IsSameFile(FileInfo &fileInfo)
{
    string srcPath = fileInfo.filePath;
    string dstPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL, fileInfo.relativePath);
    struct stat srcStatInfo {};
    struct stat dstStatInfo {};

    if (access(srcPath.c_str(), F_OK) || access(dstPath.c_str(), F_OK)) {
        return false;
    }
    if (stat(srcPath.c_str(), &srcStatInfo) != 0) {
        MEDIA_ERR_LOG("Failed to get file %{private}s StatInfo, err=%{public}d", srcPath.c_str(), errno);
        return false;
    }
    if (stat(dstPath.c_str(), &dstStatInfo) != 0) {
        MEDIA_ERR_LOG("Failed to get file %{private}s StatInfo, err=%{public}d", dstPath.c_str(), errno);
        return false;
    }
    if (fileInfo.fileSize != srcStatInfo.st_size) {
        MEDIA_ERR_LOG("Internal error");
        return false;
    }
    if (srcStatInfo.st_size != dstStatInfo.st_size) { /* file size */
        MEDIA_INFO_LOG("Size differs, %{public}lld != %{public}lld", (long long)srcStatInfo.st_size,
            (long long)dstStatInfo.st_size);
        return false;
    }
    if (srcStatInfo.st_mtime != dstStatInfo.st_mtime && !HasSameFile(fileInfo)) { /* last motify time */
        MEDIA_INFO_LOG("Mtime differs, %{public}lld != %{public}lld", (long long)srcStatInfo.st_mtime,
            (long long)dstStatInfo.st_mtime);
        return false;
    }
    return true;
}

bool CloneRestore::HasSameFile(FileInfo &fileInfo)
{
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_NAME + " = '" + fileInfo.displayName + "' AND " +
        MediaColumn::MEDIA_SIZE + " = " + to_string(fileInfo.fileSize);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (fileId <= 0 || cloudPath.empty()) {
        MEDIA_ERR_LOG("Get invalid fileId or cloudPath: %{public}d", fileId);
        return false;
    }
    fileInfo.fileIdNew = fileId;
    fileInfo.cloudPath = cloudPath;
    return true;
}

void CloneRestore::InsertAlbum(vector<AlbumInfo> &albumInfos, const string &tableName)
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (albumInfos.empty()) {
        MEDIA_ERR_LOG("albumInfos are empty");
        return;
    }
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(albumInfos, tableName);
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    if (errCode != E_OK) {
        return;
    }
    migrateDatabaseAlbumNumber_ += rowNum;

    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryAlbum(albumInfos, tableName);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("insert %{public}ld albums cost %{public}ld, query cost %{public}ld.", (long)rowNum,
        (long)(startQuery - startInsert), (long)(end - startQuery));
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(vector<AlbumInfo> &albumInfos,
    const string &tableName)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < albumInfos.size(); i++) {
        if (HasSameAlbum(albumInfos[i], tableName)) {
            MEDIA_WARN_LOG("Album (%{public}d, %{public}d, %{public}d, %{public}s) already exists.",
                albumInfos[i].albumIdOld, static_cast<int32_t>(albumInfos[i].albumType),
                static_cast<int32_t>(albumInfos[i].albumSubType), albumInfos[i].albumName.c_str());
            continue;
        }
        NativeRdb::ValuesBucket value = GetInsertValue(albumInfos[i], tableName);
        values.emplace_back(value);
    }
    return values;
}

bool CloneRestore::HasSameAlbum(const AlbumInfo &albumInfo, const string &tableName) const
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " +
        PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(albumInfo.albumType) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(albumInfo.albumSubType) + " AND " +
        PhotoAlbumColumns::ALBUM_NAME + " = '" + albumInfo.albumName + "'";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t count = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    return count > 0;    
}

void CloneRestore::BatchQueryAlbum(vector<AlbumInfo> &albumInfos, const string &tableName)
{
    auto &albumIdMap = tableAlbumIdMap_[tableName];
    for (auto &albumInfo : albumInfos) {
        string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + tableName + " WHERE " +
            PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(albumInfo.albumType) + " AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(albumInfo.albumSubType) + " AND " +
            PhotoAlbumColumns::ALBUM_NAME + " = '" + albumInfo.albumName + "'";
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            continue;
        }
        albumInfo.albumIdNew = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        if (albumInfo.albumIdNew <= 0) {
            continue;
        }
        albumIdMap[albumInfo.albumIdOld] = albumInfo.albumIdNew;
    }
}

void CloneRestore::BatchInsertMap(vector<FileInfo> &fileInfos, int64_t &totalRowNum)
{
    for (const auto &tableName : CLONE_ALBUMS) {
        string mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
        if (mapTableName.empty()) {
            MEDIA_ERR_LOG("Get map for table %{private}s failed", tableName.c_str());
            return;
        }
        vector<NativeRdb::ValuesBucket> values;
        for (const auto &fileInfo : fileInfos) {
            auto albumSet = GetValueFromMap(fileInfo.tableAlbumSetMap, tableName);
            for (auto albumIdNew : albumSet) {
                MapInfo mapInfo;
                mapInfo.albumId = albumIdNew;
                mapInfo.fileId = fileInfo.fileIdNew;
                NativeRdb::ValuesBucket value = GetInsertValue(mapInfo);
                values.emplace_back(value);
            }
        }
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry(mapTableName, values, rowNum);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Batch insert map failed, errCode: %{public}d", errCode);
        }
        totalRowNum += rowNum;
    }
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const MapInfo &mapInfo) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoMap::ASSET_ID, mapInfo.fileId);
    values.PutInt(PhotoMap::ALBUM_ID, mapInfo.albumId);
    return values;
}

void CloneRestore::CheckTableColumnStatus()
{
    unordered_map<string, unordered_map<string, string>> tableColumnInfoMap;
    for (const auto &tableList : CLONE_TABLE_LISTS) {
        bool columnStatusGlobal = true;
        for (const auto &tableName : tableList) {
            auto &columnInfoMap = tableColumnInfoMap[tableName];
            columnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_, tableName);
            auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
            columnStatusGlobal = columnStatusGlobal && HasColumns(columnInfoMap, neededColumns);
        }
        for (const auto &tableName : tableList) {
            tableColumnStatusMap_[tableName] = columnStatusGlobal;
        }
    }
    for (const auto &tableList : CLONE_TABLE_LISTS) {
        for (const auto &tableName : tableList) {
            if (!IsReadyForRestore(tableName)) {
                MEDIA_ERR_LOG("Column status is false");
                break;
            }
            auto columnInfoMap = GetValueFromMap(tableColumnInfoMap, tableName);
            GetQueryWhereClause(tableName, columnInfoMap);
        }
    }
}

bool CloneRestore::HasColumns(const unordered_map<string, string> &columnInfoMap,
    const unordered_set<string> &columnSet)
{
    for (const auto &columnName : columnSet) {
        if (!HasColumn(columnInfoMap, columnName)) {
            MEDIA_ERR_LOG("Lack of column %{public}s", columnName.c_str());
            return false;
        }
    }
    return true;
}

bool CloneRestore::HasColumn(const unordered_map<string, string> &columnInfoMap, const string &columnName)
{
    return columnInfoMap.count(columnName) > 0;
}

bool CloneRestore::IsReadyForRestore(const string &tableName)
{
    return GetValueFromMap(tableColumnStatusMap_, tableName, false);
}
} // namespace Media
} // namespace OHOS
