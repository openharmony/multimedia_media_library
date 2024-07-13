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

#include "application_context.h"
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "ffrt.h"
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

#ifdef CLOND_SYNC_MANAGER
#include "cloud_sync_manager.h"
#endif

using namespace std;
namespace OHOS {
namespace Media {
const int32_t CLONE_QUERY_COUNT = 200;
const int32_t SYSTEM_ALBUM_ID_START = 1;
const int32_t SYSTEM_ALBUM_ID_END = 7;
const string MEDIA_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const unordered_map<string, unordered_set<string>> NEEDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            MediaColumn::MEDIA_ID,
            MediaColumn::MEDIA_FILE_PATH,
            MediaColumn::MEDIA_SIZE,
            MediaColumn::MEDIA_TYPE,
            MediaColumn::MEDIA_NAME,
            MediaColumn::MEDIA_DATE_ADDED,
            MediaColumn::MEDIA_DATE_MODIFIED,
            PhotoColumn::PHOTO_ORIENTATION,
        }},
    { PhotoAlbumColumns::TABLE,
        {
            PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_TYPE,
            PhotoAlbumColumns::ALBUM_SUBTYPE,
            PhotoAlbumColumns::ALBUM_NAME,
            PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
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
    { AudioColumn::AUDIOS_TABLE,
        {
            MediaColumn::MEDIA_ID,
            MediaColumn::MEDIA_FILE_PATH,
            MediaColumn::MEDIA_SIZE,
            MediaColumn::MEDIA_TYPE,
            MediaColumn::MEDIA_NAME,
            MediaColumn::MEDIA_DATE_ADDED,
            MediaColumn::MEDIA_DATE_MODIFIED,
        }},
};
const unordered_map<string, unordered_set<string>> NEEDED_COLUMNS_EXCEPTION_MAP = {
    { PhotoAlbumColumns::TABLE,
        {
            PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
        }},
};
const unordered_map<string, unordered_set<string>> EXCLUDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            PhotoColumn::PHOTO_CLOUD_ID, PhotoColumn::PHOTO_DIRTY, PhotoColumn::PHOTO_META_DATE_MODIFIED,
            PhotoColumn::PHOTO_SYNC_STATUS, PhotoColumn::PHOTO_CLOUD_VERSION, PhotoColumn::PHOTO_POSITION,
            PhotoColumn::PHOTO_THUMB_STATUS, PhotoColumn::PHOTO_CLEAN_FLAG, // cloud related
            PhotoColumn::PHOTO_THUMBNAIL_READY, // astc related
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
const unordered_map<string, ResultSetDataType> COLUMN_TYPE_MAP = {
    { "INT", ResultSetDataType::TYPE_INT32 },
    { "INTEGER", ResultSetDataType::TYPE_INT32 },
    { "BIGINT", ResultSetDataType::TYPE_INT64 },
    { "DOUBLE", ResultSetDataType::TYPE_DOUBLE },
    { "TEXT", ResultSetDataType::TYPE_STRING },
};
const unordered_map<string, string> ALBUM_URI_PREFIX_MAP = {
    { PhotoAlbumColumns::TABLE, PhotoAlbumColumns::ALBUM_URI_PREFIX },
    { ANALYSIS_ALBUM_TABLE, PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX },
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

void CloneRestore::StartRestore(const string &backupRestoreDir, const string &upgradePath)
{
    MEDIA_INFO_LOG("Start clone restore");
    SetParameterForClone();
#ifdef CLOND_SYNC_MANAGER
    FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync("com.ohos.medialibrary.medialibrarydata");
#endif
    backupRestoreDir_ = backupRestoreDir;
    garbagePath_ = backupRestoreDir_ + "/storage/media/local/files";
    int32_t errorCode = Init(backupRestoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        RestoreGallery();
        RestoreMusic();
        (void)NativeRdb::RdbHelper::DeleteRdbStore(dbPath_);
    } else {
        SetErrorCode(RestoreError::INIT_FAILED);
    }
    HandleRestData();
    StopParameterForClone(CLONE_RESTORE_ID);
    MEDIA_INFO_LOG("End clone restore");
}

int32_t CloneRestore::Init(const string &backupRestoreDir, const string &upgradePath, bool isUpgrade)
{
    dbPath_ = backupRestoreDir_ + MEDIA_DB_PATH;
    filePath_ = backupRestoreDir_ + "/storage/media/local/files";
    if (!MediaFileUtils::IsFileExists(dbPath_)) {
        MEDIA_ERR_LOG("Media db is not exist.");
        return E_FAIL;
    }
    if (isUpgrade && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return E_FAIL;
    }
    int32_t err = BackupDatabaseUtils::InitDb(mediaRdb_, MEDIA_DATA_ABILITY_DB_NAME, dbPath_, BUNDLE_NAME, true,
        context->GetArea());
    if (mediaRdb_ == nullptr) {
        MEDIA_ERR_LOG("Init remote medialibrary rdb fail, err = %{public}d", err);
        return E_FAIL;
    }
    GetMaxFileId(mediaLibraryRdb_);
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void CloneRestore::RestorePhoto(void)
{
    MEDIA_INFO_LOG("Start clone restore: photos");
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
    for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestorePhotoBatch(offset); }, { &offset });
    }
    ffrt::wait();
}

void CloneRestore::RestoreAlbum(void)
{
    MEDIA_INFO_LOG("Start clone restore: albums");
    for (const auto &tableName : CLONE_ALBUMS) {
        if (!IsReadyForRestore(tableName)) {
            MEDIA_ERR_LOG("Column status of %{public}s is not ready for restore album, quit",
                BackupDatabaseUtils::GarbleInfoName(tableName).c_str());
            continue;
        }
        unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
        unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
            tableName);
        if (!PrepareCommonColumnInfoMap(tableName, srcColumnInfoMap, dstColumnInfoMap)) {
            MEDIA_ERR_LOG("Prepare common column info failed");
            continue;
        }
        GetAlbumExtraQueryWhereClause(tableName);
        int32_t totalNumber = QueryTotalNumber(tableName);
        MEDIA_INFO_LOG("QueryAlbumTotalNumber, totalNumber = %{public}d", totalNumber);
        for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
            vector<AlbumInfo> albumInfos = QueryAlbumInfos(tableName, offset);
            InsertAlbum(albumInfos, tableName);
        }
    }
}

void CloneRestore::MoveMigrateFile(std::vector<FileInfo> &fileInfos, int64_t &fileMoveCount,
    int64_t &videoFileMoveCount)
{
    vector<std::string> moveFailedData;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath) || fileInfos[i].cloudPath.empty()) {
            continue;
        }
        if (MoveAsset(fileInfos[i]) != E_OK) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s, error:%{public}s",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, CLONE_RESTORE_ID, garbagePath_).c_str(),
                strerror(errno));
            UpdateFailedFiles(fileInfos[i].fileType, BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL,
                fileInfos[i].relativePath), RestoreError::MOVE_FAILED);
            moveFailedData.push_back(fileInfos[i].cloudPath);
            continue;
        }
        fileMoveCount++;
        videoFileMoveCount += fileInfos[i].fileType == MediaType::MEDIA_TYPE_VIDEO;
    }
    DeleteMoveFailedData(moveFailedData);
    migrateFileNumber_ += fileMoveCount;
    migrateVideoFileNumber_ += videoFileMoveCount;
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
    int64_t startGenerate = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(CLONE_RESTORE_ID, fileInfos, SourceType::PHOTOS);
    int64_t startInsertPhoto = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t photoRowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, photoRowNum);
    if (errCode != E_OK) {
        UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
        return;
    }
    migrateDatabaseNumber_ += photoRowNum;

    int64_t startInsertRelated = MediaFileUtils::UTCTimeMilliSeconds();
    InsertPhotoRelated(fileInfos);

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t fileMoveCount = 0;
    int64_t videoFileMoveCount = 0;
    MoveMigrateFile(fileInfos, fileMoveCount, videoFileMoveCount);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate cost %{public}ld, insert %{public}ld assets cost %{public}ld, insert photo related cost "
        "%{public}ld, and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld.",
        (long)(startInsertPhoto - startGenerate), (long)photoRowNum, (long)(startInsertRelated - startInsertPhoto),
        (long)(startMove - startInsertRelated), (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(end - startMove));
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(int32_t sceneCode, vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!BackupFileUtils::IsFileValid(fileInfos[i].filePath, CLONE_RESTORE_ID)) {
            UpdateFailedFiles(fileInfos[i].fileType, BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL,
                fileInfos[i].relativePath), RestoreError::FILE_INVALID);
            continue;
        }
        if (!PrepareCloudPath(PhotoColumn::PHOTOS_TABLE, fileInfos[i])) {
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
    return QueryTotalNumber(PhotoColumn::PHOTOS_TABLE);
}

vector<FileInfo> CloneRestore::QueryFileInfos(int32_t offset)
{
    vector<FileInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    string querySql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE;
    string whereClause = GetQueryWhereClauseByTable(PhotoColumn::PHOTOS_TABLE);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        if (ParseResultSet(resultSet, fileInfo)) {
            result.emplace_back(fileInfo);
        }
    }
    QuerySource(result);
    return result;
}

bool CloneRestore::ParseResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo,
    string dbName)
{
    return ParseResultSet(PhotoColumn::PHOTOS_TABLE, resultSet, fileInfo);
}

int32_t CloneRestore::QueryTotalNumber(const string &tableName)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName;
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
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
    result.reserve(CLONE_QUERY_COUNT);
    string querySql = "SELECT * FROM " + tableName;
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
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

int32_t CloneRestore::MoveAsset(FileInfo &fileInfo)
{
    string localPath = BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL,
        fileInfo.cloudPath);
    if (MoveFile(fileInfo.filePath, localPath) != E_OK) {
        MEDIA_ERR_LOG("Move photo file failed");
        return E_FAIL;
    }

    BackupFileUtils::ModifyFile(localPath, fileInfo.dateModified / MSEC_TO_SEC);
    string srcEditDataPath = backupRestoreDir_ +
        BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL_EDIT_DATA, fileInfo.relativePath);
    string dstEditDataPath = BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD,
        PrefixType::LOCAL_EDIT_DATA, fileInfo.cloudPath);
    if (IsFilePathExist(srcEditDataPath) && MoveDirectory(srcEditDataPath, dstEditDataPath) != E_OK) {
        MEDIA_ERR_LOG("Move editData file failed");
        return E_FAIL;
    }
    return E_OK;
}

bool CloneRestore::IsFilePathExist(const string &filePath) const
{
    if (!MediaFileUtils::IsFileExists(filePath)) {
        MEDIA_DEBUG_LOG("%{private}s doesn't exist", filePath.c_str());
        return false;
    }
    if (MediaFileUtils::IsDirectory(filePath) && MediaFileUtils::IsDirEmpty(filePath)) {
        MEDIA_DEBUG_LOG("%{private}s is an empty directory", filePath.c_str());
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
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateAdded);
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, fileInfo.orientation); // photos need orientation

    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_,
        PhotoColumn::PHOTOS_TABLE);
    for (auto it = fileInfo.valMap.begin(); it != fileInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        if (columnName == PhotoColumn::PHOTO_EDIT_TIME) {
            PrepareEditTimeVal(values, get<int64_t>(columnVal), fileInfo, commonColumnInfoMap);
            continue;
        }
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    return values;
}

bool CloneRestore::PrepareCommonColumnInfoMap(const string &tableName,
    const unordered_map<string, string> &srcColumnInfoMap, const unordered_map<string, string> &dstColumnInfoMap)
{
    auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
    auto neededColumnsException = GetValueFromMap(NEEDED_COLUMNS_EXCEPTION_MAP, tableName);
    auto excludedColumns = GetValueFromMap(EXCLUDED_COLUMNS_MAP, tableName);
    auto &commonColumnInfoMap = tableCommonColumnInfoMap_[tableName];
    if (!HasColumns(dstColumnInfoMap, neededColumns)) {
        MEDIA_ERR_LOG("Destination lack needed columns");
        return false;
    }
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        if (!HasSameColumn(srcColumnInfoMap, it->first, it->second) || excludedColumns.count(it->first) > 0) {
            continue;
        }
        if (neededColumns.count(it->first) > 0 && (neededColumnsException.empty() ||
            neededColumnsException.count(it->first) == 0)) {
            continue;
        }
        commonColumnInfoMap[it->first] = it->second;
    }
    MEDIA_INFO_LOG("Table %{public}s has %{public}zu common columns",
        BackupDatabaseUtils::GarbleInfoName(tableName).c_str(), commonColumnInfoMap.size());
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
    if (queryWhereClauseMap.empty()) {
        return;
    }
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
        MEDIA_ERR_LOG("Get map of table %{public}s failed", BackupDatabaseUtils::GarbleInfoName(tableName).c_str());
        return;
    }
    string albumQueryWhereClause = "EXISTS (SELECT " + PhotoMap::ASSET_ID + " FROM " + mapTableName + " WHERE " +
        PhotoMap::ALBUM_ID + " = " + PhotoAlbumColumns::ALBUM_ID + " AND EXISTS (SELECT " + MediaColumn::MEDIA_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    string photoQueryWhereClause = GetValueFromMap(tableQueryWhereClauseMap_, PhotoColumn::PHOTOS_TABLE);
    if (!photoQueryWhereClause.empty()) {
        albumQueryWhereClause += " AND " + photoQueryWhereClause;
    }
    albumQueryWhereClause += "))";
    tableExtraQueryWhereClauseMap_[tableName] = albumQueryWhereClause;
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

void CloneRestore::BatchQueryPhoto(vector<FileInfo> &fileInfos)
{
    string selection;
    unordered_map<string, size_t> fileIndexMap;
    for (size_t index = 0; index < fileInfos.size(); index++) {
        if (fileInfos[index].cloudPath.empty()) {
            continue;
        }
        BackupDatabaseUtils::UpdateSelection(selection, fileInfos[index].cloudPath, true);
        fileIndexMap[fileInfos[index].cloudPath] = index;
    }
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_FILE_PATH + " IN (" + selection + ")";
    querySql += " LIMIT " + to_string(fileIndexMap.size());
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        if (fileId <= 0) {
            MEDIA_ERR_LOG("Get fileId invalid: %{public}d", fileId);
            continue;
        }
        if (fileIndexMap.count(cloudPath) == 0) {
            continue;
        }
        fileInfos[fileIndexMap.at(cloudPath)].fileIdNew = fileId;
    }
}

void CloneRestore::BatchNotifyPhoto(const vector<FileInfo> &fileInfos)
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Get MediaLibraryNotify instance failed");
        return;
    }
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
        if (albumInfo.albumIdOld <= 0) {
            continue;
        }
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

void CloneRestore::BatchInsertMap(const vector<FileInfo> &fileInfos, int64_t &totalRowNum)
{
    string selection;
    unordered_map<int32_t, int32_t> fileIdMap;
    SetFileIdReference(fileInfos, selection, fileIdMap);
    for (const auto &tableName : CLONE_ALBUMS) {
        string garbledTableName = BackupDatabaseUtils::GarbleInfoName(tableName);
        string mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
        if (mapTableName.empty()) {
            MEDIA_ERR_LOG("Get map of table %{public}s failed", garbledTableName.c_str());
            continue;
        }
        auto albumIdMap = GetValueFromMap(tableAlbumIdMap_, tableName);
        if (albumIdMap.empty()) {
            MEDIA_INFO_LOG("Get album id map of table %{public}s empty, skip", garbledTableName.c_str());
            continue;
        }
        string albumSelection = GetValueFromMap(tableQueryWhereClauseMap_, tableName);
        unordered_set<int32_t> currentTableAlbumSet;
        string baseQuerySql = mapTableName + " INNER JOIN " + tableName + " ON " +
            mapTableName + "." + PhotoMap::ALBUM_ID + " = " + tableName + "." + PhotoAlbumColumns::ALBUM_ID +
            " WHERE " + mapTableName + "." + PhotoMap::ASSET_ID + " IN (" + selection + ")";
        baseQuerySql += albumSelection.empty() ? "" : " AND " + albumSelection;
        int32_t totalNumber = QueryMapTotalNumber(baseQuerySql);
        MEDIA_INFO_LOG("QueryMapTotalNumber of table %{public}s, totalNumber = %{public}d", garbledTableName.c_str(),
            totalNumber);
        for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
            int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
            vector<MapInfo> mapInfos = QueryMapInfos(mapTableName, baseQuerySql, offset, fileIdMap, albumIdMap);
            int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
            int64_t rowNum = InsertMapByTable(mapTableName, mapInfos, currentTableAlbumSet);
            totalRowNum += rowNum;
            int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
            MEDIA_INFO_LOG("query %{public}zu map infos cost %{public}ld, insert %{public}ld maps cost %{public}ld",
                mapInfos.size(), (long)(startInsert - startQuery), (long)rowNum, (long)(end - startInsert));
        }
        UpdateAlbumToNotifySet(tableName, currentTableAlbumSet);
    }
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const MapInfo &mapInfo) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoMap::ASSET_ID, mapInfo.fileId);
    values.PutInt(PhotoMap::ALBUM_ID, mapInfo.albumId);
    return values;
}

void CloneRestore::CheckTableColumnStatus(shared_ptr<NativeRdb::RdbStore> rdbStore,
    const vector<vector<string>> &cloneTableList)
{
    unordered_map<string, unordered_map<string, string>> tableColumnInfoMap;
    for (const auto &tableList : cloneTableList) {
        bool columnStatusGlobal = true;
        for (const auto &tableName : tableList) {
            auto &columnInfoMap = tableColumnInfoMap[tableName];
            columnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(rdbStore, tableName);
            auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
            columnStatusGlobal = columnStatusGlobal && HasColumns(columnInfoMap, neededColumns);
        }
        for (const auto &tableName : tableList) {
            tableColumnStatusMap_[tableName] = columnStatusGlobal;
        }
    }
    for (const auto &tableList : cloneTableList) {
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

void CloneRestore::UpdateAlbumToNotifySet(const string &tableName, const unordered_set<int32_t> &albumSet)
{
    string albumUriPrefix = GetValueFromMap(ALBUM_URI_PREFIX_MAP, tableName);
    if (albumUriPrefix.empty()) {
        MEDIA_ERR_LOG("Get album uri prefix of %{public}s failed",
            BackupDatabaseUtils::GarbleInfoName(tableName).c_str());
        return;
    }
    for (auto albumId : albumSet) {
        string albumUri = MediaFileUtils::GetUriByExtrConditions(albumUriPrefix, to_string(albumId));
        albumToNotifySet_.insert(albumUri);
    }
}

void CloneRestore::NotifyAlbum()
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Get MediaLibraryNotify instance failed");
        return;
    }
    for (const auto &albumUri : albumToNotifySet_) {
        watch->Notify(albumUri, NotifyType::NOTIFY_ADD);
    }
    for (int32_t systemAlbumId = SYSTEM_ALBUM_ID_START; systemAlbumId <= SYSTEM_ALBUM_ID_END; systemAlbumId++) {
        watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX + to_string(systemAlbumId), NotifyType::NOTIFY_UPDATE);
    }
    MEDIA_INFO_LOG("System albums and %{public}zu albums notified", albumToNotifySet_.size());
}

void CloneRestore::PrepareEditTimeVal(NativeRdb::ValuesBucket &values, int64_t editTime, const FileInfo &fileInfo,
    const unordered_map<string, string> &commonColumnInfoMap) const
{
    string editDataPath = backupRestoreDir_ +
        BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL_EDIT_DATA, fileInfo.relativePath);
    int64_t newEditTime = editTime > 0 && IsFilePathExist(editDataPath) ? editTime : 0;
    PrepareCommonColumnVal(values, PhotoColumn::PHOTO_EDIT_TIME, newEditTime, commonColumnInfoMap);
}

void CloneRestore::RestoreGallery()
{
    CheckTableColumnStatus(mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    RestoreAlbum();
    RestorePhoto();
    MEDIA_INFO_LOG("migrate database photo number: %{public}lld, file number: %{public}lld (%{public}lld + "
        "%{public}lld), album number: %{public}lld, map number: %{public}lld", (long long)migrateDatabaseNumber_,
        (long long)migrateFileNumber_, (long long)(migrateFileNumber_ - migrateVideoFileNumber_),
        (long long)migrateVideoFileNumber_, (long long)migrateDatabaseAlbumNumber_,
        (long long)migrateDatabaseMapNumber_);
    MediaLibraryRdbUtils::UpdateAllAlbums(mediaLibraryRdb_);
    NotifyAlbum();
}

bool CloneRestore::PrepareCloudPath(const string &tableName, FileInfo &fileInfo)
{
    string localPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL, fileInfo.relativePath);
    fileInfo.cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfo.relativePath);
    if (fileInfo.cloudPath.empty()) {
        MEDIA_ERR_LOG("Get cloudPath empty");
        UpdateFailedFiles(fileInfo.fileType, localPath, RestoreError::PATH_INVALID);
        return false;
    }
    if (IsSameFileForClone(tableName, fileInfo)) {
        (void)MediaFileUtils::DeleteFile(fileInfo.filePath);
        MEDIA_WARN_LOG("File %{public}s already exists.",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
        return false;
    }
    if (MediaFileUtils::IsFileExists(fileInfo.cloudPath) && BackupFileUtils::CreatePath(fileInfo.fileType,
        fileInfo.displayName, fileInfo.cloudPath) != E_OK) {
        MEDIA_ERR_LOG("Destination file path %{public}s exists, create new path failed",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
        UpdateFailedFiles(fileInfo.fileType, localPath, RestoreError::GET_PATH_FAILED);
        return false;
    }
    if (BackupFileUtils::PreparePath(BackupFileUtils::GetReplacedPathByPrefixType(
        PrefixType::CLOUD, PrefixType::LOCAL, fileInfo.cloudPath)) != E_OK) {
        MEDIA_ERR_LOG("Prepare cloudPath failed");
        fileInfo.cloudPath.clear();
        UpdateFailedFiles(fileInfo.fileType, localPath, RestoreError::GET_PATH_FAILED);
        return false;
    }
    return true;
}

void CloneRestore::RestoreMusic()
{
    CheckTableColumnStatus(mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    RestoreAudio();
    MEDIA_INFO_LOG("migrate database audio number: %{public}lld, file number: %{public}lld",
        (long long)migrateAudioDatabaseNumber_, (long long)migrateAudioFileNumber_);
}

void CloneRestore::RestoreAudio(void)
{
    MEDIA_INFO_LOG("Start clone restore: audio");
    if (!IsReadyForRestore(AudioColumn::AUDIOS_TABLE)) {
        MEDIA_ERR_LOG("Column status is not ready for restore audio, quit");
        return;
    }
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_,
        AudioColumn::AUDIOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
        AudioColumn::AUDIOS_TABLE);
    if (!PrepareCommonColumnInfoMap(AudioColumn::AUDIOS_TABLE, srcColumnInfoMap, dstColumnInfoMap)) {
        MEDIA_ERR_LOG("Prepare common column info failed");
        return;
    }
    int32_t totalNumber = QueryTotalNumber(AudioColumn::AUDIOS_TABLE);
    MEDIA_INFO_LOG("QueryAudioTotalNumber, totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreAudioBatch(offset); }, { &offset });
    }
    ffrt::wait();
}

vector<FileInfo> CloneRestore::QueryFileInfos(const string &tableName, int32_t offset)
{
    vector<FileInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    string querySql = "SELECT * FROM " + tableName;
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        if (ParseResultSet(tableName, resultSet, fileInfo)) {
            result.emplace_back(fileInfo);
        }
    }
    return result;
}

bool CloneRestore::ParseResultSet(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    FileInfo &fileInfo)
{
    fileInfo.fileType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    string oldPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (!ConvertPathToRealPath(oldPath, filePath_, fileInfo.filePath, fileInfo.relativePath)) {
        UpdateFailedFiles(fileInfo.fileType, BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD,
            PrefixType::LOCAL, oldPath), RestoreError::PATH_INVALID);
        return false;
    }
    fileInfo.fileSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultSet);
    if (fileInfo.fileSize <= 0) {
        MEDIA_ERR_LOG("File size is invalid: %{public}lld, filePath: %{public}s", (long long)fileInfo.fileSize,
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
        UpdateFailedFiles(fileInfo.fileType, BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL,
            fileInfo.relativePath), RestoreError::FILE_INVALID);
        return false;
    }
    
    fileInfo.fileIdOld = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    fileInfo.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    fileInfo.dateAdded = GetInt64Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);
    fileInfo.dateModified = GetInt64Val(MediaColumn::MEDIA_DATE_MODIFIED, resultSet);
    SetSpecialAttributes(tableName, resultSet, fileInfo);

    auto commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = commonColumnInfoMap.begin(); it != commonColumnInfoMap.end(); ++it) {
        string columnName = it->first;
        string columnType = it->second;
        GetValFromResultSet(resultSet, fileInfo.valMap, columnName, columnType);
    }
    return true;
}

bool CloneRestore::ParseResultSetForAudio(const shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo)
{
    return ParseResultSet(AudioColumn::AUDIOS_TABLE, resultSet, fileInfo);
}

void CloneRestore::InsertAudio(vector<FileInfo> &fileInfos)
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t fileMoveCount = 0;
    unordered_set<int32_t> excludedFileIdSet;
    for (auto& fileInfo : fileInfos) {
        if (!BackupFileUtils::IsFileValid(fileInfo.filePath, CLONE_RESTORE_ID)) {
            UpdateFailedFiles(fileInfo.fileType, BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL,
                fileInfo.relativePath), RestoreError::FILE_INVALID);
            continue;
        }
        if (!PrepareCloudPath(AudioColumn::AUDIOS_TABLE, fileInfo)) {
            continue;
        }
        string localPath = BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL,
            fileInfo.cloudPath);
        if (MoveFile(fileInfo.filePath, localPath) != E_OK) {
            MEDIA_ERR_LOG("Move audio file failed");
            UpdateFailedFiles(fileInfo.fileType, BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL,
                fileInfo.relativePath), RestoreError::MOVE_FAILED);
            excludedFileIdSet.insert(fileInfo.fileIdOld);
            continue;
        }
        BackupFileUtils::ModifyFile(localPath, fileInfo.dateModified / MSEC_TO_SEC);
        fileMoveCount++;
    }
    migrateAudioFileNumber_ += fileMoveCount;

    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(AudioColumn::AUDIOS_TABLE, CLONE_RESTORE_ID, fileInfos,
        SourceType::AUDIOS, excludedFileIdSet);
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(AudioColumn::AUDIOS_TABLE, values, rowNum);
    if (errCode != E_OK) {
        UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
        return;
    }
    migrateAudioDatabaseNumber_ += rowNum;

    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("move %{public}ld files cost %{public}ld, insert %{public}ld assets cost %{public}ld.",
        (long)fileMoveCount, (long)(startInsert - startMove), (long)rowNum, (long)(end - startInsert));
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(const string &tableName, int32_t sceneCode,
    vector<FileInfo> &fileInfos, int32_t sourceType, const unordered_set<int32_t> &excludedFileIdSet)
{
    vector<NativeRdb::ValuesBucket> values;
    for (auto &fileInfo : fileInfos) {
        if (excludedFileIdSet.count(fileInfo.fileIdOld) > 0) {
            MEDIA_DEBUG_LOG("File id is in excluded set, skip");
            continue;
        }
        if (!fileInfo.isNew || fileInfo.cloudPath.empty()) {
            MEDIA_DEBUG_LOG("Not new record, or get cloudPath empty");
            continue;
        }
        NativeRdb::ValuesBucket value = GetInsertValue(tableName, fileInfo, fileInfo.cloudPath,
            sourceType);
        values.emplace_back(value);
    }
    return values;
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const string &tableName, const FileInfo &fileInfo,
    const string &newPath, int32_t sourceType) const
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateAdded);
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);

    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = fileInfo.valMap.begin(); it != fileInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    return values;
}

string CloneRestore::GetBackupInfo()
{
    if (BaseRestore::Init() != E_OK) {
        MEDIA_ERR_LOG("GetBackupInfo init failed");
        return "";
    }
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("GetBackupInfo Rdbstore is null");
        return "";
    }
    CheckTableColumnStatus(mediaLibraryRdb_, CLONE_TABLE_LISTS_OLD_DEVICE);
    int32_t photoCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE,
        MediaType::MEDIA_TYPE_IMAGE);
    int32_t videoCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE,
        MediaType::MEDIA_TYPE_VIDEO);
    int32_t audioCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, AudioColumn::AUDIOS_TABLE,
        MediaType::MEDIA_TYPE_AUDIO);
    MEDIA_INFO_LOG("QueryTotalNumber, photo: %{public}d, video: %{public}d, audio: %{public}d", photoCount, videoCount,
        audioCount);
    return GetBackupInfoByCount(photoCount, videoCount, audioCount);
}

int32_t CloneRestore::QueryTotalNumberByMediaType(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &tableName,
    MediaType mediaType)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " + MediaColumn::MEDIA_TYPE +
        " = " + to_string(static_cast<int32_t>(mediaType));
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " AND " + whereClause;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    return result;
}

string CloneRestore::GetBackupInfoByCount(int32_t photoCount, int32_t videoCount, int32_t audioCount)
{
    nlohmann::json jsonObject = {
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_PHOTO },
            { STAT_KEY_NUMBER, photoCount }
        },
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_VIDEO },
            { STAT_KEY_NUMBER, videoCount }
        },
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_AUDIO },
            { STAT_KEY_NUMBER, audioCount }
        }
    };
    return jsonObject.dump();
}

void CloneRestore::RestorePhotoBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start restore photo, offset: %{public}d", offset);
    vector<FileInfo> fileInfos = QueryFileInfos(offset);
    InsertPhoto(fileInfos);
    BatchNotifyPhoto(fileInfos);
    MEDIA_INFO_LOG("end restore photo, offset: %{public}d", offset);
}

void CloneRestore::RestoreAudioBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start restore audio, offset: %{public}d", offset);
    vector<FileInfo> fileInfos = QueryFileInfos(AudioColumn::AUDIOS_TABLE, offset);
    InsertAudio(fileInfos);
    MEDIA_INFO_LOG("end restore audio, offset: %{public}d", offset);
}

void CloneRestore::InsertPhotoRelated(vector<FileInfo> &fileInfos)
{
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryPhoto(fileInfos);
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t mapRowNum = 0;
    BatchInsertMap(fileInfos, mapRowNum);
    migrateDatabaseMapNumber_ += mapRowNum;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("query new file_id cost %{public}ld, insert %{public}ld maps cost %{public}ld",
        (long)(startInsert - startQuery), (long)mapRowNum, (long)(end - startInsert));
}

void CloneRestore::SetFileIdReference(const vector<FileInfo> &fileInfos, string &selection,
    unordered_map<int32_t, int32_t> &fileIdMap)
{
    for (const auto &fileInfo : fileInfos) {
        if (fileInfo.fileIdOld <= 0 || fileInfo.fileIdNew <= 0) {
            continue;
        }
        BackupDatabaseUtils::UpdateSelection(selection, to_string(fileInfo.fileIdOld), false);
        fileIdMap[fileInfo.fileIdOld] = fileInfo.fileIdNew;
    }
}

int32_t CloneRestore::QueryMapTotalNumber(const string &baseQuerySql)
{
    string querySql = "SELECT count(1) as count FROM " + baseQuerySql;
    return BackupDatabaseUtils::QueryInt(mediaRdb_, querySql, CUSTOM_COUNT);
}

vector<MapInfo> CloneRestore::QueryMapInfos(const string &tableName, const string &baseQuerySql, int32_t offset,
    const unordered_map<int32_t, int32_t> &fileIdMap, const unordered_map<int32_t, int32_t> &albumIdMap)
{
    vector<MapInfo> mapInfos;
    mapInfos.reserve(CLONE_QUERY_COUNT);
    string columnMapAlbum = tableName + "." + PhotoMap::ALBUM_ID;
    string columnMapAsset = tableName + "." + PhotoMap::ASSET_ID;
    string querySql = "SELECT " + columnMapAlbum + ", " + columnMapAsset + " FROM " + baseQuerySql;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return mapInfos;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t albumIdOld = GetInt32Val(columnMapAlbum, resultSet);
        int32_t fileIdOld = GetInt32Val(columnMapAsset, resultSet);
        if (albumIdOld <= 0 || albumIdMap.count(albumIdOld) == 0 || fileIdOld <= 0 || fileIdMap.count(fileIdOld) <= 0) {
            continue;
        }
        MapInfo mapInfo;
        mapInfo.albumId = albumIdMap.at(albumIdOld);
        mapInfo.fileId = fileIdMap.at(fileIdOld);
        mapInfos.emplace_back(mapInfo);
    }
    return mapInfos;
}

int64_t CloneRestore::InsertMapByTable(const string &tableName, const vector<MapInfo> &mapInfos,
    unordered_set<int32_t> &albumSet)
{
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(mapInfos);
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Batch insert map failed, errCode: %{public}d", errCode);
        return 0;
    }
    for (const auto &mapInfo : mapInfos) {
        albumSet.insert(mapInfo.albumId);
    }
    return rowNum;
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(const vector<MapInfo> &mapInfos)
{
    vector<NativeRdb::ValuesBucket> values;
    for (const auto &mapInfo : mapInfos) {
        NativeRdb::ValuesBucket value = GetInsertValue(mapInfo);
        values.emplace_back(value);
    }
    return values;
}

string CloneRestore::GetQueryWhereClauseByTable(const string &tableName)
{
    string whereClause;
    if (tableQueryWhereClauseMap_.count(tableName)) {
        whereClause += tableQueryWhereClauseMap_.at(tableName);
    }
    if (tableExtraQueryWhereClauseMap_.count(tableName)) {
        whereClause += whereClause.empty() ? "" : " AND " + tableExtraQueryWhereClauseMap_.at(tableName);
    }
    return whereClause;
}

void CloneRestore::QuerySource(vector<FileInfo> &fileInfos)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t hasSourceCount = 0;
    string selection;
    unordered_map<int32_t, size_t> fileIndexMap;
    for (size_t index = 0; index < fileInfos.size(); index++) {
        if (fileInfos[index].fileIdOld <= 0) {
            continue;
        }
        BackupDatabaseUtils::UpdateSelection(selection, to_string(fileInfos[index].fileIdOld), false);
        fileIndexMap[fileInfos[index].fileIdOld] = index;
    }
    string querySql = "SELECT PM." + PhotoMap::ASSET_ID + ", PA." + PhotoAlbumColumns::ALBUM_NAME + ", PA." +
        PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " FROM " + PhotoMap::TABLE + " AS PM INNER JOIN " +
        PhotoAlbumColumns::TABLE + " AS PA ON PM." + PhotoMap::ALBUM_ID + " = PA." + PhotoAlbumColumns::ALBUM_ID +
        " WHERE PA." + PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SOURCE) +
        " AND PA." + PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::SOURCE_GENERIC) +
        " AND PM." + PhotoMap::ASSET_ID + " IN (" + selection + ")";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = GetInt32Val(PhotoMap::ASSET_ID, resultSet);
        string albumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
        string bundleName = GetStringVal(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, resultSet);
        if (fileId <= 0 || fileIndexMap.count(fileId) == 0) {
            MEDIA_ERR_LOG("Get fileId invalid or not found: %{public}d", fileId);
            continue;
        }
        int32_t index = fileIndexMap.at(fileId);
        fileInfos[index].packageName = albumName;
        fileInfos[index].bundleName = bundleName;
        hasSourceCount++;
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Query source %{public}d / %{public}zu cost %{public}ld", hasSourceCount, fileIndexMap.size(),
        (long)(end - start));
}

void CloneRestore::SetSpecialAttributes(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    FileInfo &fileInfo)
{
    if (tableName != PhotoColumn::PHOTOS_TABLE) {
        return;
    }
    fileInfo.orientation = GetInt32Val(PhotoColumn::PHOTO_ORIENTATION, resultSet);
}

bool CloneRestore::IsSameFileForClone(const string &tableName, FileInfo &fileInfo)
{
    if (tableName != PhotoColumn::PHOTOS_TABLE) {
        return IsSameFile(mediaLibraryRdb_, tableName, fileInfo);
    }
    bool result = maxFileId_ > 0 && HasSameFile(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE, fileInfo);
    fileInfo.isNew = !result;
    return result;
}
} // namespace Media
} // namespace OHOS
