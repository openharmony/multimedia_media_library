/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Scanner"

#include "media_scanner_db.h"

#include "abs_rdb_predicates.h"
#include "medialibrary_asset_operations.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_errno.h"
#include "rdb_utils.h"
#include "result_set.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

MediaScannerDb::MediaScannerDb() {}

unique_ptr<MediaScannerDb> MediaScannerDb::GetDatabaseInstance()
{
    unique_ptr<MediaScannerDb> database = make_unique<MediaScannerDb>();
    return database;
}

void MediaScannerDb::SetRdbHelper(void)
{
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static inline void SetVirtualPath(const Metadata &metaData, ValuesBucket &values)
{
    string relativePath = metaData.GetRelativePath();
    string displayName = metaData.GetFileName();
    string virtualPath = (relativePath.back() == '/' ? relativePath : relativePath + "/") + displayName;
    values.PutString(MediaColumn::MEDIA_VIRTURL_PATH, virtualPath);
}
#endif

static void SetValuesFromMetaDataAndType(const Metadata &metadata, ValuesBucket &values, MediaType mediaType)
{
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO) {
        values.PutInt(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
        values.PutInt(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
        values.PutInt(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
        values.PutDouble(MEDIA_DATA_DB_LATITUDE, metadata.GetLongitude());
        values.PutDouble(MEDIA_DATA_DB_LONGITUDE, metadata.GetLatitude());
        SetVirtualPath(metadata, values);
    } else if (mediaType == MediaType::MEDIA_TYPE_AUDIO) {
        values.PutString(MEDIA_DATA_DB_AUDIO_ALBUM, metadata.GetAlbum());
        values.PutString(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());
        SetVirtualPath(metadata, values);
    } else {
        values.PutString(MEDIA_DATA_DB_AUDIO_ALBUM, metadata.GetAlbum());
        values.PutString(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());
        values.PutInt(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
        values.PutInt(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
        values.PutInt(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
        values.PutString(MEDIA_DATA_DB_BUCKET_NAME, metadata.GetAlbumName());
        values.PutInt(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());
        values.PutInt(MEDIA_DATA_DB_BUCKET_ID, metadata.GetParentId());
        values.PutDouble(MEDIA_DATA_DB_LATITUDE, metadata.GetLatitude());
        values.PutDouble(MEDIA_DATA_DB_LONGITUDE, metadata.GetLongitude());
    }
#else
    values.PutString(MEDIA_DATA_DB_AUDIO_ALBUM, metadata.GetAlbum());
    values.PutString(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());
    values.PutInt(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
    values.PutInt(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
    values.PutInt(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
    values.PutString(MEDIA_DATA_DB_BUCKET_NAME, metadata.GetAlbumName());
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());
    values.PutInt(MEDIA_DATA_DB_BUCKET_ID, metadata.GetParentId());
    values.PutDouble(MEDIA_DATA_DB_LATITUDE, metadata.GetLatitude());
    values.PutDouble(MEDIA_DATA_DB_LONGITUDE, metadata.GetLongitude());
#endif
}

static void SetValuesFromMetaDataApi9(const Metadata &metadata, ValuesBucket &values, bool isInsert)
{
    MediaType mediaType = metadata.GetFileMediaType();
    values.PutString(MEDIA_DATA_DB_FILE_PATH, metadata.GetFilePath());
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, metadata.GetRelativePath());
    values.PutString(MEDIA_DATA_DB_MIME_TYPE, metadata.GetFileMimeType());
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.PutString(MEDIA_DATA_DB_NAME, metadata.GetFileName());
    values.PutString(MEDIA_DATA_DB_TITLE, metadata.GetFileTitle());
    values.PutLong(MEDIA_DATA_DB_SIZE, metadata.GetFileSize());
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, metadata.GetFileDateModified());
    values.PutInt(MEDIA_DATA_DB_DURATION, metadata.GetFileDuration());
    values.PutLong(MEDIA_DATA_DB_DATE_TAKEN, metadata.GetDateTaken());
    values.PutLong(MEDIA_DATA_DB_TIME_PENDING, 0);

    SetValuesFromMetaDataAndType(metadata, values, mediaType);

    if (isInsert) {
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::UTCTimeSeconds());
    }
}

static void SetValuesFromMetaDataApi10(const Metadata &metadata, ValuesBucket &values, bool isInsert)
{
    MediaType mediaType = metadata.GetFileMediaType();

    values.PutString(MediaColumn::MEDIA_FILE_PATH, metadata.GetFilePath());
    values.PutString(MediaColumn::MEDIA_MIME_TYPE, metadata.GetFileMimeType());
    values.PutInt(MediaColumn::MEDIA_TYPE, mediaType);

    values.PutLong(MediaColumn::MEDIA_SIZE, metadata.GetFileSize());
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, metadata.GetFileDateModified());
    values.PutInt(MediaColumn::MEDIA_DURATION, metadata.GetFileDuration());
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, metadata.GetDateTaken());
    values.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);

    if (mediaType == MediaType::MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO) {
        values.PutInt(PhotoColumn::PHOTO_HEIGHT, metadata.GetFileHeight());
        values.PutInt(PhotoColumn::PHOTO_WIDTH, metadata.GetFileWidth());
        values.PutInt(PhotoColumn::PHOTO_ORIENTATION, metadata.GetOrientation());
        values.PutDouble(PhotoColumn::PHOTO_LATITUDE, metadata.GetLongitude());
        values.PutDouble(PhotoColumn::PHOTO_LONGITUDE, metadata.GetLatitude());
    } else if (mediaType == MediaType::MEDIA_TYPE_AUDIO) {
        values.PutString(AudioColumn::AUDIO_ALBUM, metadata.GetAlbum());
        values.PutString(AudioColumn::AUDIO_ARTIST, metadata.GetFileArtist());
    }

    if (isInsert) {
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::UTCTimeSeconds());
    }
}

static void GetTableNameByPath(int32_t mediaType, string &tableName)
{
    switch (mediaType) {
        case MediaType::MEDIA_TYPE_IMAGE:
        case MediaType::MEDIA_TYPE_VIDEO: {
            tableName = PhotoColumn::PHOTOS_TABLE;
            break;
        }
        case MediaType::MEDIA_TYPE_AUDIO: {
            tableName = AudioColumn::AUDIOS_TABLE;
            break;
        }
        default: {
            tableName = MEDIALIBRARY_TABLE;
            break;
        }
    }
}

string MediaScannerDb::InsertMetadata(const Metadata &metadata, MediaLibraryApi api)
{
    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri;
    ValuesBucket values;
    if (api == MediaLibraryApi::API_10) {
        mediaTypeUri = MediaFileUtils::GetMediaTypeUriV10(mediaType);
    } else {
        mediaTypeUri = MediaFileUtils::GetMediaTypeUri(mediaType);
#ifdef MEDIALIBRARY_COMPATIBILITY
        if ((mediaType != MediaType::MEDIA_TYPE_IMAGE) && (mediaType != MediaType::MEDIA_TYPE_VIDEO) &&
            (mediaType != MediaType::MEDIA_TYPE_AUDIO)) {
            values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
        }
#else
        values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
#endif
    }

    string tableName = MEDIALIBRARY_TABLE;
    if (api == MediaLibraryApi::API_10) {
        SetValuesFromMetaDataApi10(metadata, values, true);
        GetTableNameByPath(mediaType, tableName);
    } else {
        SetValuesFromMetaDataApi9(metadata, values, true);
#ifdef MEDIALIBRARY_COMPATIBILITY
        GetTableNameByPath(mediaType, tableName);
#endif
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return "";
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        return "";
    }

    int64_t rowNum = 0;
    int32_t result = rdbStorePtr->Insert(rowNum, tableName, values);
    if (rowNum <= 0 || result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("MediaDataAbility Insert functionality is failed, return %{public}ld", (long)rowNum);
        return "";
    }

    if (mediaTypeUri.empty()) {
        return "";
    }
    if (api == MediaLibraryApi::API_10) {
        return mediaTypeUri + "/" + to_string(rowNum) + "?api_version=10";
    }
    return mediaTypeUri + "/" + to_string(rowNum);
}

vector<string> MediaScannerDb::BatchInsert(const vector<Metadata> &metadataList)
{
    vector<string> insertUriList;
    for (auto itr : metadataList) {
        insertUriList.push_back(InsertMetadata(itr));
    }

    return insertUriList;
}

static inline void GetUriStringInUpdate(MediaType mediaType, MediaLibraryApi api, string &mediaTypeUri,
    ValuesBucket &values)
{
    if (api == MediaLibraryApi::API_10) {
        mediaTypeUri = MediaFileUtils::GetMediaTypeUriV10(mediaType);
    } else {
        mediaTypeUri = MediaFileUtils::GetMediaTypeUri(mediaType);
#ifdef MEDIALIBRARY_COMPATIBILITY
        if ((mediaType != MediaType::MEDIA_TYPE_IMAGE) && (mediaType != MediaType::MEDIA_TYPE_VIDEO) &&
            (mediaType != MediaType::MEDIA_TYPE_AUDIO)) {
            values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
        }
#else
        values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
#endif
    }
}

/**
 * @brief Update single metadata in the media database
 *
 * @param metadata The metadata object which has the information about the file
 * @return string The mediatypeUri corresponding to the given metadata
 */
string MediaScannerDb::UpdateMetadata(const Metadata &metadata, MediaLibraryApi api)
{
    int32_t updateCount(0);
    ValuesBucket values;
    string whereClause = MEDIA_DATA_DB_ID + " = ?";
    vector<string> whereArgs = { to_string(metadata.GetFileId()) };
    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri;
    GetUriStringInUpdate(mediaType, api, mediaTypeUri, values);

    string tableName = MEDIALIBRARY_TABLE;
    if (api == MediaLibraryApi::API_10) {
        SetValuesFromMetaDataApi10(metadata, values, false);
        GetTableNameByPath(mediaType, tableName);
    } else {
        SetValuesFromMetaDataApi9(metadata, values, false);
#ifdef MEDIALIBRARY_COMPATIBILITY
        GetTableNameByPath(mediaType, tableName);
#endif
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return "";
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        return "";
    }
    int32_t result = rdbStorePtr->Update(updateCount, tableName, values, whereClause, whereArgs);
    if (result != NativeRdb::E_OK || updateCount <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{public}d. Updated %{public}d", result, updateCount);
        return "";
    }
    if (mediaTypeUri.empty()) {
        return "";
    }
    if (api == MediaLibraryApi::API_10) {
        return mediaTypeUri + "/" + to_string(metadata.GetFileId()) + "?api_version=10";
    }
    return mediaTypeUri + "/" + to_string(metadata.GetFileId());
}

/**
 * @brief Deletes particular entry in database based on row id
 *
 * @param idList The list of IDs to be deleted from the media db
 * @return bool Status of the delete operation
 */
bool MediaScannerDb::DeleteMetadata(const vector<string> &idList)
{
    if (idList.size() == 0) {
        MEDIA_ERR_LOG("to-deleted idList size equals to 0");
        return false;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    NativeRdb::RdbPredicates rdbPredicate(MEDIALIBRARY_TABLE);
    rdbPredicate.In(MEDIA_DATA_DB_ID, idList);
    int32_t ret = rdbStore->Delete(rdbPredicate);
    return ret == static_cast<int32_t>(idList.size());
}

static OperationObject GetOprnObjectFromPath(const string &path)
{
    const map<string, OperationObject> oprnMap = {
        { PHOTO_BUCKET, OperationObject::FILESYSTEM_PHOTO },
        { AUDIO_BUCKET, OperationObject::FILESYSTEM_AUDIO },
#ifdef MEDIALIBRARY_COMPATIBILITY
        { PIC_DIR_VALUES, OperationObject::FILESYSTEM_PHOTO },
        { AUDIO_DIR_VALUES, OperationObject::FILESYSTEM_AUDIO },
        { VIDEO_DIR_VALUES, OperationObject::FILESYSTEM_PHOTO }
#endif
    };

    for (const auto &iter : oprnMap) {
        if (path.find(iter.first) != string::npos) {
            return iter.second;
        }
    }
    return OperationObject::FILESYSTEM_ASSET;
}

static void GetQueryParamsByPath(const string &path, MediaLibraryApi api, vector<string> &columns,
    OperationObject &oprnObject, string &whereClause)
{
    oprnObject = GetOprnObjectFromPath(path);
    if (api == MediaLibraryApi::API_10) {
        whereClause = MediaColumn::MEDIA_FILE_PATH + " = ? And " + MediaColumn::MEDIA_DATE_TRASHED + " = ? ";
        if (oprnObject == OperationObject::FILESYSTEM_PHOTO) {
            columns = {
                MediaColumn::MEDIA_ID, MediaColumn::MEDIA_SIZE, MediaColumn::MEDIA_DATE_MODIFIED,
                MediaColumn::MEDIA_NAME, PhotoColumn::PHOTO_ORIENTATION
            };
        } else if (oprnObject == OperationObject::FILESYSTEM_AUDIO) {
            columns = {
                MediaColumn::MEDIA_ID, MediaColumn::MEDIA_SIZE, MediaColumn::MEDIA_DATE_MODIFIED,
                MediaColumn::MEDIA_NAME
            };
        }
    } else {
#ifndef MEDIALIBRARY_COMPATIBILITY
        oprnObject = OperationObject::FILESYSTEM_ASSET;
#endif
        if (oprnObject == OperationObject::FILESYSTEM_PHOTO) {
            whereClause = MediaColumn::MEDIA_FILE_PATH + " = ? And " + MediaColumn::MEDIA_DATE_TRASHED + " = ? ";
            columns = {
                MediaColumn::MEDIA_ID, MediaColumn::MEDIA_SIZE, MediaColumn::MEDIA_DATE_MODIFIED,
                MediaColumn::MEDIA_NAME, PhotoColumn::PHOTO_ORIENTATION
            };
        } else if (oprnObject == OperationObject::FILESYSTEM_AUDIO) {
            whereClause = MediaColumn::MEDIA_FILE_PATH + " = ? And " + MediaColumn::MEDIA_DATE_TRASHED + " = ? ";
            columns = {
                MediaColumn::MEDIA_ID, MediaColumn::MEDIA_SIZE, MediaColumn::MEDIA_DATE_MODIFIED,
                MediaColumn::MEDIA_NAME
            };
        } else {
            whereClause = MEDIA_DATA_DB_FILE_PATH + " = ? And " + MEDIA_DATA_DB_IS_TRASH + " = ? ";
            columns = {
                MEDIA_DATA_DB_ID, MEDIA_DATA_DB_SIZE, MEDIA_DATA_DB_DATE_MODIFIED,
                MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_ORIENTATION, MEDIA_DATA_DB_RECYCLE_PATH
            };
        }
    }
}

/**
 * @brief Get date modified, id, size and name info for a file
 *
 * @param path The file path for which to obtain the latest modification info from the db
 * @return unique_ptr<Metadata> The metadata object representing the latest info for the given filepath
 */
int32_t MediaScannerDb::GetFileBasicInfo(const string &path, unique_ptr<Metadata> &ptr, MediaLibraryApi api)
{
    vector<string> columns;
    string whereClause;
    OperationObject oprnObject = OperationObject::FILESYSTEM_ASSET;
    GetQueryParamsByPath(path, api, columns, oprnObject, whereClause);

    vector<string> args = { path, to_string(NOT_TRASHED) };

    MediaLibraryCommand cmd(oprnObject, OperationType::QUERY, api);
    cmd.GetAbsRdbPredicates()->SetWhereClause(whereClause);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(args);

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_RDB;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("return nullptr when query rdb");
        return E_RDB;
    }

    int32_t rowCount = 0;
    int32_t ret = resultSet->GetRowCount(rowCount);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to get row count");
        return E_RDB;
    }

    if (rowCount == 0) {
        return E_OK;
    }

    ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to go to first row");
        return E_RDB;
    }

    return FillMetadata(resultSet, ptr);
}

/**
 * @brief Get the list of all IDs corresponding to given path
 *
 * @param path The path from which to obtain the list of child IDs
 * @return unordered_map<int32_t, MediaType> The list of IDS along with mediaType information
 */
unordered_map<int32_t, MediaType> MediaScannerDb::GetIdsFromFilePath(const string &path)
{
    unordered_map<int32_t, MediaType> idMap = {};

    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_ID);
    columns.push_back(MEDIA_DATA_DB_MEDIA_TYPE);
    columns.push_back(MEDIA_DATA_DB_RECYCLE_PATH);

    DataShare::DataSharePredicates predicates;
    // Append % to end of the path for using LIKE statement
    vector<string> args= { path.back() != '/' ? path + "/%" : path + "%", to_string(NOT_TRASHED) };
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " like ? AND " + MEDIA_DATA_DB_IS_TRASH + " = ? ");
    predicates.SetWhereArgs(args);

    Uri queryUri(MEDIALIBRARY_DATA_URI);
    int errCode = 0;
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(queryUri, columns, predicates, errCode);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, idMap, "No entries found for this path");

    int32_t id(0);
    int32_t idIndex(0);
    int32_t mediaType(0);
    int32_t mediaTypeIndex(0);
    std::string recyclePath;
    int32_t recyclePathIndex(0);

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, idIndex);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, mediaTypeIndex);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_RECYCLE_PATH, recyclePathIndex);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        recyclePath.clear();
        resultSet->GetString(recyclePathIndex, recyclePath);
        if (!recyclePath.empty()) {
            continue;
        }

        resultSet->GetInt(idIndex, id);
        resultSet->GetInt(mediaTypeIndex, mediaType);
        idMap.emplace(make_pair(id, static_cast<MediaType>(mediaType)));
    }

    return idMap;
}

string MediaScannerDb::GetFileDBUriFromPath(const string &path)
{
    string uri;

    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_URI);

    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ? AND " + MEDIA_DATA_DB_IS_TRASH + " = ?");
    vector<string> args = { path, to_string(NOT_TRASHED) };
    predicates.SetWhereArgs(args);

    Uri queryUri(MEDIALIBRARY_DATA_URI);
    int errCode = 0;
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(queryUri, columns, predicates, errCode);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, uri, "No entries found for this path");
    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != NativeRdb::E_OK)) {
        MEDIA_ERR_LOG("No result found for this path");
        return uri;
    }

    int32_t intValue(0);
    int32_t columnIndex(0);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    resultSet->GetInt(columnIndex, intValue);
    uri = MEDIALIBRARY_DATA_URI + "/" + to_string(intValue);
    return uri;
}

int32_t MediaScannerDb::GetIdFromPath(const string &path)
{
    int32_t id = UNKNOWN_ID;
    int32_t columnIndex = -1;

    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ? AND " + MEDIA_DATA_DB_IS_TRASH + " = ?");
    vector<string> args = { path, to_string(NOT_TRASHED) };
    predicates.SetWhereArgs(args);

    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns = {MEDIA_DATA_DB_ID};
    int errCode = 0;
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates, errCode);
    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != NativeRdb::E_OK)) {
        MEDIA_ERR_LOG("No data found for the given path %{private}s", path.c_str());
        return id;
    }

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    resultSet->GetInt(columnIndex, id);

    return id;
}

int32_t MediaScannerDb::ReadAlbums(const string &path, unordered_map<string, Metadata> &albumMap)
{
    if ((path + "/").find(ROOT_MEDIA_DIR) != 0) {
        return E_INVALID_ARGUMENTS;
    }

    AbsRdbPredicates predicates(MEDIALIBRARY_TABLE);
    string queryCmd = MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + MEDIA_DATA_DB_FILE_PATH + " like ? AND " +
        MEDIA_DATA_DB_IS_TRASH + " = ?";
    string queryPath = path.back() != '/' ? path + "/%" : path + "%";
    vector<string> args = { to_string(MediaType::MEDIA_TYPE_ALBUM), queryPath, to_string(NOT_TRASHED) };
    predicates.SetWhereClause(queryCmd);
    predicates.SetWhereArgs(args);
    vector<string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_DATE_MODIFIED};

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        return E_HAS_DB_ERROR;
    }
    auto resultSet = rdbStorePtr->Query(predicates, columns);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }

    albumMap.clear();
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        Metadata metadata;
        int32_t intValue = GetInt32Val(MEDIA_DATA_DB_ID, resultSet);
        metadata.SetFileId(intValue);
        string strValue = GetStringVal(MEDIA_DATA_DB_FILE_PATH, resultSet);
        metadata.SetFilePath(strValue);
        int64_t dateModified = GetInt64Val(MEDIA_DATA_DB_DATE_MODIFIED, resultSet);
        metadata.SetFileDateModified(dateModified);
        albumMap.insert(make_pair(strValue, metadata));
    }

    return E_OK;
}

int32_t MediaScannerDb::InsertAlbum(const Metadata &metadata)
{
    int32_t id = 0;

    string uri = InsertMetadata(metadata);
    id = stoi(MediaLibraryDataManagerUtils::GetIdFromUri(uri));

    return id;
}

int32_t MediaScannerDb::UpdateAlbum(const Metadata &metadata)
{
    int32_t id = 0;

    string uri = UpdateMetadata(metadata);
    id = stoi(MediaLibraryDataManagerUtils::GetIdFromUri(uri));

    return id;
}

void MediaScannerDb::NotifyDatabaseChange(const MediaType mediaType)
{
    string notifyUri = MediaFileUtils::GetMediaTypeUri(mediaType);
    Uri uri(notifyUri);

    MediaLibraryDataManager::GetInstance()->NotifyChange(uri);
}

void MediaScannerDb::ExtractMetaFromColumn(const shared_ptr<NativeRdb::ResultSet> &resultSet,
                                           unique_ptr<Metadata> &metadata, const std::string &col)
{
    ResultSetDataType dataType = ResultSetDataType::TYPE_NULL;
    Metadata::MetadataFnPtr requestFunc = nullptr;
    auto itr = metadata->memberFuncMap_.find(col);
    if (itr != metadata->memberFuncMap_.end()) {
        dataType = itr->second.first;
        requestFunc = itr->second.second;
    } else {
        MEDIA_ERR_LOG("invalid column name %{private}s", col.c_str());
        return;
    }

    std::variant<int32_t, std::string, int64_t, double> data =
        ResultSetUtils::GetValFromColumn<const shared_ptr<NativeRdb::ResultSet>>(col, resultSet, dataType);

    // Use the function pointer from map and pass data to fn ptr
    if (requestFunc != nullptr) {
        (metadata.get()->*requestFunc)(data);
    }
}

int32_t MediaScannerDb::FillMetadata(const shared_ptr<NativeRdb::ResultSet> &resultSet,
    unique_ptr<Metadata> &ptr)
{
    std::vector<std::string> columnNames;
    int32_t err = resultSet->GetAllColumnNames(columnNames);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to get all column names");
        return E_RDB;
    }

    for (const auto &col : columnNames) {
        ExtractMetaFromColumn(resultSet, ptr, col);
    }

    return E_OK;
}

int32_t MediaScannerDb::RecordError(const std::string &err)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_ERROR, err);
    int64_t outRowId = -1;
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        MEDIA_ERR_LOG("rdbStorePtr is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStorePtr->Insert(outRowId, MEDIALIBRARY_ERROR_TABLE, valuesBucket);
    if (ret) {
        MEDIA_ERR_LOG("rdb insert err %{public}d", ret);
        return E_ERR;
    }

    return E_OK;
}

std::vector<std::string> MediaScannerDb::ReadError()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return {};
    }

    AbsRdbPredicates predicates(MEDIALIBRARY_ERROR_TABLE);
    vector<string> columns = { MEDIA_DATA_ERROR };
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        MEDIA_ERR_LOG("rdbStorePtr is nullptr");
        return {};
    }
    auto resultSet = rdbStorePtr->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("rdb query return nullptr");
        return {};
    }

    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to get row count");
        return {};
    }

    if (rowCount == 0) {
        return {};
    }

    string str;
    vector<string> errList;
    errList.reserve(rowCount);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetString(0, str);
        errList.emplace_back(move(str));
    }

    return errList;
}

int32_t MediaScannerDb::DeleteError(const std::string &err)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    int32_t outRowId = -1;
    string whereClause = MEDIA_DATA_ERROR + " = ?";
    vector<string> whereArgs= { err };
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        MEDIA_ERR_LOG("rdbStorePtr is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStorePtr->Delete(outRowId, MEDIALIBRARY_ERROR_TABLE, whereClause, whereArgs);
    if (ret) {
        MEDIA_ERR_LOG("rdb delete err %{public}d", ret);
        return E_ERR;
    }

    return E_OK;
}
} // namespace Media
} // namespace OHOS
