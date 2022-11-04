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
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"
#include "media_file_utils.h"

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

string MediaScannerDb::InsertMetadata(const Metadata &metadata)
{
    int32_t rowNum(0);
    DataShareValuesBucket values;

    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri = GetMediaTypeUri(mediaType);

    values.Put(MEDIA_DATA_DB_URI, mediaTypeUri);
    values.Put(MEDIA_DATA_DB_FILE_PATH, metadata.GetFilePath());
    values.Put(MEDIA_DATA_DB_RELATIVE_PATH, metadata.GetRelativePath());
    values.Put(MEDIA_DATA_DB_MIME_TYPE, metadata.GetFileMimeType());
    values.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.Put(MEDIA_DATA_DB_NAME, metadata.GetFileName());

    values.Put(MEDIA_DATA_DB_SIZE, metadata.GetFileSize());
    values.Put(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::UTCTimeSeconds());
    values.Put(MEDIA_DATA_DB_DATE_MODIFIED, metadata.GetFileDateModified());
    values.Put(MEDIA_DATA_DB_TITLE, ScannerUtils::GetFileTitle(metadata.GetFileName()));
    values.Put(MEDIA_DATA_DB_AUDIO_ALBUM, metadata.GetAlbum());
    values.Put(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());

    values.Put(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
    values.Put(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
    values.Put(MEDIA_DATA_DB_DURATION, metadata.GetFileDuration());
    values.Put(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());

    values.Put(MEDIA_DATA_DB_BUCKET_NAME, metadata.GetAlbumName());
    values.Put(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());
    values.Put(MEDIA_DATA_DB_BUCKET_ID, metadata.GetParentId());

    values.Put(MEDIA_DATA_DB_DATE_TAKEN, metadata.GetDateTaken());
    values.Put(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
    values.Put(MEDIA_DATA_DB_LONGITUDE, metadata.GetLongitude());
    values.Put(MEDIA_DATA_DB_LATITUDE, metadata.GetLatitude());

    Uri abilityUri(MEDIALIBRARY_DATA_URI);
    rowNum = MediaLibraryDataManager::GetInstance()->Insert(abilityUri, values);
    if (rowNum <= 0) {
        MEDIA_ERR_LOG("MediaDataAbility Insert functionality is failed, return %{public}d", rowNum);
        return "";
    }

    return (!mediaTypeUri.empty() ? (mediaTypeUri + "/" + to_string(rowNum)) : mediaTypeUri);
}

vector<string> MediaScannerDb::BatchInsert(const vector<Metadata> &metadataList)
{
    vector<string> insertUriList;
    for (auto itr : metadataList) {
        insertUriList.push_back(InsertMetadata(itr));
    }

    return insertUriList;
}

unique_ptr<Metadata> MediaScannerDb::ReadMetadata(const string &path)
{
    DataShare::DataSharePredicates predicates = {};
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ?");
    predicates.SetWhereArgs(vector<string>({ path }));

    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns = {};
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "No result found for %{private}s", path.c_str());
    unique_ptr<Metadata> metadata = FillMetadata(resultSet);

    return metadata;
}

/**
 * @brief Update single metadata in the media database
 *
 * @param metadata The metadata object which has the information about the file
 * @return string The mediatypeUri corresponding to the given metadata
 */
string MediaScannerDb::UpdateMetadata(const Metadata &metadata)
{
    int32_t updateCount(0);
    DataShareValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ?");
    predicates.SetWhereArgs(vector<string>({ to_string(metadata.GetFileId()) }));

    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri = GetMediaTypeUri(mediaType);

    values.Put(MEDIA_DATA_DB_URI, mediaTypeUri);
    values.Put(MEDIA_DATA_DB_FILE_PATH, metadata.GetFilePath());
    values.Put(MEDIA_DATA_DB_RELATIVE_PATH, metadata.GetRelativePath());

    values.Put(MEDIA_DATA_DB_MIME_TYPE, metadata.GetFileMimeType());
    values.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.Put(MEDIA_DATA_DB_NAME, metadata.GetFileName());

    values.Put(MEDIA_DATA_DB_SIZE, metadata.GetFileSize());
    values.Put(MEDIA_DATA_DB_DATE_MODIFIED, metadata.GetFileDateModified());

    values.Put(MEDIA_DATA_DB_AUDIO_ALBUM, metadata.GetAlbum());
    values.Put(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());

    values.Put(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
    values.Put(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
    values.Put(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
    values.Put(MEDIA_DATA_DB_DURATION, metadata.GetFileDuration());

    values.Put(MEDIA_DATA_DB_BUCKET_NAME, metadata.GetAlbumName());
    values.Put(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());
    values.Put(MEDIA_DATA_DB_BUCKET_ID, metadata.GetParentId());

    values.Put(MEDIA_DATA_DB_DATE_TAKEN, metadata.GetDateTaken());
    values.Put(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
    values.Put(MEDIA_DATA_DB_LONGITUDE, metadata.GetLongitude());
    values.Put(MEDIA_DATA_DB_LATITUDE, metadata.GetLatitude());

    Uri uri(MEDIALIBRARY_DATA_URI);
    updateCount = MediaLibraryDataManager::GetInstance()->Update(uri, values, predicates);
    if (updateCount <= 0) {
        MEDIA_ERR_LOG("RDBSTORE update failed");
        return "";
    }

    return (!mediaTypeUri.empty() ? (mediaTypeUri + "/" + to_string(metadata.GetFileId())) : mediaTypeUri);
}

/**
 * @brief Do a batch update of Metadata list
 *
 * @param metadataList The list of metadata to update in the media db
 * @return int32_t Status of the update operation
 */
int32_t MediaScannerDb::UpdateMetadata(const vector<Metadata> &metadataList)
{
    int32_t status = 0;
    vector<string> updateUriList;
    for (auto itr : metadataList) {
        updateUriList.push_back(UpdateMetadata(itr));
    }

    return status;
}

/**
 * @brief Deletes particular entry in database based on row id
 *
 * @param idList The list of IDs to be deleted from the media db
 * @return bool Status of the delete operation
 */
bool MediaScannerDb::DeleteMetadata(const vector<string> &idList)
{
    int32_t deletedCount(0);
    DataShare::DataSharePredicates predicates;

    if (idList.size() == 0) {
        MEDIA_ERR_LOG("to-deleted idList size equals to 0");
        return false;
    }

    std::string builder = " IN (?";
    for (std::size_t i = 0; i < idList.size() - 1; i++) {
        builder += ",?";
    }
    builder += ")";

    predicates.SetWhereClause(MEDIA_DATA_DB_ID + builder);
    predicates.SetWhereArgs(idList);

    Uri deleteUri(MEDIALIBRARY_DATA_URI);

    deletedCount = MediaLibraryDataManager::GetInstance()->Delete(deleteUri, predicates);
    if (deletedCount > 0) {
        return true;
    }

    MEDIA_ERR_LOG("Failed to delete metadata");
    return false;
}

/**
 * @brief Get date modified, id, size and name info for a file
 *
 * @param path The file path for which to obtain the latest modification info from the db
 * @return unique_ptr<Metadata> The metadata object representing the latest info for the given filepath
 */
unique_ptr<Metadata> MediaScannerDb::GetFileModifiedInfo(const string &path)
{
    // Columns to be returned in resultset
    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_ID);
    columns.push_back(MEDIA_DATA_DB_SIZE);
    columns.push_back(MEDIA_DATA_DB_DATE_MODIFIED);
    columns.push_back(MEDIA_DATA_DB_NAME);
    columns.push_back(MEDIA_DATA_DB_RECYCLE_PATH);
    columns.push_back(MEDIA_DATA_DB_ORIENTATION);

    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ?");
    predicates.SetWhereArgs(vector<string>({ path }));

    Uri abilityUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(abilityUri, columns, predicates);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "No result found for %{private}s", path.c_str());
    int ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, nullptr, "Failed to fetch first record");

    unique_ptr<Metadata> metaInfo = FillMetadata(resultSet);
    return metaInfo;
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
    vector<string> args= { path.back() != '/' ? path + "/%" : path + "%" };
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " like ?");
    predicates.SetWhereArgs(args);

    Uri queryUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(queryUri, columns, predicates);
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
    string uri("");

    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_URI);

    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ?");
    predicates.SetWhereArgs(vector<string>({ path }));

    Uri queryUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(queryUri, columns, predicates);
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

int32_t MediaScannerDb::GetIdFromUri(const string &uri) const
{
    int32_t mediaFileId = 0;
    size_t index = 0;

    if (!uri.empty()) {
        index =  uri.find_last_of("/");
        if (index != string::npos) {
            mediaFileId = stoi(uri.substr(index + 1));
        } else {
            MEDIA_ERR_LOG("Id could not be obtained from the given uri");
        }
    } else {
        MEDIA_ERR_LOG("Uri is empty");
    }

    return mediaFileId;
}

int32_t MediaScannerDb::ReadAlbumId(const string &path)
{
    int32_t albumId = 0;
    int32_t columnIndex = -1;

    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_FILE_PATH + " = ?");
    predicates.SetWhereArgs(vector<string>({ path }));

    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns = {MEDIA_DATA_DB_ID};
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, albumId, "No result found for %{private}s", path.c_str());
    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != NativeRdb::E_OK)) {
        MEDIA_ERR_LOG("MediaScannerDb:: No Data found for the given path %{private}s", path.c_str());
        return albumId;
    }

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    resultSet->GetInt(columnIndex, albumId);

    return albumId;
}

void MediaScannerDb::ReadAlbums(const string &path, unordered_map<string, Metadata> &albumMap)
{
    DataShare::DataSharePredicates predicates;
    string queryCmd = MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + MEDIA_DATA_DB_FILE_PATH + " like ? ";
    string queryPath = path.back() != '/' ? path + "/%" : path + "%";
    vector<string> args= { to_string(MediaType::MEDIA_TYPE_ALBUM), queryPath };
    predicates.SetWhereClause(queryCmd);
    predicates.SetWhereArgs(args);

    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_DATE_MODIFIED};
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "No result found for %{private}s", path.c_str());
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("MediaScannerDb:: No Data found for the given path %{private}s", path.c_str());
        return;
    }

    int32_t intValue(0);
    string strValue("");
    int64_t dateModified(0);

    int32_t columnIndexId(0);
    int32_t columnIndexPath(0);
    int32_t columnIndexDateModified(0);

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndexPath);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_MODIFIED, columnIndexDateModified);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        Metadata metadata;
        resultSet->GetInt(columnIndexId, intValue);
        metadata.SetFileId(intValue);

        resultSet->GetString(columnIndexPath, strValue);
        metadata.SetFilePath(strValue);

        resultSet->GetLong(columnIndexDateModified, dateModified);
        metadata.SetFileDateModified(dateModified);

        albumMap.insert(make_pair(strValue, metadata));
    }

    return;
}

int32_t MediaScannerDb::InsertAlbum(const Metadata &metadata)
{
    int32_t id = 0;

    string uri = InsertMetadata(metadata);
    id = GetIdFromUri(uri);

    return id;
}

int32_t MediaScannerDb::UpdateAlbum(const Metadata &metadata)
{
    int32_t id = 0;

    string uri = UpdateMetadata(metadata);
    id = GetIdFromUri(uri);

    return id;
}

string MediaScannerDb::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
    }
}

void MediaScannerDb::NotifyDatabaseChange(const MediaType mediaType)
{
    string notifyUri = GetMediaTypeUri(mediaType);
    Uri uri(notifyUri);

    MediaLibraryDataManager::GetInstance()->NotifyChange(uri);
}

void MediaScannerDb::ExtractMetaFromColumn(const shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
                                           unique_ptr<Metadata> &metadata, const std::string &col)
{
    int32_t columnIndex(0);
    resultSet->GetColumnIndex(col, columnIndex);

    auto dataType = DataType::TYPE_NULL;
    Metadata::MetadataFnPtr requestFunc = nullptr;
    auto itr = metadata->memberFuncMap_.find(col);
    if (itr != metadata->memberFuncMap_.end()) {
        dataType = itr->second.first;
        requestFunc = itr->second.second;
    }

    int32_t ret(0);
    std::variant<int32_t, int64_t, double, std::string> data = 0;

    switch (dataType) {
        case DataType::TYPE_INT: {
            int32_t intValue(0);
            ret = resultSet->GetInt(columnIndex, intValue);
            CHECK_AND_PRINT_LOG(ret == 0, "Failed to obtain integer value for index %{public}d", columnIndex);
            data = intValue;
            break;
        }
        case DataType::TYPE_LONG: {
            int64_t longValue(0);
            ret = resultSet->GetLong(columnIndex, longValue);
            CHECK_AND_PRINT_LOG(ret == 0, "Failed to obtain integer value for index %{public}d", columnIndex);
            data = longValue;
            break;
        }
        case DataType::TYPE_STRING: {
            string strValue("");
            ret = resultSet->GetString(columnIndex, strValue);
            CHECK_AND_PRINT_LOG(ret == 0, "Failed to obtain string value for index %{public}d", columnIndex);
            data = strValue;
            break;
        }
        case DataType::TYPE_DOUBLE: {
            double doubleVal(0);
            ret = resultSet->GetDouble(columnIndex, doubleVal);
            CHECK_AND_PRINT_LOG(ret == 0, "Failed to obtain double value for index %{public}d", columnIndex);
            data = doubleVal;
            break;
        }
        default:
            break;
    }

    // Use the function pointer from map and pass data to fn ptr
    if (requestFunc != nullptr) {
        (metadata.get()->*requestFunc)(data);
    }
}

unique_ptr<Metadata> MediaScannerDb::FillMetadata(const shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    unique_ptr<Metadata> metadata = make_unique<Metadata>();
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, nullptr, "Metadata object creation failed");
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "Result set for metadata is empty");

    std::vector<std::string> columnNames;

    resultSet->GetAllColumnNames(columnNames);
    for (const auto &col : columnNames) {
        ExtractMetaFromColumn(resultSet, metadata, col);
    }

    return metadata;
}
} // namespace Media
} // namespace OHOS
