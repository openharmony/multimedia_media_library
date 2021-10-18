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

#include "media_scanner_db.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;

MediaScannerDb::MediaScannerDb() {}

unique_ptr<MediaScannerDb> MediaScannerDb::GetDatabaseInstance()
{
    unique_ptr<MediaScannerDb> database = make_unique<MediaScannerDb>();
    return database;
}

void MediaScannerDb::SetRdbHelper(const shared_ptr<OHOS::AppExecFwk::DataAbilityHelper> &rdbhelper)
{
    rdbhelper_ = rdbhelper;
}

string MediaScannerDb::InsertMetadata(const Metadata &metadata)
{
    int32_t rowNum(0);
    ValuesBucket values;

    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri = GetMediaTypeUri(mediaType);

    values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
    values.PutString(MEDIA_DATA_DB_FILE_PATH, metadata.GetFilePath());
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, metadata.GetRelativePath());
    values.PutString(MEDIA_DATA_DB_MIME_TYPE, metadata.GetFileMimeType());
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.PutString(MEDIA_DATA_DB_NAME, metadata.GetFileName());

    values.PutLong(MEDIA_DATA_DB_SIZE, metadata.GetFileSize());
    values.PutLong(MEDIA_DATA_DB_DATE_ADDED, metadata.GetFileDateAdded());
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, metadata.GetFileDateModified());

    values.PutString(MEDIA_DATA_DB_TITLE, metadata.GetFileTitle());
    values.PutString(MEDIA_DATA_DB_ALBUM, metadata.GetAlbum());
    values.PutString(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());

    values.PutInt(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
    values.PutInt(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
    values.PutInt(MEDIA_DATA_DB_DURATION, metadata.GetFileDuration());
    values.PutInt(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());

    values.PutInt(MEDIA_DATA_DB_ALBUM_ID, metadata.GetAlbumId());
    values.PutString(MEDIA_DATA_DB_ALBUM_NAME, metadata.GetAlbumName());
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());

    if (rdbhelper_ != nullptr) {
        Uri abilityUri(MEDIALIBRARY_DATA_URI);
        rowNum = rdbhelper_->Insert(abilityUri, values);
    }

    if (rowNum <= 0) {
        MEDIA_ERR_LOG("MediaDataAbility Insert functionality is failed");
        return "";
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

unique_ptr<Metadata> MediaScannerDb::ReadMetadata(const string &path)
{
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    DataAbilityPredicates predicates = {};
    predicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

    if (rdbhelper_ != nullptr) {
        Uri uri(MEDIALIBRARY_DATA_URI);
        vector<string> columns = {};
        resultSet = rdbhelper_->Query(uri, columns, predicates);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "No result found for %{public}s", path.c_str());
    }

    unique_ptr<Metadata> metadata = make_unique<Metadata>();
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, nullptr, "Metadata object creation failed");

    int32_t rowId = get<int32_t>(GetColumnValue(MEDIA_DATA_DB_ID, resultSet, DataType::TYPE_INT));

    metadata->SetFileId(rowId);
    metadata->SetFileHeight(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_WIDTH, resultSet, DataType::TYPE_INT)));
    metadata->SetFileDuration(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_DURATION, resultSet, DataType::TYPE_INT)));
    metadata->SetOrientation(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_ORIENTATION, resultSet, DataType::TYPE_INT)));
    metadata->SetAlbumId(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_ALBUM_ID, resultSet, DataType::TYPE_INT)));
    metadata->SetParentId(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_PARENT_ID, resultSet, DataType::TYPE_INT)));
    metadata->SetFileHeight(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_HEIGHT, resultSet, DataType::TYPE_INT)));
    metadata->SetFileMediaType(static_cast<MediaType>(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_MEDIA_TYPE,
        resultSet, DataType::TYPE_INT))));

    string fileUri = get<string>(GetColumnValue(MEDIA_DATA_DB_URI, resultSet, DataType::TYPE_STRING));
    metadata->SetUri(fileUri + "/" + to_string(rowId));
    metadata->SetFileMimeType(get<string>(GetColumnValue(MEDIA_DATA_DB_MIME_TYPE, resultSet, DataType::TYPE_STRING)));
    metadata->SetFileName(get<string>(GetColumnValue(MEDIA_DATA_DB_NAME, resultSet, DataType::TYPE_STRING)));
    metadata->SetFileTitle(get<string>(GetColumnValue(MEDIA_DATA_DB_TITLE, resultSet, DataType::TYPE_STRING)));
    metadata->SetAlbum(get<string>(GetColumnValue(MEDIA_DATA_DB_FILE_PATH, resultSet, DataType::TYPE_STRING)));
    metadata->SetFileArtist(get<string>(GetColumnValue(MEDIA_DATA_DB_ARTIST, resultSet, DataType::TYPE_STRING)));
    metadata->SetAlbumName(get<string>(GetColumnValue(MEDIA_DATA_DB_ALBUM_NAME, resultSet, DataType::TYPE_STRING)));
    metadata->SetRelativePath(get<string>(GetColumnValue(MEDIA_DATA_DB_RELATIVE_PATH, resultSet,
        DataType::TYPE_STRING)));
    metadata->SetFilePath(get<string>(GetColumnValue(MEDIA_DATA_DB_FILE_PATH, resultSet,
        DataType::TYPE_STRING)));

    metadata->SetFileSize(get<int64_t>(GetColumnValue(MEDIA_DATA_DB_SIZE, resultSet, DataType::TYPE_LONG)));
    metadata->SetFileDateAdded(get<int64_t>(GetColumnValue(MEDIA_DATA_DB_DATE_ADDED, resultSet, DataType::TYPE_LONG)));
    metadata->SetFileDateModified(get<int64_t>(GetColumnValue(MEDIA_DATA_DB_DATE_MODIFIED, resultSet,
        DataType::TYPE_LONG)));

    return metadata;
}

/**
 * @brief Update single metadata
 *
 * @param metadata
 * @return string
 */
string MediaScannerDb::UpdateMetadata(const Metadata &metadata)
{
    int32_t updateCount(0);
    ValuesBucket values;
    DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(metadata.GetFileId()));

    MediaType mediaType = metadata.GetFileMediaType();
    string mediaTypeUri = GetMediaTypeUri(mediaType);

    values.PutString(MEDIA_DATA_DB_URI, mediaTypeUri);
    values.PutString(MEDIA_DATA_DB_FILE_PATH, metadata.GetFilePath());
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, metadata.GetRelativePath());

    values.PutString(MEDIA_DATA_DB_MIME_TYPE, metadata.GetFileMimeType());
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.PutString(MEDIA_DATA_DB_NAME, metadata.GetFileName());

    values.PutLong(MEDIA_DATA_DB_SIZE, metadata.GetFileSize());
    values.PutLong(MEDIA_DATA_DB_DATE_ADDED, metadata.GetFileDateAdded());
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, metadata.GetFileDateModified());

    values.PutString(MEDIA_DATA_DB_TITLE, metadata.GetFileTitle());
    values.PutString(MEDIA_DATA_DB_ALBUM, metadata.GetAlbum());
    values.PutString(MEDIA_DATA_DB_ARTIST, metadata.GetFileArtist());

    values.PutInt(MEDIA_DATA_DB_HEIGHT, metadata.GetFileHeight());
    values.PutInt(MEDIA_DATA_DB_WIDTH, metadata.GetFileWidth());
    values.PutInt(MEDIA_DATA_DB_ORIENTATION, metadata.GetOrientation());
    values.PutInt(MEDIA_DATA_DB_DURATION, metadata.GetFileDuration());

    values.PutInt(MEDIA_DATA_DB_ALBUM_ID, metadata.GetAlbumId());
    values.PutString(MEDIA_DATA_DB_ALBUM_NAME, metadata.GetAlbumName());
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, metadata.GetParentId());

    if (rdbhelper_ != nullptr) {
        Uri uri(MEDIALIBRARY_DATA_URI);
        updateCount = rdbhelper_->Update(uri, values, predicates);
    }

    if (updateCount <= 0) {
        MEDIA_ERR_LOG("RDBSTORE update failed");
        return "";
    }

    return mediaTypeUri + "/" + to_string(metadata.GetFileId());
}

/**
 * @brief Do a batch update of Metadata list
 *
 * @param metadataList
 * @return int32_t
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
 * @param id
 * @return true
 * @return false
 */
bool MediaScannerDb::DeleteMetadata(const int32_t id)
{
    int32_t deletedCount(0);
    DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(id));

    Uri deleteUri(MEDIALIBRARY_DATA_URI);

    if (rdbhelper_ != nullptr) {
        deletedCount = rdbhelper_->Delete(deleteUri, predicates);
    }

    if (deletedCount > 0) {
        return true;
    }

    return false;
}

/**
 * @brief Get date modified info of a file
 *
 * @param path
 * @return unique_ptr<Metadata>
 */
unique_ptr<Metadata> MediaScannerDb::GetFileModifiedInfo(const string &path)
{
    // Columns to be returned in resultset
    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_ID);
    columns.push_back(MEDIA_DATA_DB_SIZE);
    columns.push_back(MEDIA_DATA_DB_DATE_MODIFIED);
    columns.push_back(MEDIA_DATA_DB_NAME);

    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

    if (rdbhelper_ != nullptr) {
        Uri abilityUri(MEDIALIBRARY_DATA_URI);
        resultSet = rdbhelper_->Query(abilityUri, columns, predicates);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "No result found for %{public}s", path.c_str());
    }

    int ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, nullptr, "Failed to fetch first record");

    unique_ptr<Metadata> metaInfo = make_unique<Metadata>();
    CHECK_AND_RETURN_RET_LOG(metaInfo != nullptr, nullptr, "Memory failure");

    if (metaInfo != nullptr) {
        metaInfo->SetFileId(get<int32_t>(GetColumnValue(MEDIA_DATA_DB_ID, resultSet, DataType::TYPE_INT)));
        metaInfo->SetFileSize(get<int64_t>(GetColumnValue(MEDIA_DATA_DB_SIZE, resultSet, DataType::TYPE_LONG)));
        metaInfo->SetFileName(get<string>(GetColumnValue(MEDIA_DATA_DB_NAME, resultSet, DataType::TYPE_STRING)));
        metaInfo->SetFileDateModified(get<int64_t>(GetColumnValue(MEDIA_DATA_DB_DATE_MODIFIED, resultSet,
            DataType::TYPE_LONG)));
    }

    return metaInfo;
}

/**
 * @brief Get the list of all IDs corresponding to given path
 *
 * @param path
 * @return vector<int32_t>
 */
unordered_map<int32_t, MediaType> MediaScannerDb::GetIdsFromFilePath(const string &path)
{
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    unordered_map<int32_t, MediaType> idMap = {};

    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_ID);
    columns.push_back(MEDIA_DATA_DB_MEDIA_TYPE);

    DataAbilityPredicates predicates;
    predicates.Like(MEDIA_DATA_DB_FILE_PATH, path);

    if (rdbhelper_ != nullptr) {
        Uri queryUri(MEDIALIBRARY_DATA_URI);
        resultSet = rdbhelper_->Query(queryUri, columns, predicates);
    }

    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("No result found for this path");
        return idMap;
    }

    int32_t id(0);
    int32_t idIndex(0);
    int32_t mediaType(0);
    int32_t mediaTypeIndex(0);

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, idIndex);
    resultSet->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, mediaTypeIndex);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetInt(idIndex, id);
        resultSet->GetInt(mediaTypeIndex, mediaType);
        idMap.emplace(make_pair(id, static_cast<MediaType>(mediaType)));
    }

    return idMap;
}

string MediaScannerDb::GetFileDBUriFromPath(const string &path)
{
    string uri("");
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;

    vector<string> columns = {};
    columns.push_back(MEDIA_DATA_DB_URI);

    DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

    if (rdbhelper_ != nullptr) {
        Uri queryUri(MEDIALIBRARY_DATA_URI);
        resultSet = rdbhelper_->Query(queryUri, columns, predicates);
    }

    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != NativeRdb::E_OK)) {
        MEDIA_ERR_LOG("No result found for this path");
        return nullptr;
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
    int32_t mediaFileId = -1;
    size_t index;

    if (uri.length() != 0) {
        index =  uri.find_last_of("/");
        mediaFileId = stoi(uri.substr(index + 1));
    }

    return mediaFileId;
}

int32_t MediaScannerDb::ReadAlbumId(const string &path)
{
    int32_t albumId = -1;
    int32_t columnIndex = -1;

    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

    if (rdbhelper_ != nullptr) {
        Uri uri(MEDIALIBRARY_DATA_URI);
        vector<string> columns = {MEDIA_DATA_DB_ID};
        resultSet = rdbhelper_->Query(uri, columns, predicates);
    }

    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != NativeRdb::E_OK)) {
        MEDIA_ERR_LOG("MediaScannerDb:: No Data found for the given path");
        return albumId;
    }

    resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    resultSet->GetInt(columnIndex, albumId);

    return albumId;
}

void MediaScannerDb::ReadAlbums(const string &path, unordered_map<string, Metadata> &albumMap)
{
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    DataAbilityPredicates predicates;
    int32_t mediaType = static_cast<int>(MediaType::MEDIA_TYPE_ALBUM);
    predicates.Contains(MEDIA_DATA_DB_FILE_PATH, path);
    predicates.EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(mediaType));

    if (rdbhelper_ != nullptr) {
        Uri uri(MEDIALIBRARY_ALBUM_URI);
        vector<string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_DATE_MODIFIED};
        resultSet = rdbhelper_->Query(uri, columns, predicates);
    }

    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("MediaScannerDb:: No Data found for the given path");
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
        metadata.SetAlbumId(intValue);

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
    int32_t id = -1;

    string uri = InsertMetadata(metadata);
    id = GetIdFromUri(uri);

    return id;
}

int32_t MediaScannerDb::UpdateAlbum(const Metadata &metadata)
{
    int32_t id = -1;

    string uri = UpdateMetadata(metadata);
    id = GetIdFromUri(uri);

    return id;
}

string MediaScannerDb::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
            break;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
            break;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
            break;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
            break;
    }
}

void MediaScannerDb::NotifyDatabaseChange(const MediaType mediaType)
{
    CHECK_AND_RETURN_LOG(rdbhelper_ != nullptr, "RDB helper unavailable");

    string notifyUri = GetMediaTypeUri(mediaType);
    Uri uri(notifyUri);
    rdbhelper_->NotifyChange(uri);
}

/**
 * @brief Returns the resutset value based on datatype
 *
 * @param col
 * @param resultSet
 * @param type
 * @return variant<int32_t, int64_t, string, double>
 */
variant<int32_t, int64_t, string, double> MediaScannerDb::GetColumnValue(const string &col,
    const shared_ptr<AbsSharedResultSet> &resultSet, DataType type)
{
    int32_t columnIndex(0);
    int32_t intValue(0);
    int32_t ret(0);
    int64_t longValue(0);
    double doubleValue(0);
    string strValue("");

    variant<int32_t, int64_t, string, double> columnData;

    resultSet->GetColumnIndex(col, columnIndex);

    switch (type) {
        case DataType::TYPE_INT:
            ret = resultSet->GetInt(columnIndex, intValue);
            CHECK_AND_RETURN_RET_LOG(ret == 0, ERR_FAIL, "Failed to obtain value for index %{public}d", columnIndex);
            columnData = intValue;
            break;
        case DataType::TYPE_LONG:
            ret = resultSet->GetLong(columnIndex, longValue);
            CHECK_AND_RETURN_RET_LOG(ret == 0, ERR_FAIL, "Failed to obtain value for index %{public}d", columnIndex);
            columnData = longValue;
            break;
        case DataType::TYPE_DOUBLE:
            ret = resultSet->GetDouble(columnIndex, doubleValue);
            CHECK_AND_RETURN_RET_LOG(ret == 0, ERR_FAIL, "Failed to obtain value for index %{public}d", columnIndex);
            columnData = doubleValue;
            break;
        case DataType::TYPE_STRING:
            ret = resultSet->GetString(columnIndex, strValue);
            CHECK_AND_RETURN_RET_LOG(ret == 0, "", "Failed to obtain value for index %{public}d", columnIndex);
            columnData = strValue;
            break;
        default:
            break;
    }

    return columnData;
}
} // namespace Media
} // namespace OHOS
