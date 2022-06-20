/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "media_file_extention_utils.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "media_file_utils.h"
#include "uri_helper.h"
#include "media_asset.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
string MediaFileExtentionUtils::GetFileMediaTypeUri(MediaType mediaType, const string& networkId)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return uri + MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return uri + MEDIALIBRARY_TYPE_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return uri + MEDIALIBRARY_TYPE_IMAGE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return uri + MEDIALIBRARY_TYPE_FILE_URI;
    }
}

void GetSingleFileInfo(const string &networkId, FileAccessFwk::FileInfo &fileInfo,
    shared_ptr<AbsSharedResultSet> &result)
{
    int32_t index = 0;
    int fileId;
    int mediaType;
    string fileName;
    int64_t fileSize, date_modified;
    result->GetColumnIndex(MEDIA_DATA_DB_ID, index);
    result->GetInt(index, fileId);
    result->GetColumnIndex(MEDIA_DATA_DB_NAME, index);
    result->GetString(index, fileName);
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, index);
    result->GetInt(index, mediaType);
    result->GetColumnIndex(MEDIA_DATA_DB_SIZE, index);
    result->GetLong(index, fileSize);
    result->GetColumnIndex(MEDIA_DATA_DB_DATE_MODIFIED, index);
    result->GetLong(index, date_modified);
    string uri = MediaFileExtentionUtils::GetFileMediaTypeUri(MediaType(mediaType), networkId) +
         '/' + to_string(fileId);
    fileInfo.uri = Uri(uri);
    fileInfo.fileName = fileName;
    fileInfo.mimiType = to_string(mediaType);
    fileInfo.size = fileSize;
    fileInfo.mtime = date_modified;
    if (mediaType == MEDIA_TYPE_ALBUM) {
        fileInfo.mode = MEDIALIBRARY_FOLDER;
    }
}

void GetFileInfoFromResult(const string &networkId, shared_ptr<AbsSharedResultSet> &result,
    vector<FileAccessFwk::FileInfo> &fileList)
{
    int count = 0;
    result->GetRowCount(count);
    MEDIA_DEBUG_LOG("count %{public}d", count);
    if (count == 0) {
        MEDIA_ERR_LOG("DataShareResultSet null");
        return;
    }
    result->GoToFirstRow();
    for (int i = 0; i < count; i++) {
        FileAccessFwk::FileInfo fileInfo;
        GetSingleFileInfo(networkId, fileInfo, result);
        MEDIA_DEBUG_LOG("fileInfo.uri %{public}s", fileInfo.uri.ToString().c_str());
        fileList.push_back(fileInfo);
        result->GoToNextRow();
    }
}

std::shared_ptr<AbsSharedResultSet> GetListFileResult(const string &queryUri,
                                                      const string &selection,
                                                      vector<string> &selectionArgs)
{
    Uri uri(queryUri);
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    return resultSet;
}

shared_ptr<AbsSharedResultSet> MediaFileExtentionUtils::GetFileFromRdb(const string &selectUri, const string &networkId)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    string selection = MEDIA_DATA_DB_ID + " LIKE ? ";
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(selectUri);
    vector<string> selectionArgs = { id };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    shared_ptr<AbsSharedResultSet> result =
        MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    return result;
}

bool MediaFileExtentionUtils::GetAlbumRelativePath(const string &selectUri, const string &networkId,
    string &relativePath)
{
    auto result = GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("GetAlbum fail");
        return false;
    }
    result->GoToFirstRow();
    int columnIndex = 0;
    int mediaType;
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, columnIndex);
    result->GetInt(columnIndex, mediaType);
    CHECK_AND_RETURN_RET_LOG(mediaType == MEDIA_TYPE_ALBUM, false, "selectUri is not album");
    result->GetColumnIndex(MEDIA_DATA_DB_RELATIVE_PATH, columnIndex);
    result->GetString(columnIndex, relativePath);
    string displayname;
    result->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    result->GetString(columnIndex, displayname);
    relativePath = relativePath + displayname + SLASH_CHAR;
    MEDIA_DEBUG_LOG("relativePath %{public}s", relativePath.c_str());
    return true;
}

vector<FileAccessFwk::FileInfo> MediaFileExtentionUtils::ListFile(string selectUri)
{
    UriHelper::ListFileType listFileType = UriHelper::ResolveUri(selectUri);
    MEDIA_DEBUG_LOG("selectUri %{public}s istFileType %{public}d", selectUri.c_str(), listFileType);
    vector<FileAccessFwk::FileInfo> fileList;
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(selectUri);
    string selection;
    vector<string> selectionArgs;
    if (listFileType == UriHelper::LISTFILE_ROOT) {
        selection = MEDIA_DATA_DB_PARENT_ID + " LIKE ? AND " + MEDIA_DATA_DB_IS_TRASH + " LIKE ? ";
        selectionArgs = { to_string(ROOT_PARENT_ID), to_string(NOT_ISTRASH) };
    } else if (listFileType == UriHelper::LISTFILE_DIR) {
        string relativePath;
        if (!GetAlbumRelativePath(selectUri, networkId, relativePath)) {
            MEDIA_ERR_LOG("selectUri is not valid album uri");
            return fileList;
        }
        selection = MEDIA_DATA_DB_RELATIVE_PATH + " LIKE ? AND " + MEDIA_DATA_DB_IS_TRASH + " LIKE ? ";
        selectionArgs = { relativePath, to_string(NOT_ISTRASH) };
        MEDIA_DEBUG_LOG("relativePath %{public}s", relativePath.c_str());
    }
    string queryUri;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    } else {
        queryUri = MEDIALIBRARY_DATA_URI;
    }
    MEDIA_DEBUG_LOG("queryUri %{public}s", queryUri.c_str());
    std::shared_ptr<AbsSharedResultSet> resultSet = GetListFileResult(queryUri, selection, selectionArgs);
    GetFileInfoFromResult(networkId, resultSet, fileList);
    MEDIA_DEBUG_LOG("fileList.size() count %{public}u", (uint32_t)fileList.size());
    return fileList;
}

bool GetDeviceInfo(shared_ptr<AbsSharedResultSet> result,
    FileAccessFwk::DeviceInfo &deviceInfo)
{
    int index = 0;
    string name;
    string networkId;
    result->GetColumnIndex(DEVICE_DB_NETWORK_ID, index);
    result->GetString(index, networkId);
    result->GetColumnIndex(DEVICE_DB_NAME, index);
    result->GetString(index, name);
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_ROOT;
    deviceInfo.uri = Uri(uri);
    deviceInfo.displayName = name;
    return true;
}

int GetDeviceInfoFromResult(shared_ptr<AbsSharedResultSet> &result, vector<FileAccessFwk::DeviceInfo> &deviceList)
{
    int count = 0;
    result->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("GetDeviceInfoFromResult is empty");
        return DATA_ABILITY_FAIL;
    }
    result->GoToFirstRow();
    for (int i = 0; i < count; i++) {
        FileAccessFwk::DeviceInfo deviceInfo;
        GetDeviceInfo(result, deviceInfo);
        deviceList.push_back(deviceInfo);
        result->GoToNextRow();
    }
    return SUCCESS;
}

void GetActivePeer(shared_ptr<AbsSharedResultSet> &result)
{
    std::string strQueryCondition = DEVICE_DB_DATE_MODIFIED + " = 0";
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(strQueryCondition);
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

vector<FileAccessFwk::DeviceInfo> MediaFileExtentionUtils::GetRoots()
{
    FileAccessFwk::DeviceInfo deviceInfo;
    // add local root
    deviceInfo.uri = Uri(MEDIALIBRARY_DATA_URI + MEDIALIBRARY_ROOT);
    deviceInfo.displayName = MEDIALIBRARY_LOCAL_DEVICE_NAME;
    vector<FileAccessFwk::DeviceInfo> deviceList;
    deviceList.push_back(deviceInfo);
    shared_ptr<AbsSharedResultSet> resultSet;
    GetActivePeer(resultSet);
    GetDeviceInfoFromResult(resultSet, deviceList);
    return deviceList;
}

bool MediaFileExtentionUtils::CheckSupport(const string &uri)
{
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    if (!networkId.empty()) {
        MEDIA_ERR_LOG("not support distributed operation");
        return false;
    }
    return true;
}

static bool GetFileFromResult(const string &selectUri, const string &networkId, string &sourcePath,
    string &relativePath, int &mediaType)
{
    auto result = MediaFileExtentionUtils::GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("GetFileFromRdb fail");
        return false;
    }
    result->GoToFirstRow();
    int columnIndex = 0;
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, columnIndex);
    result->GetInt(columnIndex, mediaType);
    result->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    result->GetString(columnIndex, sourcePath);
    result->GetColumnIndex(MEDIA_DATA_DB_RELATIVE_PATH, columnIndex);
    result->GetString(columnIndex, relativePath);
    return true;
}

int32_t HandleFileRename(const string &sourceUri, const string &displayName, const string &destRelativePath)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, sourceUri);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri));
    return MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
}

string getRelativePath(const string &path)
{
    string relativePath = "";
    if (path.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = path.substr(ROOT_MEDIA_DIR.length()) + "/";
    }
    return relativePath;
}

int32_t HandleAlbumRename(const string &srcId, const string &srcPath, const string &displayName)
{
    size_t slashIndex = srcPath.rfind("/");
    string newAlbumPath = srcPath.substr(0, slashIndex) + SLASH_CHAR + displayName;
    int32_t errCode =  MediaFileUtils::RenameDir(srcPath, newAlbumPath);
    if (errCode == 0) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return errCode;
    }
    ValuesBucket valuesBucket;
    int64_t date_modified = MediaLibraryDataManagerUtils::GetAlbumDateModified(newAlbumPath);
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    string title = displayName.substr(0, displayName.find('.'));
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, title);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    std::vector<std::string> whereArgs = { srcId };
    int32_t count = 0;
    int32_t updateResult = MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count,
        MEDIALIBRARY_TABLE, valuesBucket, MEDIA_DATA_DB_ID + " = ?", whereArgs);
    if (updateResult == NativeRdb::E_OK) {
        // Update data "old albumPath/%" -> "new albumPath/%"
        // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
        // Update bucket_display_name "old album displayName" -> "new album displayName"
        // Update date_modified "old time" -> "new time"
        const std::string modifySql =
            "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace("
            + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), "
            + MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
            + ", '" + getRelativePath(srcPath) + "', '" + getRelativePath(newAlbumPath) + "'), "
            + MEDIA_DATA_DB_BUCKET_NAME + " = replace(" + MEDIA_DATA_DB_BUCKET_NAME + ", '"
            + srcPath.substr(slashIndex + 1) + "', '" + displayName + "'), "
            + MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified)
            + " where " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%'";
        MEDIA_DEBUG_LOG("HandleAlbumRename modifySql %{public}s", modifySql.c_str());
        errCode = MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
        CHECK_AND_PRINT_LOG(errCode == 0, "Album update sql failed");
    }
    return errCode;
}

int32_t MediaFileExtentionUtils::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    if (!CheckSupport(sourceUri)) {
        MEDIA_ERR_LOG("Rename not support distributed operation");
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string sourcePath, destRelativePath;
    int type;
    if (!GetFileFromResult(sourceUri, "", sourcePath, destRelativePath, type)) {
        MEDIA_ERR_LOG("Rename uri is not correct");
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    int ret = 0;
    MEDIA_DEBUG_LOG("Rename type %{public}d", type);
    if (type == MediaType::MEDIA_TYPE_ALBUM) {
        string sourceId = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
        ret = HandleAlbumRename(sourceId, sourcePath, displayName);
    } else {
        ret = HandleFileRename(sourceUri, displayName, destRelativePath);
    }
    newFileUri = Uri(sourceUri);
    return ret;
}

static bool GetSrcFileFromResult(const string &selectUri, const string &networkId, string &sourcePath,
    string &displayName, int &mediaType)
{
    auto result = MediaFileExtentionUtils::GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("GetFileFromRdb fail");
        return false;
    }
    result->GoToFirstRow();
    int columnIndex = 0;
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, columnIndex);
    result->GetInt(columnIndex, mediaType);
    result->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    result->GetString(columnIndex, sourcePath);
    result->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    result->GetString(columnIndex, displayName);
    return true;
}

int32_t HandleFileMove(const string &sourceUri, const string &displayName, const string &destRelativePath)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, sourceUri);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri));
    return MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
}

int32_t HandleAlbumMove(const string &srcId, const string &srcPath, const string &displayName,
    const string &destRelativePath, const string &bucketId)
{
    string newAlbumPath = ROOT_MEDIA_DIR + destRelativePath + displayName;
    int32_t errCode =  MediaFileUtils::RenameDir(srcPath, newAlbumPath);
    if (errCode == 0) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return errCode;
    }
    ValuesBucket valuesBucket;
    int64_t date_modified = MediaLibraryDataManagerUtils::GetAlbumDateModified(newAlbumPath);
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutInt(MEDIA_DATA_DB_PARENT_ID, stoi(bucketId));
    valuesBucket.PutInt(MEDIA_DATA_DB_BUCKET_ID, stoi(bucketId));
    std::vector<std::string> whereArgs = { srcId };
    int32_t count = 0;
    int32_t updateResult = MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count,
        MEDIALIBRARY_TABLE, valuesBucket, MEDIA_DATA_DB_ID + " = ?", whereArgs);
    if (updateResult == NativeRdb::E_OK) {
        // Update data "old albumPath/%" -> "new albumPath/%"
        // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
        // Update date_modified "old time" -> new time
        const std::string modifySql =
            "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace("
            + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), "
            + MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
            + ", '" + getRelativePath(srcPath) + "', '" + getRelativePath(newAlbumPath) + "'), "
            + MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified)
            + " where " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%'";
        MEDIA_DEBUG_LOG("HandleAlbumMove modifySql %{public}s", modifySql.c_str());
        errCode = MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
        CHECK_AND_PRINT_LOG(errCode == 0, "Album update sql failed");
    }
    return errCode;
}

int32_t MediaFileExtentionUtils::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    string targetUri = targetParentUri.ToString();
    if (!CheckSupport(sourceUri) || !CheckSupport(targetUri)) {
        MEDIA_ERR_LOG("Move not support distributed operation");
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string sourcePath, displayName;
    int type;
    if (!GetSrcFileFromResult(sourceUri, "", sourcePath, displayName, type)) {
        MEDIA_ERR_LOG("Move source uri is not correct");
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetAlbumRelativePath(targetUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Move target parent uri is not correct");
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    int ret = 0;
    MEDIA_DEBUG_LOG("Move type %{public}d", type);
    if (type == MediaType::MEDIA_TYPE_ALBUM) {
        string sourceId = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
        string bucketId = MediaLibraryDataManagerUtils::GetIdFromUri(targetUri);
        ret = HandleAlbumMove(sourceId, sourcePath, displayName, destRelativePath, bucketId);
    } else {
        ret = HandleFileMove(sourceUri, displayName, destRelativePath);
    }
    newFileUri = Uri(sourceUri);
    return ret;
}
} // Media
} // OHOS