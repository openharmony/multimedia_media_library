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
#include "media_asset.h"
#include "media_file_utils.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
bool MediaFileExtentionUtils::CheckUriValid(const string &uri)
{
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
    size_t slashIndex = uri.rfind(SLASH_CHAR);
    string id = uri.substr(slashIndex + 1);
    if (id.empty()) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
    for (const char &c : id) {
        if (!isdigit(c)) {
            MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
            return false;
        }
    }
    return true;
}

MediaFileUriType MediaFileExtentionUtils::ResolveUri(const std::string &uri)
{
    size_t slashIndex = uri.rfind(SLASH_CHAR);
    if (slashIndex != std::string::npos) {
        std::string type = uri.substr(slashIndex);
        if (type == MEDIALIBRARY_ROOT) {
            return MediaFileUriType::URITYPE_ROOT;
        } else {
            return MediaFileUriType::URITYPE_DIR;
        }
    } else {
        return MediaFileUriType::URITYPE_FILE;
    }
}

bool MediaFileExtentionUtils::CheckValidDirName(const std::string &displayName)
{
    AbsRdbPredicates absPredicates(MEDIATYPE_DIRECTORY_TABLE);
    absPredicates.EqualTo(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, displayName);
    vector<string> columns;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->rdbStore_->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, DATA_ABILITY_FAIL, "Query functionality failed");
    int32_t count = 0;
    queryResultSet->GetRowCount(count);
    return count > 0;
}

void GetSingleFileInfo(const string &networkId, FileAccessFwk::FileInfo &fileInfo,
    shared_ptr<AbsSharedResultSet> &result)
{
    int fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, result, TYPE_INT32));
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    string uri = MediaFileUtils::GetFileMediaTypeUri(MediaType(mediaType), networkId) +
         '/' + to_string(fileId);
    fileInfo.uri = Uri(uri);
    fileInfo.fileName = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    fileInfo.mimeType = to_string(mediaType);
    fileInfo.size = ResultSetUtils::GetLongValFromColumn(MEDIA_DATA_DB_SIZE, result);
    fileInfo.mtime = ResultSetUtils::GetLongValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED, result);
    if (mediaType == MEDIA_TYPE_ALBUM) {
        fileInfo.mode = MEDIA_FILE_EXT_MODE_FOLDER;
    } else {
        fileInfo.mode = MEDIA_FILE_EXT_MODE_FILE;
    }
}

void GetFileInfoFromResult(const string &networkId, shared_ptr<AbsSharedResultSet> &result,
    vector<FileAccessFwk::FileInfo> &fileList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_LOG(count > 0, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    fileList.reserve(count);
    for (int i = 0; i < count; i++) {
        FileAccessFwk::FileInfo fileInfo;
        GetSingleFileInfo(networkId, fileInfo, result);
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

bool MediaFileExtentionUtils::GetAlbumRelativePathFromDB(const string &selectUri, const string &networkId,
    string &relativePath)
{
    auto result = GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    CHECK_AND_RETURN_RET_LOG(mediaType == MEDIA_TYPE_ALBUM, false, "selectUri is not album");
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    string displayname = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    relativePath = relativePath + displayname + SLASH_CHAR;
    return true;
}

int32_t MediaFileExtentionUtils::ListFile(string selectUri, vector<FileAccessFwk::FileInfo> &fileList)
{
    MediaFileUriType uriType = MediaFileExtentionUtils::ResolveUri(selectUri);
    MEDIA_DEBUG_LOG("selectUri %{public}s istFileType %{public}d", selectUri.c_str(), uriType);
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(selectUri);
    string selection;
    vector<string> selectionArgs;
    if (uriType == MediaFileUriType::URITYPE_ROOT) {
        selection = MEDIA_DATA_DB_PARENT_ID + " LIKE ? AND " + MEDIA_DATA_DB_IS_TRASH + " LIKE ? ";
        selectionArgs = { to_string(ROOT_PARENT_ID), to_string(NOT_ISTRASH) };
    } else if (uriType == MediaFileUriType::URITYPE_DIR) {
        if (!CheckUriValid(selectUri)) {
            MEDIA_ERR_LOG("selectUri is not valid uri %{private}s", selectUri.c_str());
            return MEDIA_FILE_URI_INVALID;
        }
        string relativePath;
        if (!GetAlbumRelativePathFromDB(selectUri, networkId, relativePath)) {
            MEDIA_ERR_LOG("selectUri is not valid album uri %{private}s", selectUri.c_str());
            return MEDIA_FILE_URI_IS_NOT_ALBUM;
        }
        selection = MEDIA_DATA_DB_RELATIVE_PATH + " LIKE ? AND " + MEDIA_DATA_DB_IS_TRASH + " LIKE ? ";
        selectionArgs = { relativePath, to_string(NOT_ISTRASH) };
    } else {
        return MEDIA_FILE_URI_INVALID;
    }
    string queryUri;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    } else {
        queryUri = MEDIALIBRARY_DATA_URI;
    }
    std::shared_ptr<AbsSharedResultSet> resultSet = GetListFileResult(queryUri, selection, selectionArgs);
    GetFileInfoFromResult(networkId, resultSet, fileList);
    return DATA_ABILITY_SUCCESS;
}

bool GetDeviceInfo(shared_ptr<AbsSharedResultSet> result,
    FileAccessFwk::DeviceInfo &deviceInfo)
{
    string networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, result, TYPE_STRING));
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_ROOT;
    deviceInfo.uri = Uri(uri);
    deviceInfo.displayName = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NAME, result, TYPE_STRING));
    return true;
}

int GetDeviceInfoFromResult(shared_ptr<AbsSharedResultSet> &result, vector<FileAccessFwk::DeviceInfo> &deviceList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, DATA_ABILITY_FAIL, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    deviceList.reserve(count + 1);
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
    Uri uri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

int32_t MediaFileExtentionUtils::GetRoots(vector<FileAccessFwk::DeviceInfo> &deviceList)
{
    FileAccessFwk::DeviceInfo deviceInfo;
    // add local root
    deviceInfo.uri = Uri(MEDIALIBRARY_DATA_URI + MEDIALIBRARY_ROOT);
    deviceInfo.displayName = MEDIALIBRARY_LOCAL_DEVICE_NAME;
    deviceList.push_back(deviceInfo);
    shared_ptr<AbsSharedResultSet> resultSet;
    GetActivePeer(resultSet);
    GetDeviceInfoFromResult(resultSet, deviceList);
    return DATA_ABILITY_SUCCESS;
}

bool MediaFileExtentionUtils::CheckDistributedUri(const string &uri)
{
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    if (!networkId.empty()) {
        MEDIA_ERR_LOG("not support distributed operation %{public}s", uri.c_str());
        return false;
    }
    return true;
}

static bool GetRelativePathFromDB(const string &selectUri, const string &networkId, string &relativePath)
{
    auto result = MediaFileExtentionUtils::GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    return true;
}

static bool GetSrcFileFromDB(const string &selectUri, const string &networkId, string &sourcePath, int &mediaType)
{
    auto result = MediaFileExtentionUtils::GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    sourcePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH, result, TYPE_STRING));
    return true;
}

static bool GetDisplayNameFromDB(const string &selectUri, const string &networkId, string &displayName)
{
    auto result = MediaFileExtentionUtils::GetFileFromRdb(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetDisplayNameFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    displayName = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    return true;
}

int32_t HandleFileRename(const string &sourceUri, const string &displayName, const string &destRelativePath)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + SLASH_CHAR + Media::MEDIA_FILEOPRN + SLASH_CHAR +
        Media::MEDIA_FILEOPRN_MODIFYASSET);
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

string GetRelativePathFromPath(const string &path)
{
    string relativePath = "";
    if (path.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = path.substr(ROOT_MEDIA_DIR.length());
    }
    return relativePath;
}

int32_t HandleAlbumRename(const string &srcId, const string &srcPath, const string &displayName)
{
    size_t slashIndex = srcPath.rfind(SLASH_CHAR);
    string newAlbumPath = srcPath.substr(0, slashIndex) + SLASH_CHAR + displayName;
    int32_t errCode =  MediaFileUtils::RenameDir(srcPath, newAlbumPath);
    if (errCode == 0) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return errCode;
    }
    ValuesBucket valuesBucket;
    int64_t date_modified = MediaLibraryDataManagerUtils::GetAlbumDateModified(newAlbumPath);
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, srcId);
    int32_t count = 0;
    int32_t updateResult = MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count,
        valuesBucket, absPredicates);
    if (updateResult == NativeRdb::E_OK) {
        std::string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
        // Update data "old albumPath/%" -> "new albumPath/%"
        modifySql += MEDIA_DATA_DB_FILE_PATH + " = replace("
            + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), ";
        // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
        modifySql += MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
            + ", '" + GetRelativePathFromPath(srcPath) + "', '" + GetRelativePathFromPath(newAlbumPath) + "'), ";
        // Update bucket_display_name "old album displayName" -> "new album displayName"
        modifySql += MEDIA_DATA_DB_BUCKET_NAME + " = replace(" + MEDIA_DATA_DB_BUCKET_NAME + ", '"
            + srcPath.substr(slashIndex + 1) + "', '" + displayName + "'), ";
        // Update date_modified "old time" -> "new time"
        modifySql +=  MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified);
        modifySql +=  " where " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%'";
        MEDIA_DEBUG_LOG("HandleAlbumRename modifySql %{private}s", modifySql.c_str());
        errCode = MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
        CHECK_AND_PRINT_LOG(errCode == 0, "Album update sql failed %{public}d", errCode);
    }
    return errCode;
}

int32_t MediaFileExtentionUtils::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    if (!CheckUriValid(sourceUri)) {
        return MEDIA_FILE_URI_INVALID;
    }
    if (!CheckDistributedUri(sourceUri)) {
        MEDIA_ERR_LOG("Rename not support distributed operation");
        return MEDIA_FILE_DISTIBUTED_URI_NO_SUPPORT;
    }
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid displayName %{private}s", displayName.c_str());
        return MEDIA_FILE_INVAVLID_DISPLAY_NAME;
    }
    string sourcePath, destRelativePath;
    int type;
    if (!GetSrcFileFromDB(sourceUri, "", sourcePath, type)) {
        MEDIA_ERR_LOG("Rename uri is not correct %{private}s", sourceUri.c_str());
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }

    if (!GetRelativePathFromDB(sourceUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Rename uri is not correct %{private}s", sourceUri.c_str());
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string destPath = ROOT_MEDIA_DIR + destRelativePath + displayName;
    if (MediaLibraryDataManagerUtils::isFileExistInDb(destPath, MediaLibraryDataManager::GetInstance()->rdbStore_)) {
        MEDIA_ERR_LOG("Rename file is existed %{private}s", destPath.c_str());
        return MEDIA_FILE_TARGET_FILE_EXIST;
    }
    int ret = 0;
    if (type == MediaType::MEDIA_TYPE_ALBUM) {
        string sourceId = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
        ret = HandleAlbumRename(sourceId, sourcePath, displayName);
    } else {
        ret = HandleFileRename(sourceUri, displayName, destRelativePath);
    }
    newFileUri = Uri(sourceUri);
    return ret;
}

int32_t HandleFileMove(const string &sourceUri, const string &displayName, const string &destRelativePath)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + SLASH_CHAR + Media::MEDIA_FILEOPRN + SLASH_CHAR +
        Media::MEDIA_FILEOPRN_MODIFYASSET);
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
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, srcId);
    int32_t count = 0;
    int32_t updateResult = MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count,
        valuesBucket, absPredicates);
    if (updateResult == NativeRdb::E_OK) {
        std::string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
        // Update data "old albumPath/%" -> "new albumPath/%"
        modifySql += MEDIA_DATA_DB_FILE_PATH + " = replace(" + MEDIA_DATA_DB_FILE_PATH + ", '"
            + srcPath + "' , '" + newAlbumPath + "'), ";
        // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
        modifySql += MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
            + ", '" + GetRelativePathFromPath(srcPath) + "', '" + GetRelativePathFromPath(newAlbumPath) + "'), ";
        // Update date_modified "old time" -> new time
        modifySql += MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified);
        modifySql += " where " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "%'";
        MEDIA_DEBUG_LOG("HandleAlbumMove modifySql %{private}s", modifySql.c_str());
        errCode = MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
        CHECK_AND_PRINT_LOG(errCode == 0, "Album update sql failed %{public}d", errCode);
    }
    return errCode;
}

int32_t MediaFileExtentionUtils::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    string targetUri = targetParentUri.ToString();
    CHECK_AND_RETURN_RET_LOG(sourceUri != targetUri, MEDIA_FILE_TWO_URI_ARE_THE_SAME,
        "sourceUri is the same as TargetUri");
    if (!CheckUriValid(sourceUri) || !CheckUriValid(targetUri)) {
        return MEDIA_FILE_URI_INVALID;
    }
    if (!CheckDistributedUri(sourceUri) || !CheckDistributedUri(targetUri)) {
        MEDIA_ERR_LOG("Move not support distributed operation");
        return MEDIA_FILE_DISTIBUTED_URI_NO_SUPPORT;
    }
    string sourcePath, displayName;
    int type;
    if (!GetSrcFileFromDB(sourceUri, "", sourcePath, type)) {
        MEDIA_ERR_LOG("Move source uri is not correct %{private}s", sourceUri.c_str());
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    if (!GetDisplayNameFromDB(sourceUri, "", displayName)) {
        MEDIA_ERR_LOG("Move source uri is not correct %{private}s", sourceUri.c_str());
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetAlbumRelativePathFromDB(targetUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Move target parent uri is not correct %{private}s", targetUri.c_str());
        return DATA_ABILITY_MODIFY_DATA_FAIL;
    }
    string destPath = ROOT_MEDIA_DIR + destRelativePath +
        MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(sourcePath);
    if (MediaLibraryDataManagerUtils::isFileExistInDb(destPath, MediaLibraryDataManager::GetInstance()->rdbStore_)) {
        MEDIA_ERR_LOG("Move file is existed %{private}s", destPath.c_str());
        return MEDIA_FILE_TARGET_FILE_EXIST;
    }
    int ret = 0;
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
