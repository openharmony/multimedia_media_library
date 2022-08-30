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
#define MLOG_TAG "FileExtension"

#include "media_file_extention_utils.h"
#include "media_asset.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_smartalbum_map_db.h"
#include "result_set_utils.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::FileAccessFwk;

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
    if (slashIndex == string::npos) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
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

int32_t MediaFileExtentionUtils::CheckUriSupport(const string &uri)
{
    if (!MediaFileExtentionUtils::CheckUriValid(uri)) {
        MEDIA_ERR_LOG("Invalid uri");
        return E_URI_INVALID;
    }
    if (!MediaFileExtentionUtils::CheckDistributedUri(uri)) {
        MEDIA_ERR_LOG("CreateFile not support distributed operation");
        return E_DISTIBUTED_URI_NO_SUPPORT;
    }
    return E_SUCCESS;
}

MediaFileUriType MediaFileExtentionUtils::ResolveUri(const std::string &uri)
{
    size_t slashIndex = uri.rfind(SLASH_CHAR);
    if (slashIndex != std::string::npos) {
        std::string type = uri.substr(slashIndex);
        if (type == MEDIALIBRARY_ROOT) {
            return MediaFileUriType::URI_ROOT;
        } else {
            return MediaFileUriType::URI_DIR;
        }
    } else {
        return MediaFileUriType::URI_FILE;
    }
}

bool MediaFileExtentionUtils::CheckValidDirName(const std::string &displayName)
{
    AbsRdbPredicates absPredicates(MEDIATYPE_DIRECTORY_TABLE);
    absPredicates.EqualTo(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, displayName);
    vector<string> columns;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->rdbStore_->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, false, "Query functionality failed");
    int32_t count = 0;
    queryResultSet->GetRowCount(count);
    return count > 0;
}

int32_t MediaFileExtentionUtils::CheckMkdirValid(MediaFileUriType uriType, const string &parentUriStr,
    const string &displayName)
{
    if (uriType == MediaFileUriType::URI_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckDistributedUri(parentUriStr),
            E_DISTIBUTED_URI_NO_SUPPORT, "Mkdir not support distributed operation");
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckValidDirName(displayName + SLASH_CHAR),
            E_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    } else {
        auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDisplayName(displayName),
            E_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    }
    return E_SUCCESS;
}

void GetSingleFileInfo(const string &networkId, FileInfo &fileInfo, shared_ptr<AbsSharedResultSet> &result)
{
    int fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, result, TYPE_INT32));
    string mimeType = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MIME_TYPE, result, TYPE_STRING));
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    fileInfo.uri = MediaFileUtils::GetFileMediaTypeUri(MediaType(mediaType), networkId) +
        SLASH_CHAR + to_string(fileId);
    fileInfo.fileName = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    fileInfo.mimeType = mimeType;
    fileInfo.size =  get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_SIZE, result, TYPE_INT64));
    fileInfo.mtime = get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED, result, TYPE_INT64));
    if (mediaType == MEDIA_TYPE_ALBUM) {
        fileInfo.mode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    } else {
        fileInfo.mode = DOCUMENT_FLAG_REPRESENTS_FILE | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    }
}

void GetFileInfoFromResult(const string &networkId, shared_ptr<AbsSharedResultSet> &result, vector<FileInfo> &fileList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_LOG(count > 0, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_LOG(ret == 0, "Failed to shift at first row");
    fileList.reserve(count);
    FileInfo fileInfo;
    for (int i = 0; i < count; i++) {
        GetSingleFileInfo(networkId, fileInfo, result);
        fileList.push_back(fileInfo);
        ret = result->GoToNextRow();
        CHECK_AND_RETURN_LOG(ret == 0, "Failed to GoToNextRow");
    }
}

std::shared_ptr<AbsSharedResultSet> GetListFileResult(const string &queryUri, const string &selection,
    vector<string> &selectionArgs)
{
    Uri uri(queryUri);
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

shared_ptr<AbsSharedResultSet> MediaFileExtentionUtils::GetFileFromDB(const string &selectUri, const string &networkId)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    string selection = MEDIA_DATA_DB_ID + " = ? ";
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(selectUri);
    vector<string> selectionArgs = { id };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

bool MediaFileExtentionUtils::GetAlbumRelativePathFromDB(const string &selectUri, const string &networkId,
    string &relativePath)
{
    auto result = MediaFileExtentionUtils::GetFileFromDB(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "Failed to shift at first row");
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    CHECK_AND_RETURN_RET_LOG(mediaType == MEDIA_TYPE_ALBUM, false, "selectUri is not album");
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    string displayname = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    relativePath = relativePath + displayname + SLASH_CHAR;
    return true;
}

int32_t GetListFilePredicates(const string &selectUri, string &networkId, string &selection,
    vector<string> &selectionArgs)
{
    MediaFileUriType uriType = MediaFileExtentionUtils::ResolveUri(selectUri);
    MEDIA_DEBUG_LOG("selectUri %{public}s istFileType %{public}d", selectUri.c_str(), uriType);
    networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(selectUri);
    if (uriType == MediaFileUriType::URI_ROOT) {
        selection = MEDIA_DATA_DB_PARENT_ID + " = ?";
        selectionArgs = { to_string(ROOT_PARENT_ID) };
    } else if (uriType == MediaFileUriType::URI_DIR) {
        if (!MediaFileExtentionUtils::CheckUriValid(selectUri)) {
            MEDIA_ERR_LOG("selectUri is not valid uri %{private}s", selectUri.c_str());
            return E_URI_INVALID;
        }
        string relativePath;
        if (!MediaFileExtentionUtils::GetAlbumRelativePathFromDB(selectUri, networkId, relativePath)) {
            MEDIA_ERR_LOG("selectUri is not valid album uri %{private}s", selectUri.c_str());
            return E_URI_IS_NOT_ALBUM;
        }
        selection = MEDIA_DATA_DB_RELATIVE_PATH + " = ?";
        selectionArgs = { relativePath };
    } else {
        return E_URI_INVALID;
    }
    selection += " AND " + MEDIA_DATA_DB_IS_TRASH + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + "<> ? ";
    selectionArgs.push_back(to_string(NOT_ISTRASH));
    selectionArgs.push_back(to_string(MEDIA_TYPE_NOFILE));
    MEDIA_DEBUG_LOG("GetListFilePredicates selection %{public}s", selection.c_str());
    return E_SUCCESS;
}

int32_t MediaFileExtentionUtils::ListFile(const string &selectUri, vector<FileInfo> &fileList)
{
    string networkId, selection;
    vector<string> selectionArgs;
    int32_t errCode = GetListFilePredicates(selectUri, networkId, selection, selectionArgs);
    if (errCode != E_SUCCESS) {
        return errCode;
    }
    string queryUri;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    } else {
        queryUri = MEDIALIBRARY_DATA_URI;
    }
    std::shared_ptr<AbsSharedResultSet> resultSet = GetListFileResult(queryUri, selection, selectionArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "GetListFileResult Get fail");
    GetFileInfoFromResult(networkId, resultSet, fileList);
    return errCode;
}

bool GetRootInfo(shared_ptr<AbsSharedResultSet> &result, RootInfo &rootInfo)
{
    string networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, result, TYPE_STRING));
    rootInfo.uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_ROOT;
    rootInfo.displayName = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NAME, result, TYPE_STRING));
    rootInfo.deviceFlags = DEVICE_FLAG_SUPPORTS_READ;
    rootInfo.deviceType = DEVICE_SHARED_TERMINAL;
    return true;
}

void GetRootInfoFromResult(shared_ptr<AbsSharedResultSet> &result, vector<RootInfo> &rootList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_LOG(count > 0, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_LOG(ret == 0, "Failed to shift at first row");
    rootList.reserve(count + 1);
    for (int i = 0; i < count; i++) {
        RootInfo rootInfo;
        GetRootInfo(result, rootInfo);
        rootList.push_back(rootInfo);
        ret = result->GoToNextRow();
        CHECK_AND_RETURN_LOG(ret == 0, "Failed to GoToNextRow");
    }
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

int32_t MediaFileExtentionUtils::GetRoots(vector<RootInfo> &rootList)
{
    RootInfo rootInfo;
    // add local root
    rootInfo.uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_ROOT;
    rootInfo.displayName = MEDIALIBRARY_LOCAL_DEVICE_NAME;
    rootInfo.deviceFlags = DEVICE_FLAG_SUPPORTS_READ | DEVICE_FLAG_SUPPORTS_WRITE;
    rootInfo.deviceType = DEVICE_LOCAL_DISK;
    rootList.push_back(rootInfo);
    shared_ptr<AbsSharedResultSet> resultSet;
    GetActivePeer(resultSet);
    GetRootInfoFromResult(resultSet, rootList);
    return E_SUCCESS;
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
    auto result = MediaFileExtentionUtils::GetFileFromDB(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "Failed to shift at first row");
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    return true;
}

static bool GetAssetFromDB(const string &selectUri, const string &networkId, FileAsset &fileAsset)
{
    auto result = MediaFileExtentionUtils::GetFileFromDB(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "Failed to shift at first row");
    int32_t mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    string sourcePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH, result, TYPE_STRING));
    string displayName = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    string relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result,
        TYPE_STRING));
    fileAsset.SetMediaType((MediaType)mediaType);
    fileAsset.SetPath(sourcePath);
    fileAsset.SetDisplayName(displayName);
    fileAsset.SetRelativePath(relativePath);
    fileAsset.SetUri(selectUri);
    int id = stoi(MediaLibraryDataManagerUtils::GetIdFromUri(selectUri));
    fileAsset.SetId(id);
    return true;
}

int32_t HandleFileRename(const FileAsset &srcAsset, const string &displayName, const string &destRelativePath)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, srcAsset.GetMediaType());
    valuesBucket.PutString(MEDIA_DATA_DB_URI, srcAsset.GetUri());
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + MediaLibraryDataManagerUtils::GetIdFromUri(srcAsset.GetUri()));
    auto ret = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileRename Update ret %{private}d", ret);
        return ret;
    }
}

string GetRelativePathFromPath(const string &path)
{
    string relativePath = "";
    if (path.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = path.substr(ROOT_MEDIA_DIR.length());
    }
    return relativePath;
}

int32_t UpdateRenamedAlbumInfo(const string &srcId, const string &displayName, const string &newAlbumPath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, srcId);
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, displayName);
    int32_t count = 0;
    return MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count, valuesBucket, absPredicates);
}

int32_t UpdateSubFilesPath(const string &srcPath, const string &newAlbumPath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    std::string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
    // Update data "old albumPath/%" -> "new albumPath/%"
    modifySql += MEDIA_DATA_DB_FILE_PATH + " = replace("
        + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), ";
    // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
    modifySql += MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
        + ", '" + GetRelativePathFromPath(srcPath) + "/', '" + GetRelativePathFromPath(newAlbumPath) + "/'), ";
    // Update date_modified "old time" -> "new time"
    modifySql += MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified);
    modifySql += " WHERE " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%'";
    MEDIA_DEBUG_LOG("UpdateSubFilesPath modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t UpdateSubFilesBucketName(const string &srcId, const string &displayName)
{
    // Update bucket_display_name "old album displayName" -> "new album displayName"
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_BUCKET_NAME + " = '" + displayName;
    modifySql += "' WHERE " + MEDIA_DATA_DB_PARENT_ID + " = " + srcId + " AND " +
        MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    MEDIA_DEBUG_LOG("UpdateSubFilesBucketName modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t HandleAlbumRename(const FileAsset &srcAsset, const string &displayName)
{
    if (srcAsset.GetRelativePath().empty()) {
        MEDIA_ERR_LOG("Rename dir in root dir, denied");
        return E_DENIED_RENAME;
    }
    string srcPath = srcAsset.GetPath();
    size_t slashIndex = srcPath.rfind(SLASH_CHAR);
    string destPath = srcPath.substr(0, slashIndex) + SLASH_CHAR + displayName;
    if (MediaLibraryObjectUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Rename file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    bool succ = MediaFileUtils::RenameDir(srcPath, destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }
    string srcId = to_string(srcAsset.GetId());
    int32_t updateResult = UpdateRenamedAlbumInfo(srcId, displayName, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateRenamedAlbumInfo failed");
    updateResult = UpdateSubFilesPath(srcPath, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    updateResult = UpdateSubFilesBucketName(srcId, displayName);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL,
        "UpdateSubFilesBucketName failed");
    return E_SUCCESS;
}

int32_t MediaFileExtentionUtils::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid displayName %{private}s", displayName.c_str());
        return E_INVAVLID_DISPLAY_NAME;
    }
    FileAsset srcAsset;
    if (!GetAssetFromDB(sourceUri, "", srcAsset)) {
        MEDIA_ERR_LOG("Rename source uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetRelativePathFromDB(sourceUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Rename uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    if (srcAsset.GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        ret = HandleAlbumRename(srcAsset, displayName);
    } else {
        ret = HandleFileRename(srcAsset, displayName, destRelativePath);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}

int32_t HandleFileMove(const FileAsset &srcAsset, const string &destRelativePath)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, srcAsset.GetMediaType());
    valuesBucket.PutString(MEDIA_DATA_DB_URI, srcAsset.GetUri());
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, srcAsset.GetDisplayName());
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + MediaLibraryDataManagerUtils::GetIdFromUri(srcAsset.GetUri()));
    auto ret = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileMove Update ret %{private}d", ret);
        return ret;
    }
}

int32_t UpdateMovedAlbumInfo(const FileAsset &srcAsset, const string &bucketId, const string &newAlbumPath,
    const string &destRelativePath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, to_string(srcAsset.GetId()));
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutInt(MEDIA_DATA_DB_PARENT_ID, stoi(bucketId));
    valuesBucket.PutInt(MEDIA_DATA_DB_BUCKET_ID, stoi(bucketId));
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    int32_t count = 0;
    return MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count, valuesBucket, absPredicates);
}

int32_t HandleAlbumMove(const FileAsset &srcAsset, const string &destRelativePath, const string &bucketId)
{
    string destPath = ROOT_MEDIA_DIR + destRelativePath + srcAsset.GetDisplayName();
    if (MediaLibraryObjectUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Move file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    bool succ = MediaFileUtils::RenameDir(srcAsset.GetPath(), destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }
    int32_t updateResult = UpdateMovedAlbumInfo(srcAsset, bucketId, destPath, destRelativePath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateMovedAlbumInfo failed");
    updateResult = UpdateSubFilesPath(srcAsset.GetPath(), destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    return E_SUCCESS;
}

int32_t CheckFileExtension(const string &relativePath, const string &name, int32_t mediaType)
{
    std::unordered_map<std::string, DirAsset> dirQuerySetMap;
    MediaLibraryDataManager::GetInstance()->MakeDirQuerySetMap(dirQuerySetMap);
    MediaLibraryDirOperations dirOprn;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, name);
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    return dirOprn.HandleDirOperations(MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION,
        values, MediaLibraryDataManager::GetInstance()->rdbStore_, dirQuerySetMap);
}

void GetMoveSubFile(const string &srcPath, shared_ptr<AbsSharedResultSet> &result)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? ";
    vector<string> selectionArgs = { srcPath + SLASH_CHAR + "%" };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

bool CheckSubFileExtension(const string &srcPath, const string &destRelPath)
{
    shared_ptr<AbsSharedResultSet> result;
    GetMoveSubFile(srcPath, result);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, true, "AbsSharedResultSet empty");
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int32_t mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE,
            result, TYPE_INT32));
        string path = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH,
            result, TYPE_STRING));
        string name = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME,
            result, TYPE_STRING));
        if (mediaType == MEDIA_TYPE_ALBUM) {
            continue;
        }
        if (CheckFileExtension(destRelPath, name, mediaType) != E_SUCCESS) {
            return false;
        }
    }
    return true;
}

bool CheckRootDir(const FileAsset &srcAsset, const string &destRelPath)
{
    string srcRelPath = srcAsset.GetRelativePath();
    if (srcAsset.GetRelativePath().empty()) {
        MEDIA_ERR_LOG("Can not move the first level directories, like Pictures, Audios, ...");
        return false;
    }
    if (destRelPath.empty()) {
        MEDIA_ERR_LOG("Can not move to root dir");
        return false;
    }
    size_t srcPos = srcRelPath.find(SLASH_CHAR);
    size_t destPos = destRelPath.find(SLASH_CHAR);
    if (srcPos == string::npos || destPos == string::npos) {
        MEDIA_ERR_LOG("Invalid relativePath %{private}s, %{private}s", srcRelPath.c_str(), destRelPath.c_str());
        return false;
    }
    if (srcRelPath.substr(0, srcPos) != destRelPath.substr(0, destPos)) {
        MEDIA_INFO_LOG("move dir to other root dir");
        return CheckSubFileExtension(srcAsset.GetPath(), destRelPath);
    }
    return true;
}

int32_t MediaFileExtentionUtils::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    string targetUri = targetParentUri.ToString();
    CHECK_AND_RETURN_RET_LOG(sourceUri != targetUri, E_TWO_URI_ARE_THE_SAME,
        "sourceUri is the same as TargetUri");
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid source uri");
    ret = MediaFileExtentionUtils::CheckUriSupport(targetUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid targetUri uri");
    FileAsset srcAsset;
    if (!GetAssetFromDB(sourceUri, "", srcAsset)) {
        MEDIA_ERR_LOG("Move source uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetAlbumRelativePathFromDB(targetUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Move target parent uri is not correct %{private}s", targetUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    if (srcAsset.GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        if (!CheckRootDir(srcAsset, destRelativePath)) {
            MEDIA_ERR_LOG("Move file to another type alubm, denied");
            return E_DENIED_MOVE;
        }
        string bucketId = MediaLibraryDataManagerUtils::GetIdFromUri(targetUri);
        ret = HandleAlbumMove(srcAsset, destRelativePath, bucketId);
    } else {
        ret = HandleFileMove(srcAsset, destRelativePath);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}
} // Media
} // OHOS
