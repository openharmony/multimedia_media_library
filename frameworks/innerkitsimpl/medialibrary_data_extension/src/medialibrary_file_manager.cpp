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

#include "medialibrary_file_manager.h"

#include "media_file_utils.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
MediaLibraryFileManager::MediaLibraryFileManager()
{
    uniStore_ = MediaLibraryUnistoreManager::GetInstance().GetUnistore(MediaLibraryUnistoreType::RDB);
}

int32_t MediaLibraryFileManager::CreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // UNKNOWN_OBJECT mode
    if (uniStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryFileManager Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }
    int64_t outRowId = DATA_ABILITY_FAIL;
    (void)uniStore_->Insert(cmd, outRowId);
    return outRowId;
}

int32_t MediaLibraryFileManager::BatchCreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryFileManager::DeleteFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // string fileId = cmd.GetOprnFileId();
    // if (fileId == "-1") {
    //     MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
    //     return DATA_ABILITY_FAIL;
    // }
    return DeleteInfoInDbWithId(cmd);
}

int32_t MediaLibraryFileManager::RenameFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryFileManager::ModifyFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // string fileId = cmd.GetOprnFileId();
    // if (fileId == "-1") {
    //     MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
    //     return DATA_ABILITY_FAIL;
    // }
    return ModifyInfoInDbWithId(cmd);
}

std::shared_ptr<DataShare::ResultSetBridge> MediaLibraryFileManager::LookupFile(MediaLibraryCommand &cmd,
                                                                                const std::vector<std::string> &columns)
{
    MEDIA_INFO_LOG("[lqh] enter");
    auto queryResultSet = uniStore_->Query(cmd, columns);
    return RdbUtils::ToResultSetBridge(queryResultSet);
}

int32_t MediaLibraryFileManager::OpenFile(MediaLibraryCommand &cmd, const string &mode)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string uriString = cmd.GetUri().ToString();
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(uriString);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain path from Database");
        return DATA_ABILITY_FAIL;
    }

    bool isWriteMode = MediaLibraryDataManagerUtils::CheckOpenMode(mode);
    if (isWriteMode) {
        if (MediaLibraryDataManagerUtils::CheckFilePending(fileAsset)) {
            MEDIA_ERR_LOG("MediaLibraryDataManager OpenFile: File is pending");
            return DATA_ABILITY_HAS_OPENED_FAIL;
        }
    }

    string path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    int32_t fd = fileAsset->OpenAsset(path, mode);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{private}d, errno %{private}d", fd, errno);
        return DATA_ABILITY_HAS_FD_ERROR;
    }
    if (isWriteMode && fd > 0) {
        int32_t errorCode = SetFilePending(uriString, true);
        if (errorCode == DATA_ABILITY_FAIL) {
            fileAsset->CloseAsset(fd);
            MEDIA_ERR_LOG("MediaLibraryDataManager OpenFile: Set file to pending DB error");
            return DATA_ABILITY_HAS_DB_ERROR;
        }
    }
    MEDIA_INFO_LOG("MediaLibraryDataManager OpenFile: Success");
    return fd;
}

int32_t MediaLibraryFileManager::CloseFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    MEDIA_ERR_LOG("Not a real file in filesystem, close file failed!");
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryFileManager::IsDictionary(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    int32_t id = -1;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(id);
    }
    MEDIA_INFO_LOG("HandleIsDirectoryAsset id = %{private}d", id);
    if (id == -1) {
        MEDIA_ERR_LOG("HandleIsDirectoryAsset: not dictionary id, can't do the judgement!");
        return DATA_ABILITY_FAIL;
    }

    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
    std::vector<std::string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore_->Query(cmd, columns);
    string path = "";
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
        queryResultSet->GetString(columnIndex, path);
        MEDIA_INFO_LOG("HandleIsDirectoryAsset path = %{private}s", path.c_str());
    }
    if (MediaFileUtils::IsDirectory(path)) {
        MEDIA_INFO_LOG("HandleIsDirectoryAsset: %{private}s is a dictionary!", path.c_str());
        return DATA_ABILITY_SUCCESS;
    }
    MEDIA_INFO_LOG("HandleIsDirectoryAsset: %{private}s is NOT a dictionary!", path.c_str());
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryFileManager::GetCapatity(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    bool isFavourite = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_FAV, valueObject)) {
        valueObject.GetBool(isFavourite);
    }

    bool isTrash = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_TRASH, valueObject)) {
        valueObject.GetBool(isTrash);
    }

    if (isFavourite) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isFavourite");
        resultSet = QueryFavFiles(cmd);
    } else if (isTrash) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isTrash");
        resultSet = QueryTrashFiles(cmd);
    }

    if (resultSet != nullptr) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity not get ");
        return DATA_ABILITY_FAIL;
    }

    int32_t albumCapatity = DATA_ABILITY_FAIL;
    resultSet->GetRowCount(albumCapatity);
    MEDIA_INFO_LOG("HandleGetAlbumCapacity GetRowCount %{private}d", albumCapatity);
    return albumCapatity;
}

string MediaLibraryFileManager::GetPathFromDb(const string &id)
{
    string filePath("");
    vector<string> selectionArgs = {};
    int32_t columnIndex(0);

    if ((id.empty()) || (!MediaFileUtils::IsNumber(id)) || (stoi(id) == -1)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return filePath;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);

    shared_ptr<ResultSet> queryResultSet = uniStore_->Query(cmd, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, filePath);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain file path");

    return filePath;
}

int32_t MediaLibraryFileManager::GetIdByPathFromDb(const string &path)
{
    int32_t fileId = -1;
    int32_t columnIndex = 0;

    if (path.empty()) {
        MEDIA_ERR_LOG("Id for the path is incorrect");
        return fileId;
    }
    string newPath = path;
    if (newPath.back() == '/') {
        newPath.pop_back();
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, newPath);

    shared_ptr<ResultSet> queryResultSet = uniStore_->Query(cmd, {MEDIA_DATA_DB_ID});
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, fileId, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain column index");

    ret = queryResultSet->GetInt(columnIndex, fileId);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain file id");

    return fileId;
}

int32_t MediaLibraryFileManager::ModifyInfoInDbWithPath(MediaLibraryCommand &cmd, const string &path)
{

    MEDIA_INFO_LOG("[lqh] enter");
    vector<string> whereArgs = {path};
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = ?";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t updatedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Update(cmd, updatedRows);
    if (result != E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{private}d. Deleted %{private}d", result, updatedRows);
    }

    return updatedRows;
}

int32_t MediaLibraryFileManager::ModifyInfoInDbWithId(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
    // update file
    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        if (strRow.empty() || stoi(strRow) == -1 || !MediaFileUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryFileManager DeleteFile: Index not digit");
            return DATA_ABILITY_FAIL;
        }
        strDeleteCondition = MEDIA_DATA_DB_ID + " = ? ";
        vector<string> whereArgs = {strRow};
        cmd.GetAbsRdbPredicates()->SetWhereClause(strDeleteCondition);
        cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    }

    int32_t updatedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Update(cmd, updatedRows);
    if (result != E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{private}d. Deleted %{private}d", result, updatedRows);
    }

    return updatedRows;
}

int32_t MediaLibraryFileManager::DeleteInfoInDbWithPath(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_INFO_LOG("[lqh] enter");
    vector<string> whereArgs = {path};
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = ?";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Delete(cmd, deletedRows);
    if (result != E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
    }

    return deletedRows;
}

int32_t MediaLibraryFileManager::DeleteInfoInDbWithId(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;

    // delete file
    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        if (strRow.empty() || stoi(strRow) == -1 || !MediaFileUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryFileManager DeleteFile: Index not digit");
            return DATA_ABILITY_FAIL;
        }
        strDeleteCondition = MEDIA_DATA_DB_ID + " = ? ";
        vector<string> whereArgs = {strRow};
        cmd.GetAbsRdbPredicates()->SetWhereClause(strDeleteCondition);
        cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    }

    int32_t deletedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Delete(cmd, deletedRows);
    if (result != E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
    }

    return deletedRows;
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    vector<string> selectionArgs = {};
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);
    vector<string> columns;

    shared_ptr<AbsSharedResultSet> resultSet = uniStore_->Query(cmd, columns);

    return resultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryFavFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_IS_FAV + " = 1 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    return QueryFiles(cmd);
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryTrashFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_DATE_TRASHED + " > 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    return QueryFiles(cmd);
}

int32_t MediaLibraryFileManager::SetFilePending(string &uriStr, bool isPending)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

shared_ptr<FileAsset> MediaLibraryFileManager::GetFileAssetFromDb(const string &uriStr)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string id = MediaFileUtils::GetIdFromUri(uriStr);
    string networkId = MediaFileUtils::GetNetworkIdFromUri(uriStr);

    if ((id.empty()) || (!MediaFileUtils::IsNumber(id)) || (stoi(id) == -1)) {
        MEDIA_ERR_LOG("Id for the path is incorrect");
        return nullptr;
    }
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;
    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    cmd.SetOprnDevice(networkId);
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);

    shared_ptr<AbsSharedResultSet> resultSet = QueryFiles(cmd);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain file asset from database");
        return nullptr;
    }

    shared_ptr<DataShare::ResultSetBridge> rsBridge = RdbUtils::ToResultSetBridge(resultSet);
    shared_ptr<DataShare::DataShareResultSet> dataShareRs = make_shared<DataShare::DataShareResultSet>(rsBridge);
    shared_ptr<FetchResult> fetchFileResult = make_shared<FetchResult>(dataShareRs);
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain fetch file result");
        return nullptr;
    }
    fetchFileResult->networkId_ = networkId;
    return fetchFileResult->GetFirstObject();
}

} // namespace Media
} // namespace OHOS
