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

#include "medialibrary_object_utils.h"

#include "album_asset.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_thumbnail.h"
#include "value_object.h"
#include "medialibrary_dir_operations.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

// return: dir id in database
int32_t MediaLibraryObjectUtils::CreateDirWithPath(const string &dirPath)
{
    int64_t rowId = -1;
    if (!dirPath.empty()) {
        ValuesBucket values;
        values.PutString(MEDIA_DATA_DB_FILE_PATH, dirPath);
        MediaLibraryCommand cmd(FILESYSTEM_ALBUM, CREATE, values);
        (void)CreateDirObj(cmd, rowId);
    }
    return rowId;
}

NativeAlbumAsset MediaLibraryObjectUtils::GetDirAsset(const string &path)
{
    NativeAlbumAsset dirAsset;
    if (path.empty()) {
        MEDIA_WARNING_LOG("Path is empty, create failed!");
        dirAsset.SetAlbumId(DATA_ABILITY_FAIL);
        return dirAsset;
    }

    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        dirAsset.SetAlbumId(DATA_ABILITY_FAIL);
        return dirAsset;
    }

    int32_t dirId = CreateDirWithPath(path);
    MEDIA_WARNING_LOG("After CreateDirWithPath, get dirId = %{private}d!", dirId);
    dirAsset.SetAlbumId(dirId);
    if (dirId < 0) {
        return dirAsset;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(dirId));
    auto queryResultSet = uniStore_->Query(cmd, {});
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexName;
        string nameVal;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndexName);
        queryResultSet->GetString(columnIndexName, nameVal);
        dirAsset.SetAlbumName(nameVal);
        MEDIA_INFO_LOG("HandleModifyAsset bucketId = %{private}d bucketName = %{private}s", dirId, nameVal.c_str());
    }
    return dirAsset;
}

int32_t MediaLibraryObjectUtils::DeleteInvalidRowInDb(const string &path)
{
    if (GetIdByPathFromDb(path) < 0) {
        // path is not in database, no need to delete
        return DATA_ABILITY_SUCCESS;
    }

    FileAsset fileAsset;
    if (fileAsset.IsFileExists(path)) {
        // File aready exist, not need to create again
        return DATA_ABILITY_DUPLICATE_CREATE;
    }

    MediaLibraryCommand deleteCmd(FILESYSTEM_ASSET, DELETE);
    if (DeleteInfoInDbWithPath(deleteCmd, path) != DATA_ABILITY_SUCCESS) {
        // Delete the record in database if file is not in filesystem any more
        MEDIA_WARNING_LOG("CreateFileAsset: delete info in db failed");
        return DATA_ABILITY_FAIL;
    }
    return DATA_ABILITY_SUCCESS;
}

// create
int32_t MediaLibraryObjectUtils::CreateFileObj(MediaLibraryCommand &cmd)
{
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    string relativePath(""), path(""), displayName("");
    int32_t mediaType = static_cast<int32_t>(MEDIA_TYPE_FILE);
    FileAsset fileAsset;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    // Obtain file displayName
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(displayName);
    }

    // Obtain relative path
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
        path = ROOT_MEDIA_DIR + relativePath + displayName;
    }

    // Obtain mediatype
    if (values.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject)) {
        valueObject.GetInt(mediaType);
        fileAsset.SetMediaType(static_cast<MediaType>(mediaType));
    }

    NativeAlbumAsset dirAsset = GetDirAsset(ROOT_MEDIA_DIR + relativePath);
    if (dirAsset.GetAlbumId() < 0) {
        return dirAsset.GetAlbumId();
    }

    int32_t errCode = DeleteInvalidRowInDb(path);
    if (errCode != DATA_ABILITY_SUCCESS) {
        return errCode;
    }

    errCode = fileAsset.CreateAsset(path);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_WARNING_LOG("CreateFileAsset: create file asset failed");
        return errCode;
    }
    // Fill basic file information into DB
    ValuesBucket updatedAssetInfo;
    updatedAssetInfo.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    updatedAssetInfo.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    updatedAssetInfo.PutString(MEDIA_DATA_DB_NAME, displayName);
    updatedAssetInfo.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    struct stat statInfo {};
    if (stat(path.c_str(), &statInfo) == 0) {
        updatedAssetInfo.PutLong(MEDIA_DATA_DB_SIZE, statInfo.st_size);
        updatedAssetInfo.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    }
    updatedAssetInfo.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    updatedAssetInfo.PutInt(MEDIA_DATA_DB_BUCKET_ID, dirAsset.GetAlbumId());
    updatedAssetInfo.PutInt(MEDIA_DATA_DB_PARENT_ID, dirAsset.GetAlbumId());
    updatedAssetInfo.PutString(MEDIA_DATA_DB_BUCKET_NAME, dirAsset.GetAlbumName());
    cmd.SetValueBucket(updatedAssetInfo);
    int64_t outRowId = -1;
    errCode = uniStore_->Insert(cmd, outRowId);
    MEDIA_INFO_LOG("Insert errCode = %d, outRowId = %lld", errCode, outRowId);
    return (errCode == NativeRdb::E_OK) ? outRowId : errCode;
}

NativeAlbumAsset MediaLibraryObjectUtils::GetLastDirExistInDb(const std::string &dirPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    NativeAlbumAsset dirAsset;
    string lastPath = dirPath;
    if (lastPath.back() == '/') {
        lastPath.pop_back();
    }
    int32_t dirId = 0;
    int32_t lastPathId = -1;
    do {
        size_t slashIndex = lastPath.rfind(SLASH_CHAR);
        if (slashIndex != string::npos && lastPath.length() > ROOT_MEDIA_DIR.length()) {
            lastPath = lastPath.substr(0, slashIndex);
            MEDIA_INFO_LOG("GetLastAlbumExistInDb lastPath = %{private}s", lastPath.c_str());
        } else {
            break;
        }
        lastPathId = GetIdByPathFromDb(lastPath);
        if (lastPathId >= 0) {
            dirId = lastPathId;
        }
    } while (lastPathId < 0);
    dirAsset.SetAlbumId(dirId);
    dirAsset.SetAlbumPath(lastPath);
    return dirAsset;
}

int32_t MediaLibraryObjectUtils::DeleteRows(const std::vector<int64_t> &rowIds)
{
    int32_t errCode = 0;

    for (auto id : rowIds) {
        MediaLibraryCommand cmd(FILESYSTEM_ASSET, DELETE);
        errCode = DeleteInfoInDbWithId(cmd, to_string(id));
    }
    return errCode;
}

int32_t MediaLibraryObjectUtils::InsertDirToDbRecursively(const std::string &dirPath, int64_t &rowId)
{
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    NativeAlbumAsset dirAsset = GetLastDirExistInDb(dirPath);
    string parentPath = dirAsset.GetAlbumPath();
    int64_t parentId = dirAsset.GetAlbumId();
    string path = dirPath;
    vector<int64_t> outIds;
    rowId = parentId;

    while (parentPath.length() < path.length() - 1) {
        ValuesBucket values;
        string relativePath;
        if (path.substr(path.length() - 1) != "/") {
            path = path + "/";
        }
        size_t index = path.find("/", parentPath.length() + 1);
        parentPath = path.substr(0, index);
        values.PutString(MEDIA_DATA_DB_FILE_PATH, parentPath);
        string title = parentPath;
        size_t titleIndex = parentPath.rfind('/');
        if (index != string::npos) {
            title = parentPath.substr(titleIndex + 1);
            string tmpPath = parentPath.substr(0, titleIndex);
            if (tmpPath.length() > ROOT_MEDIA_DIR.length()) {
                relativePath = tmpPath.substr(ROOT_MEDIA_DIR.length()) + "/";
            }
        }
        if (!MediaFileUtils::CheckDisplayName(title)) {
            DeleteRows(outIds);
            MEDIA_WARNING_LOG("Check display name failed!");
            return DATA_ABILITY_VIOLATION_PARAMETERS;
        }
        values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        values.PutString(MEDIA_DATA_DB_TITLE, title);
        values.PutString(MEDIA_DATA_DB_NAME, title);
        values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
        values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentId);
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::GetAlbumDateModified(path));
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(path));

        MediaLibraryCommand cmd(FILESYSTEM_ALBUM, CREATE);
        cmd.SetValueBucket(values);
        if (uniStore_->Insert(cmd, rowId) != NativeRdb::E_OK) {
            rowId = parentId;
            return DATA_ABILITY_FAIL;
        }
        parentId = rowId;
        outIds.push_back(rowId);
    }
    MEDIA_INFO_LOG("parentId = %{private}lld", parentId);
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryObjectUtils::CreateDirObj(MediaLibraryCommand &cmd, int64_t &rowId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    AlbumAsset dirAsset;
    string dirPath = "";
    ValueObject valueObject;
    const ValuesBucket &values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject)) {
        valueObject.GetString(dirPath);
    }
    if (dirPath.empty()) {
        MEDIA_WARNING_LOG("Dir path is empty!");
        return DATA_ABILITY_FAIL;
    }
    dirAsset.SetAlbumPath(dirPath);
    rowId = GetIdByPathFromDb(dirPath);
    MEDIA_INFO_LOG("dirPath %{private}s id in database is %{private}lld", dirPath.c_str(), rowId);
    if (rowId < 0) {
        dirAsset.CreateAlbumAsset();
        return InsertDirToDbRecursively(dirPath, rowId);
    }

    if (!MediaFileUtils::IsDirectory(dirPath)) {
        dirAsset.CreateAlbumAsset();
        return DATA_ABILITY_SUCCESS;
    }
    return DATA_ABILITY_DUPLICATE_CREATE;
}

int32_t MediaLibraryObjectUtils::DeleteEmptyDirsRecursively(int32_t dirId)
{
    int32_t deleteErrorCode = DATA_ABILITY_SUCCESS;
    if (dirId == -1) {
        return DATA_ABILITY_FAIL;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    auto mediaLibDirAbsPred = cmd.GetAbsRdbPredicates();
    mediaLibDirAbsPred->SetWhereClause(DIR_PARENT_WHERECLAUSE);
    mediaLibDirAbsPred->SetWhereArgs({to_string(dirId)});
    auto resultSet = uniStore_->Query(cmd, {});
    int32_t asParentCount = 0;
    resultSet->GetRowCount(asParentCount);
    MEDIA_INFO_LOG("asParentCount = %{public}d", asParentCount);

    if (asParentCount == 0) {
        mediaLibDirAbsPred->SetWhereClause(DIR_FILE_WHERECLAUSE);
        mediaLibDirAbsPred->SetWhereArgs({to_string(dirId)});
        auto queryParentResultSet = uniStore_->Query(cmd, {});
        if (queryParentResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexParentId, columnIndexDir;
            int32_t parentIdVal = 0;
            string dirVal;
            queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
            queryParentResultSet->GetInt(columnIndexParentId, parentIdVal);
            queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndexDir);
            queryParentResultSet->GetString(columnIndexDir, dirVal);
            if (parentIdVal == 0) {
                return DATA_ABILITY_SUCCESS;
            }
            MEDIA_INFO_LOG("dirVal = %{private}s", dirVal.c_str());
            MEDIA_INFO_LOG("parentIdVal = %{public}d", parentIdVal);

            MediaLibraryDirDb dirDbOprn;
            deleteErrorCode =
                dirDbOprn.DeleteDirInfo(dirId, MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
            if (deleteErrorCode != DATA_ABILITY_SUCCESS) {
                MEDIA_ERR_LOG("DeleteDirInfo failed");
                return deleteErrorCode;
            }
            if (!MediaFileUtils::DeleteDir(dirVal)) {
                MEDIA_ERR_LOG("deleteDir failed");
                return DATA_ABILITY_DELETE_DIR_FAIL;
            }
            DeleteEmptyDirsRecursively(parentIdVal);
        }
    }

    return deleteErrorCode;
}

// Restriction: input param cmd MUST have file id in either uri or valuebucket
int32_t MediaLibraryObjectUtils::DeleteFileObj(MediaLibraryCommand &cmd, const string &filePath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    FileAsset fileAsset;
    int32_t errCode = fileAsset.DeleteAsset(filePath);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete file in filesystem failed!");
        return errCode;
    }
    // must get parent id BEFORE deleting file in database
    int32_t parentId = GetParentIdWithId(cmd.GetOprnFileId());
    int32_t deleteRows = DeleteInfoInDbWithId(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete file info in database failed!");
        return DATA_ABILITY_FAIL;
    }
    // if delete successfully, 1) update modify time
    string dirPath = MediaLibraryDataManagerUtils::GetParentPath(filePath);
    UpdateDateModified(dirPath);
    // 2) recursively delete empty parent dirs
    if (DeleteEmptyDirsRecursively(parentId) != DATA_ABILITY_SUCCESS) {
        return DATA_ABILITY_FAIL;
    }
    // 3) delete relative records in smart album
    MediaLibraryCommand deleteSmartMapCmd(SMART_ALBUM_MAP, DELETE);
    string strCondition = SMARTALBUM_MAP_DE_ASSETS_COND + " = ?";
    deleteSmartMapCmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    errCode = DeleteInfoInDbWithId(deleteSmartMapCmd, cmd.GetOprnFileId());
    return deleteRows;
}

int32_t MediaLibraryObjectUtils::DeleteDirObj(MediaLibraryCommand &cmd, const string &dirPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    AlbumAsset dirAsset;
    if (!dirAsset.DeleteAlbumAsset(dirPath)) {
        MEDIA_ERR_LOG("Delete album asset failed!");
        return DATA_ABILITY_FAIL;
    }

    int32_t parentId = GetParentIdWithId(cmd.GetOprnFileId());
    int32_t deleteRows = DeleteInfoInDbWithId(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete album info in database failed!");
        return DATA_ABILITY_FAIL;
    }
    // need to delete subfiles in the album when deleting album, delete: xx/xxx/album_name/%
    MediaLibraryCommand deleteSubfilesCmd(FILESYSTEM_ASSET, DELETE);
    string strCondition = MEDIA_DATA_DB_FILE_PATH + " LIKE ?";
    deleteSubfilesCmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    vector<string> whereArgs = {(dirPath.back() != '/' ? (dirPath + "/%") : (dirPath + "%"))};
    deleteSubfilesCmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = ALBUM_OPERATION_ERR;
    int32_t deleteResult = uniStore_->Delete(deleteSubfilesCmd, deletedRows);
    if (deleteResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete subfiles in album %{private}s failed", dirPath.c_str());
        return deleteResult;
    }
    if (DeleteEmptyDirsRecursively(parentId) != DATA_ABILITY_SUCCESS) {
        return DATA_ABILITY_FAIL;
    }
    return deleteRows;
}

// Restriction: input param cmd MUST have id in uri
int32_t MediaLibraryObjectUtils::RenameFileObj(MediaLibraryCommand &cmd, const string &srcFilePath,
                                               const string &dstFilePath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (srcFilePath.compare(dstFilePath) == 0) {
        // why: 如果不改名字，只改相关信息？
        MEDIA_ERR_LOG("Failed to modify the file, the path of new file is the same as old");
        return DATA_ABILITY_FAIL;
    }

    string dstAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(dstFilePath);
    MEDIA_INFO_LOG("dstAlbumPath = %{private}s", dstAlbumPath.c_str());
    NativeAlbumAsset dirAsset = GetDirAsset(dstAlbumPath);
    if (dirAsset.GetAlbumId() <= 0) {
        MEDIA_WARNING_LOG("Failed to get or create directory");
        return DATA_ABILITY_FAIL;
    }

    FileAsset fileAsset;
    int32_t errCode = fileAsset.ModifyAsset(srcFilePath, dstFilePath);
    if (errCode == DATA_ABILITY_MODIFY_DATA_FAIL) {
        MEDIA_ERR_LOG("Failed to modify the file in the device");
        return errCode;
    }
    string dstFileName = MediaLibraryDataManagerUtils::GetFileName(dstFilePath);
    if (ProcessNoMediaFile(dstFileName, dstAlbumPath) || ProcessHiddenFile(dstFileName, srcFilePath)) {
        MEDIA_ERR_LOG("New file is a .nomedia file or hidden file.");
        // why: return fail insteal of success
        return DATA_ABILITY_FAIL;
    }

    if (UpdateFileInfoInDb(cmd, dstFilePath, dirAsset.GetAlbumId(), dirAsset.GetAlbumName()) > 0) {
        UpdateDateModified(dstAlbumPath);
        string srcAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(srcFilePath);
        UpdateDateModified(srcAlbumPath);
    }
    return errCode;
}

// Restriction: input param cmd MUST have id in uri
int32_t MediaLibraryObjectUtils::RenameDirObj(MediaLibraryCommand &cmd, const string &srcDirPath,
                                              const string &dstDirPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    if (srcDirPath.empty() || dstDirPath.empty()) {
        MEDIA_ERR_LOG("srcDirPath or dstDirPath is empty, rename failed!");
        return DATA_ABILITY_FAIL;
    }

    if (!MediaFileUtils::RenameDir(srcDirPath, dstDirPath)) {
        MEDIA_ERR_LOG("Rename directory failed!");
        return DATA_ABILITY_FAIL;
    }
    string dstDirName = MediaLibraryDataManagerUtils::GetFileName(dstDirPath);
    if (ProcessHiddenDir(dstDirName, srcDirPath) == DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("New album is a hidden album.");
        return DATA_ABILITY_SUCCESS;
    }

    ValuesBucket values = cmd.GetValueBucket();
    values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, MediaLibraryDataManagerUtils::GetParentPath(dstDirPath));
    values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, dstDirPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(dstDirPath));

    cmd.SetValueBucket(values);
    int32_t retVal = ModifyInfoInDbWithId(cmd);
    if (retVal == DATA_ABILITY_SUCCESS && !dstDirPath.empty()) {
        // Update the path, relative path and album Name for internal files
        const std::string modifyAlbumInternalsStmt =
            "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace(" +
            MEDIA_DATA_DB_FILE_PATH + ", '" + srcDirPath + "/' , '" + dstDirPath + "/'), " +
            MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH + ", '" + srcDirPath + "', '" +
            dstDirPath + "'), " + MEDIA_DATA_DB_ALBUM_NAME + " = replace(" + MEDIA_DATA_DB_ALBUM_NAME + ", '" +
            MediaLibraryDataManagerUtils::GetFileName(srcDirPath) + "', '" + dstDirName + "')" + "where " +
            MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcDirPath + "/%'";

        auto ret = uniStore_->ExecuteSql(modifyAlbumInternalsStmt);
        if (ret != 0) {
            MEDIA_ERR_LOG("Album update sql failed");
            return DATA_ABILITY_FAIL;
        }
    }
    return retVal;
}

int32_t MediaLibraryObjectUtils::OpenFile(MediaLibraryCommand &cmd, const string &mode)
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

int32_t MediaLibraryObjectUtils::CloseFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strFileId = cmd.GetOprnFileId();
    if (strFileId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return DATA_ABILITY_FAIL;
    }
    string srcPath = GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strFileId.c_str());
        return DATA_ABILITY_FAIL;
    }

    int32_t errorCode = SetFilePending(srcPath, false);
    if (errorCode == DATA_ABILITY_FAIL) {
        MEDIA_ERR_LOG("HandleCloseAsset Set file to pending DB error");
        return DATA_ABILITY_FAIL;
    }

    string fileName = MediaLibraryDataManagerUtils::GetFileName(srcPath);
    if ((fileName.length() != 0) && (fileName.at(0) != '.')) {
        string dirPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModified(dirPath);
    }

    MediaLibraryThumbnail thumbnail;
    ThumbRdbOpt opt{.store = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(),
                    .table = MEDIALIBRARY_TABLE,
                    .row = strFileId};
    string kvId;
    thumbnail.CreateThumbnail(opt, kvId);
    ScanFile(srcPath);
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryObjectUtils::ScanFile(string &path)
{
    MEDIA_INFO_LOG("[lqh] enter");
    std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
    if (scanFileCb == nullptr) {
        MEDIA_WARNING_LOG("Failed to create scan file callback object");
        return ;
    }
    int ret = MediaScannerObj::GetMediaScannerInstance()->ScanFile(path, nullptr);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed!");
    }
}

bool MediaLibraryObjectUtils::ProcessNoMediaFile(const string &dstFileName, const string &dstAlbumPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return false;
    }

    if (dstFileName.empty() || dstFileName != ".nomedia") {
        MEDIA_INFO_LOG("Not a .nomedia file, no need to do anything.");
        return false;
    }

    // the whole folder containing .nomedia file is invisible in database
    MediaLibraryCommand cmd(FILESYSTEM_ASSET, DELETE);
    string strCondition = MEDIA_DATA_DB_FILE_PATH + " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ?";
    vector<string> whereArgs = {(dstAlbumPath.back() != '/' ? (dstAlbumPath + "/%") : (dstAlbumPath + "%")),
                                dstAlbumPath};
    cmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = ALBUM_OPERATION_ERR;
    if (uniStore_->Delete(cmd, deletedRows) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete rows for the hidden album failed");
    }
    return true;
}

bool MediaLibraryObjectUtils::ProcessHiddenFile(const string &dstFileName, const string &srcPath)
{
    if (dstFileName.empty() || dstFileName.at(0) != '.') {
        MEDIA_INFO_LOG("Not a hidden file (file name begin with \'.\'), no need to do anything.");
        return false;
    }
    MediaLibraryCommand deleteCmd(FILESYSTEM_ASSET, DELETE);
    if (DeleteInfoInDbWithPath(deleteCmd, srcPath) == DATA_ABILITY_FAIL) {
        MEDIA_ERR_LOG("Delete rows for the old path failed");
    }
    return true;
}

int32_t MediaLibraryObjectUtils::ProcessHiddenDir(const string &dstDirName, const string &srcDirPath)
{
    if (dstDirName.empty() || dstDirName.at(0) != '.') {
        MEDIA_INFO_LOG("Not a hidden dir(name begin with \'.\'), no need to do anything.");
        return DATA_ABILITY_FAIL;
    }

    MediaLibraryCommand deleteCmd(FILESYSTEM_ASSET, DELETE);
    string strCondition = MEDIA_DATA_DB_FILE_PATH + " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ?";
    vector<string> whereArgs = {(srcDirPath.back() != '/' ? (srcDirPath + "/%") : (srcDirPath + "%")), srcDirPath};
    deleteCmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    deleteCmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = ALBUM_OPERATION_ERR;
    if (uniStore_->Delete(deleteCmd, deletedRows) != NativeRdb::E_OK) {
        MEDIA_WARNING_LOG("Delete src dir in database failed!");
        return DATA_ABILITY_FAIL;
    }
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryObjectUtils::UpdateDateModified(const string &dirPath)
{
    if (dirPath.empty()) {
        MEDIA_ERR_LOG("Path is empty, update failed!");
        return;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, UPDATE);
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(dirPath));
    cmd.SetValueBucket(valuesBucket);

    int32_t updateResult = ModifyInfoInDbWithPath(cmd, dirPath);
    if (updateResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Update failed for album");
    }
}

// Query with the WhereClause
shared_ptr<AbsSharedResultSet> MediaLibraryObjectUtils::QueryFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return nullptr;
    }

    vector<string> selectionArgs = {};
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);
    vector<string> columns;

    shared_ptr<AbsSharedResultSet> resultSet = uniStore_->Query(cmd, columns);
    return resultSet;
}

shared_ptr<FileAsset> MediaLibraryObjectUtils::GetFileAssetFromDb(const string &uriStr)
{
    MEDIA_INFO_LOG("[lqh] enter");

    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriStr);
    string networkId = MediaFileUtils::GetNetworkIdFromUri(uriStr);

    if ((id.empty()) || (!MediaLibraryDataManagerUtils::IsNumber(id)) || (stoi(id) == -1)) {
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

    shared_ptr<FetchResult> fetchFileResult = make_shared<FetchResult>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain fetch file result");
        return nullptr;
    }
    fetchFileResult->networkId_ = networkId;
    return fetchFileResult->GetObjectFromRdb(resultSet, 0);
}

int32_t MediaLibraryObjectUtils::SetFilePending(string &uriStr, bool isPending)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    ValuesBucket values;
    int64_t timeNow = MediaFileUtils::UTCTimeSeconds();
    values.PutBool(MEDIA_DATA_DB_IS_PENDING, isPending);
    values.PutLong(MEDIA_DATA_DB_TIME_PENDING, isPending ? timeNow : 0);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, timeNow);

    int32_t rowId = DATA_ABILITY_FAIL;
    MediaLibraryCommand cmd(Uri(uriStr), values);
    if (uniStore_->Update(cmd, rowId) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Update failed for file");
        return DATA_ABILITY_FAIL;
    }
    return rowId;
}

int32_t MediaLibraryObjectUtils::UpdateFileInfoInDb(MediaLibraryCommand &cmd, const string &dstPath,
                                                    const int &bucketId, const string &bucketName)
{
    if (dstPath.empty()) {
        MEDIA_ERR_LOG("Input argument is empty.");
        return DATA_ABILITY_FAIL;
    }

    // dispName doesn't be used, maybe forget
    size_t found = dstPath.rfind("/");
    string dispName;
    if (found != string::npos) {
        dispName = dstPath.substr(found + 1);
    }

    struct stat statInfo;
    if (stat(dstPath.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("dstPath %{private}s is invalid. Modify failed!", dstPath.c_str());
        return DATA_ABILITY_FAIL;
    }
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, dstPath);
    values.PutString(MEDIA_DATA_DB_BUCKET_NAME, bucketName);
    values.PutInt(MEDIA_DATA_DB_BUCKET_ID, bucketId);
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, bucketId);
    values.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime);
    cmd.SetValueBucket(values);

    return ModifyInfoInDbWithId(cmd);
}

string MediaLibraryObjectUtils::GetPathByIdFromDb(const string &id)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return "";
    }

    string filePath("");
    vector<string> selectionArgs = {};
    int32_t columnIndex(0);

    if ((id.empty()) || (!MediaLibraryDataManagerUtils::IsNumber(id)) || (stoi(id) == -1)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return "";
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);

    auto queryResultSet = uniStore_->Query(cmd, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, filePath);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain file path");

    return filePath;
}

int32_t MediaLibraryObjectUtils::GetIdByPathFromDb(const string &path)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

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

    shared_ptr<NativeRdb::ResultSet> queryResultSet = uniStore_->Query(cmd, {MEDIA_DATA_DB_ID});
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, fileId, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain column index");

    ret = queryResultSet->GetInt(columnIndex, fileId);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain file id");

    return fileId;
}

int32_t MediaLibraryObjectUtils::GetParentIdWithId(const string &fileId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    int32_t parentIdVal = -1;
    if (fileId.empty()) {
        MEDIA_WARNING_LOG("Input id is empty, cannot get parent path");
        return parentIdVal;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ASSET, QUERY);
    string strDeleteCondition = MEDIA_DATA_DB_ID + " = ? ";
    vector<string> whereArgs = {fileId};
    cmd.GetAbsRdbPredicates()->SetWhereClause(strDeleteCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore_->Query(cmd, {});
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexParentId;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
        queryResultSet->GetInt(columnIndexParentId, parentIdVal);
    }
    return parentIdVal;
}

int32_t MediaLibraryObjectUtils::DeleteInfoInDbWithPath(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    vector<string> whereArgs = {path};
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = ?";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
    }

    return deletedRows;
}

int32_t MediaLibraryObjectUtils::DeleteInfoInDbWithId(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow) || (stoi(strRow) == -1)) {
            MEDIA_ERR_LOG("MediaLibraryObjectUtils DeleteFile: Index not digit");
            return DATA_ABILITY_FAIL;
        }
        strDeleteCondition = MEDIA_DATA_DB_ID + " = ? ";
        vector<string> whereArgs = {strRow};
        cmd.GetAbsRdbPredicates()->SetWhereClause(strDeleteCondition);
        cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    }

    int32_t deletedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
    }

    return deletedRows;
}

int32_t MediaLibraryObjectUtils::ModifyInfoInDbWithPath(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    vector<string> whereArgs = {path};
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = ?";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t updatedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Update(cmd, updatedRows);
    if (result != NativeRdb::E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{private}d. Deleted %{private}d", result, updatedRows);
    }

    return updatedRows;
}

int32_t MediaLibraryObjectUtils::ModifyInfoInDbWithId(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore_ is nullptr!");
        return DATA_ABILITY_FAIL;
    }

    string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
    // update file
    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow) || (stoi(strRow) == -1)) {
            MEDIA_ERR_LOG("MediaLibraryObjectUtils DeleteFile: Index not digit");
            return DATA_ABILITY_FAIL;
        }
        strDeleteCondition = MEDIA_DATA_DB_ID + " = ? ";
        vector<string> whereArgs = {strRow};
        cmd.GetAbsRdbPredicates()->SetWhereClause(strDeleteCondition);
        cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    }

    int32_t updatedRows = DATA_ABILITY_FAIL;
    int32_t result = uniStore_->Update(cmd, updatedRows);
    if (result != NativeRdb::E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{private}d. Deleted %{private}d", result, updatedRows);
    }

    return updatedRows;
}

shared_ptr<AbsSharedResultSet> MediaLibraryObjectUtils::QueryWithCondition(MediaLibraryCommand &cmd,
    vector<string> columns, const string &conditionColumn)
{
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore is nullptr");
        return nullptr;
    }
    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strQueryCondition.empty() && !conditionColumn.empty()) {
        strQueryCondition = conditionColumn + " = " + cmd.GetOprnFileId();
        cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    }

    return uniStore_->Query(cmd, columns);
}

shared_ptr<AbsSharedResultSet> MediaLibraryObjectUtils::QueryView(MediaLibraryCommand &cmd, vector<string> columns)
{
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore is nullptr");
        return nullptr;
    }
    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (!strQueryCondition.empty()) {
        return uniStore_->Query(cmd, columns);
    }
    return uniStore_->QuerySql("SELECT * FROM " + cmd.GetTableName());
}


void ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) {}


} // namespace Media
} // namespace OHOS
