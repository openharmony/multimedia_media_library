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
#include "fetch_result.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_thumbnail.h"
#include "value_object.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const string NO_MEDIA_TAG = ".nomedia";
int32_t MediaLibraryObjectUtils::CreateDirWithPath(const string &dirPath)
{
    if (dirPath.empty()) {
        return DATA_ABILITY_INVALID_PATH;
    }

    int64_t rowId = -1;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, dirPath);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::CREATE, values);
    int32_t ret = CreateDirObj(cmd, rowId);
    if (ret == DATA_ABILITY_DUPLICATE_CREATE || ret == DATA_ABILITY_SUCCESS) {
        return rowId;
    }
    return ret;
}

NativeAlbumAsset MediaLibraryObjectUtils::GetDirAsset(const string &path)
{
    NativeAlbumAsset dirAsset;
    if (path.empty()) {
        MEDIA_ERR_LOG("Path is empty, create failed!");
        dirAsset.SetAlbumId(DATA_ABILITY_INVALID_PATH);
        return dirAsset;
    }

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        dirAsset.SetAlbumId(DATA_ABILITY_HAS_DB_ERROR);
        return dirAsset;
    }

    int32_t dirId = CreateDirWithPath(path);
    MEDIA_DEBUG_LOG("After CreateDirWithPath, get dirId = %{private}d!", dirId);
    dirAsset.SetAlbumId(dirId);
    if (dirId < 0) {
        return dirAsset;
    }

    string nameVal = GetStringColumnByIdFromDb(to_string(dirId), MEDIA_DATA_DB_NAME);
    if (nameVal.empty()) {
        MEDIA_ERR_LOG("Get dir name failed!");
        return dirAsset;
    }
    dirAsset.SetAlbumName(nameVal);
    MEDIA_DEBUG_LOG("bucketId = %{private}d bucketName = %{private}s", dirId, nameVal.c_str());
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
        return DATA_ABILITY_SUCCESS;
    }

    MediaLibraryCommand deleteCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    if (DeleteInfoByPathInDb(deleteCmd, path) != DATA_ABILITY_SUCCESS) {
        // Delete the record in database if file is not in filesystem any more
        MEDIA_ERR_LOG("CreateFileAsset: delete info in db failed");
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryObjectUtils::InsertFileInDb(MediaLibraryCommand &cmd,
    const FileAsset &fileAsset, const NativeAlbumAsset &dirAsset)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    // Fill basic file information into DB
    string displayName = fileAsset.GetDisplayName();
    ValuesBucket assetInfo;
    assetInfo.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset.GetMediaType());
    assetInfo.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset.GetRelativePath());
    assetInfo.PutString(MEDIA_DATA_DB_NAME, displayName);
    assetInfo.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    struct stat statInfo {};
    if (stat(fileAsset.GetPath().c_str(), &statInfo) == 0) {
        assetInfo.PutLong(MEDIA_DATA_DB_SIZE, statInfo.st_size);
        assetInfo.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    }
    assetInfo.PutString(MEDIA_DATA_DB_FILE_PATH, fileAsset.GetPath());
    assetInfo.PutInt(MEDIA_DATA_DB_BUCKET_ID, dirAsset.GetAlbumId());
    assetInfo.PutInt(MEDIA_DATA_DB_PARENT_ID, dirAsset.GetAlbumId());
    assetInfo.PutString(MEDIA_DATA_DB_BUCKET_NAME, dirAsset.GetAlbumName());
    cmd.SetValueBucket(assetInfo);
    int64_t outRowId = -1;
    int32_t errCode = uniStore->Insert(cmd, outRowId);
    return (errCode == NativeRdb::E_OK) ? outRowId : errCode;
}

// create
int32_t MediaLibraryObjectUtils::CreateFileObj(MediaLibraryCommand &cmd)
{
    string relativePath(""), path(""), displayName("");
    int32_t mediaType = static_cast<int32_t>(MEDIA_TYPE_FILE);
    FileAsset fileAsset;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(displayName);
        fileAsset.SetDisplayName(displayName);
    }

    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
        path = ROOT_MEDIA_DIR + relativePath + displayName;
        fileAsset.SetRelativePath(relativePath);
        fileAsset.SetPath(path);
    }

    if (values.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject)) {
        valueObject.GetInt(mediaType);
        fileAsset.SetMediaType(static_cast<MediaType>(mediaType));
    }

    NativeAlbumAsset dirAsset = GetDirAsset(ROOT_MEDIA_DIR + relativePath);
    if (dirAsset.GetAlbumId() < 0) {
        return dirAsset.GetAlbumId();
    }

    // delete rows in database but not in real filesystem
    int32_t errCode = DeleteInvalidRowInDb(path);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete invalid row in database failed");
        return errCode;
    }

    errCode = fileAsset.CreateAsset(path);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("CreateFileAsset: create file asset failed");
        return errCode;
    }

    return InsertFileInDb(cmd, fileAsset, dirAsset);
}

NativeAlbumAsset MediaLibraryObjectUtils::GetLastDirExistInDb(const std::string &dirPath)
{
    MEDIA_DEBUG_LOG("enter");
    NativeAlbumAsset dirAsset;
    string lastPath = dirPath;
    if (lastPath.back() == '/') {
        lastPath.pop_back();
    }
    int32_t dirId = 0;
    int32_t lastPathId = -1;
    do {
        size_t slashIndex = lastPath.rfind(SLASH_CHAR);
        if (slashIndex == string::npos || lastPath.length() <= ROOT_MEDIA_DIR.length()) {
            break;
        }
        lastPath = lastPath.substr(0, slashIndex);
        lastPathId = GetIdByPathFromDb(lastPath);
        if (lastPathId >= 0) {
            dirId = lastPathId;
        }
    } while (lastPathId < 0);
    MEDIA_INFO_LOG("GetLastAlbumExistInDb lastPath = %{private}s", lastPath.c_str());
    dirAsset.SetAlbumId(dirId);
    dirAsset.SetAlbumPath(lastPath);
    return dirAsset;
}

int32_t MediaLibraryObjectUtils::DeleteRows(const std::vector<int64_t> &rowIds)
{
    int32_t errCode = 0;

    for (auto id : rowIds) {
        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
        errCode = DeleteInfoByIdInDb(cmd, to_string(id));
    }
    return errCode;
}

int32_t MediaLibraryObjectUtils::InsertDirToDbRecursively(const std::string &dirPath, int64_t &rowId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    if (dirPath.empty()) {
        MEDIA_ERR_LOG("Input parameter dirPath is empty!");
        return DATA_ABILITY_VIOLATION_PARAMETERS;
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
        string title = MediaLibraryDataManagerUtils::GetFileName(parentPath);
        if (index != string::npos) {
            string tmpPath = MediaLibraryDataManagerUtils::GetParentPath(parentPath);
            if (tmpPath.length() > ROOT_MEDIA_DIR.length()) {
                relativePath = tmpPath.substr(ROOT_MEDIA_DIR.length()) + "/";
            }
        }
        if (!MediaFileUtils::CheckDisplayName(title)) {
            DeleteRows(outIds);
            MEDIA_ERR_LOG("Check display name failed!");
            return DATA_ABILITY_VIOLATION_PARAMETERS;
        }
        values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        values.PutString(MEDIA_DATA_DB_TITLE, title);
        values.PutString(MEDIA_DATA_DB_NAME, title);
        values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
        values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentId);
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::GetAlbumDateModified(path));
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(path));

        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::CREATE);
        cmd.SetValueBucket(values);
        if (uniStore->Insert(cmd, rowId) != NativeRdb::E_OK) {
            rowId = parentId;
            return DATA_ABILITY_HAS_DB_ERROR;
        }
        parentId = rowId;
        outIds.push_back(rowId);
    }
    MEDIA_DEBUG_LOG("parentId = %{private}d", static_cast<int>(parentId));
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryObjectUtils::CreateDirObj(MediaLibraryCommand &cmd, int64_t &rowId)
{
    MEDIA_DEBUG_LOG("enter");
    string dirPath;
    ValueObject valueObject;
    const ValuesBucket &values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject)) {
        valueObject.GetString(dirPath);
    }
    if (dirPath.empty()) {
        MEDIA_ERR_LOG("Dir path is empty!");
        return DATA_ABILITY_INVALID_PATH;
    }

    AlbumAsset dirAsset;
    dirAsset.SetAlbumPath(dirPath);
    rowId = GetIdByPathFromDb(dirPath);
    MEDIA_DEBUG_LOG("dirPath %{private}s id in database is %{private}d", dirPath.c_str(), static_cast<int>(rowId));
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

int32_t MediaLibraryObjectUtils::DeleteEmptyDirsRecursively(const int32_t dirId)
{
    if (dirId <= 0) {
        return DATA_ABILITY_INVALID_FILEID;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }
    if (IsColumnValueExist(to_string(dirId), MEDIA_DATA_DB_PARENT_ID)) {
        return DATA_ABILITY_SUCCESS;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(dirId));
    auto queryParentResultSet = uniStore->Query(cmd, {});
    if (queryParentResultSet->GoToNextRow() != NativeRdb::E_OK) {
        return DATA_ABILITY_SUCCESS;
    }
    int32_t columnIndexParentId = 0;
    int32_t columnIndexDir = 0;
    int32_t parentIdVal = 0;
    string dirVal;
    queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
    queryParentResultSet->GetInt(columnIndexParentId, parentIdVal);
    queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndexDir);
    queryParentResultSet->GetString(columnIndexDir, dirVal);
    if (parentIdVal == 0) {
        return DATA_ABILITY_SUCCESS;
    }
    MEDIA_DEBUG_LOG("dirVal = %{private}s, parentIdVal = %{public}d", dirVal.c_str(), parentIdVal);

    MediaLibraryCommand deleteDirCmd(OperationObject::FILESYSTEM_DIR, OperationType::DELETE);
    int32_t errCode = DeleteInfoByIdInDb(deleteDirCmd, to_string(dirId));
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete dir info failed");
        return errCode;
    }
    if (!MediaFileUtils::DeleteDir(dirVal)) {
        MEDIA_ERR_LOG("Delete dir in filesystem failed");
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }
    DeleteEmptyDirsRecursively(parentIdVal);
    return DATA_ABILITY_SUCCESS;
}

// Restriction: input param cmd MUST have file id in either uri or valuebucket
int32_t MediaLibraryObjectUtils::DeleteFileObj(MediaLibraryCommand &cmd, const string &filePath)
{
    MEDIA_DEBUG_LOG("enter");
    FileAsset fileAsset;
    int32_t errCode = fileAsset.DeleteAsset(filePath);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete file in filesystem failed!");
        return errCode;
    }
    // must get parent id BEFORE deleting file in database
    string fileId = cmd.GetOprnFileId();
    if (fileId.empty()) {
        MEDIA_ERR_LOG("Get id from uri or valuebucket failed!");
        return DATA_ABILITY_INVALID_FILEID;
    }
    int32_t parentId = GetParentIdByIdFromDb(fileId);
    int32_t deleteRows = DeleteInfoByIdInDb(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete file info in database failed!");
        return deleteRows;
    }
    // if delete successfully, 1) update modify time
    string dirPath = MediaLibraryDataManagerUtils::GetParentPath(filePath);
    UpdateDateModified(dirPath);
    // 2) recursively delete empty parent dirs
    if (DeleteEmptyDirsRecursively(parentId) != DATA_ABILITY_SUCCESS) {
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }
    // 3) delete relative records in smart album
    MediaLibraryCommand deleteSmartMapCmd(OperationObject::SMART_ALBUM_MAP, OperationType::DELETE);
    deleteSmartMapCmd.GetAbsRdbPredicates()->EqualTo(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
    deleteRows = DeleteInfoByIdInDb(deleteSmartMapCmd);
    return deleteRows;
}

int32_t MediaLibraryObjectUtils::DeleteDirObj(MediaLibraryCommand &cmd, const string &dirPath)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", dirPath.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    AlbumAsset dirAsset;
    if (!dirAsset.DeleteAlbumAsset(dirPath)) {
        MEDIA_ERR_LOG("Delete album asset failed!");
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }

    int32_t parentId = GetParentIdByIdFromDb(cmd.GetOprnFileId());
    int32_t deleteRows = DeleteInfoByIdInDb(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete album info in database failed!");
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }
    // need to delete subfiles in the album when deleting album, delete: xx/xxx/album_name/%
    MediaLibraryCommand deleteSubfilesCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    string pathPrefix = dirPath.back() != '/' ? (dirPath + "/") : dirPath;
    deleteSubfilesCmd.GetAbsRdbPredicates()->BeginsWith(MEDIA_DATA_DB_FILE_PATH, pathPrefix);

    int32_t deletedRows = -1;
    int32_t deleteResult = uniStore->Delete(deleteSubfilesCmd, deletedRows);
    if (deleteResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete subfiles in album %{private}s failed", pathPrefix.c_str());
        return deleteResult;
    }
    if (DeleteEmptyDirsRecursively(parentId) != DATA_ABILITY_SUCCESS) {
        return DATA_ABILITY_DELETE_DIR_FAIL;
    }
    return deleteRows;
}

// Restriction: input param cmd MUST have id in uri
int32_t MediaLibraryObjectUtils::RenameFileObj(MediaLibraryCommand &cmd,
    const string &srcFilePath, const string &dstFilePath)
{
    MEDIA_DEBUG_LOG("enter, srcFilePath = %{private}s, dstFilePath = %{private}s",
        srcFilePath.c_str(), dstFilePath.c_str());
    if (srcFilePath.empty() || dstFilePath.empty()) {
        MEDIA_ERR_LOG("srcFilePath or dstFilePath is empty, rename failed!");
        return DATA_ABILITY_INVALID_PATH;
    }
    if (srcFilePath.compare(dstFilePath) == 0) {
        MEDIA_DEBUG_LOG("Skip modify the file, the path of new file is the same as old");
        return DATA_ABILITY_SUCCESS;
    }

    string dstAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(dstFilePath);
    NativeAlbumAsset dirAsset = GetDirAsset(dstAlbumPath);
    if (dirAsset.GetAlbumId() <= 0) {
        MEDIA_ERR_LOG("Failed to get or create directory");
        return dirAsset.GetAlbumId();
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
int32_t MediaLibraryObjectUtils::RenameDirObj(MediaLibraryCommand &cmd,
    const string &srcDirPath, const string &dstDirPath)
{
    MEDIA_DEBUG_LOG("enter, srcDirPath = %{private}s, dstDirPath = %{private}s",
        srcDirPath.c_str(), dstDirPath.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    if (srcDirPath.empty() || dstDirPath.empty()) {
        MEDIA_ERR_LOG("srcDirPath or dstDirPath is empty, rename failed!");
        return DATA_ABILITY_INVALID_PATH;
    }
    if (!MediaFileUtils::RenameDir(srcDirPath, dstDirPath)) {
        MEDIA_ERR_LOG("Rename directory failed!");
        return DATA_ABILITY_HAS_FS_ERROR;
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
    int32_t retVal = ModifyInfoByIdInDb(cmd);
    if (retVal <= 0) {
        return retVal;
    }

    // Update the path, relative path and album Name for internal files
    const std::string modifyAlbumInternalsStmt =
        "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace(" +
        MEDIA_DATA_DB_FILE_PATH + ", '" + srcDirPath + "/' , '" + dstDirPath + "/'), " +
        MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH + ", '" + srcDirPath + "', '" +
        dstDirPath + "'), " + MEDIA_DATA_DB_ALBUM_NAME + " = replace(" + MEDIA_DATA_DB_ALBUM_NAME + ", '" +
        MediaLibraryDataManagerUtils::GetFileName(srcDirPath) + "', '" + dstDirName + "')" + "where " +
        MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcDirPath + "/%'";
    if (uniStore->ExecuteSql(modifyAlbumInternalsStmt) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Album update sql failed");
        return DATA_ABILITY_HAS_DB_ERROR;
    }
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryObjectUtils::OpenFile(MediaLibraryCommand &cmd, const string &mode)
{
    MEDIA_DEBUG_LOG("enter");
    string uriString = cmd.GetUri().ToString();
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(uriString);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain path from Database");
        return DATA_ABILITY_INVALID_URI;
    }

    string path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    int32_t fd = fileAsset->OpenAsset(path, mode);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{private}d, errno %{private}d", fd, errno);
        return DATA_ABILITY_HAS_FS_ERROR;
    }

    MEDIA_DEBUG_LOG("MediaLibraryDataManager OpenFile: Success");
    return fd;
}

int32_t MediaLibraryObjectUtils::CloseFile(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    string strFileId = cmd.GetOprnFileId();
    if (strFileId.empty()) {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return DATA_ABILITY_INVALID_FILEID;
    }

    string srcPath = GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strFileId.c_str());
        return DATA_ABILITY_INVALID_FILEID;
    }

    string fileName = MediaLibraryDataManagerUtils::GetFileName(srcPath);
    if ((fileName.length() != 0) && (fileName.at(0) != '.')) {
        string dirPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModified(dirPath);
    }

    MediaLibraryThumbnail thumbnail;
    ThumbRdbOpt opt {.store = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(),
                     .table = MEDIALIBRARY_TABLE,
                     .row = strFileId};
    string kvId;
    thumbnail.CreateThumbnail(opt, kvId);
    ScanFile(srcPath);
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryObjectUtils::ScanFile(string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
    if (scanFileCb == nullptr) {
        MEDIA_ERR_LOG("Failed to create scan file callback object");
        return ;
    }
    int ret = MediaScannerObj::GetMediaScannerInstance()->ScanFile(path, nullptr);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed!");
    }
}

bool MediaLibraryObjectUtils::ProcessNoMediaFile(const string &dstFileName, const string &dstAlbumPath)
{
    MEDIA_DEBUG_LOG("enter, dstFileName = %{private}s, dstAlbumPath = %{private}s",
        dstFileName.c_str(), dstAlbumPath.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    if (dstFileName.empty() || dstAlbumPath.empty() || dstFileName != NO_MEDIA_TAG) {
        MEDIA_INFO_LOG("Not a .nomedia file, no need to do anything.");
        return false;
    }

    // the whole folder containing .nomedia file is invisible in database
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    string dstAlbumPathPrefix = dstAlbumPath.back() != '/' ? (dstAlbumPath + "/") : dstAlbumPath;
    cmd.GetAbsRdbPredicates()->BeginsWith(MEDIA_DATA_DB_FILE_PATH, dstAlbumPathPrefix);
    cmd.GetAbsRdbPredicates()->Or()->EqualTo(MEDIA_DATA_DB_FILE_PATH, dstAlbumPath);

    int32_t deletedRows = -1;
    if (uniStore->Delete(cmd, deletedRows) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete rows for the hidden album failed");
    }
    return true;
}

bool MediaLibraryObjectUtils::ProcessHiddenFile(const string &dstFileName, const string &srcPath)
{
    MEDIA_DEBUG_LOG("enter, dstFileName = %{private}s, srcPath = %{private}s",
        dstFileName.c_str(), srcPath.c_str());
    if (dstFileName.empty() || srcPath.empty() || dstFileName.at(0) != '.') {
        MEDIA_INFO_LOG("Not a hidden file (file name begin with \'.\'), no need to do anything.");
        return false;
    }
    MediaLibraryCommand deleteCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    if (DeleteInfoByPathInDb(deleteCmd, srcPath) != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete rows for the old path failed");
    }
    return true;
}

int32_t MediaLibraryObjectUtils::ProcessHiddenDir(const string &dstDirName, const string &srcDirPath)
{
    if (dstDirName.empty() || srcDirPath.empty() || dstDirName.at(0) != '.') {
        MEDIA_INFO_LOG("Not a hidden dir(name begin with \'.\'), no need to do anything.");
        return DATA_ABILITY_INVALID_PATH;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    MediaLibraryCommand deleteCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    string dstAlbumPathPrefix = srcDirPath.back() != '/' ? (srcDirPath + "/") : srcDirPath;
    deleteCmd.GetAbsRdbPredicates()->BeginsWith(MEDIA_DATA_DB_FILE_PATH, dstAlbumPathPrefix);
    deleteCmd.GetAbsRdbPredicates()->Or()->EqualTo(MEDIA_DATA_DB_FILE_PATH, srcDirPath);

    int32_t deletedRows = -1;
    if (uniStore->Delete(deleteCmd, deletedRows) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete src dir in database failed!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryObjectUtils::UpdateDateModified(const string &dirPath)
{
    if (dirPath.empty()) {
        MEDIA_ERR_LOG("Path is empty, update failed!");
        return;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(dirPath));
    cmd.SetValueBucket(valuesBucket);

    (void)ModifyInfoByPathInDb(cmd, dirPath);
}

shared_ptr<FileAsset> MediaLibraryObjectUtils::GetFileAssetFromDb(const string &uriStr)
{
    MEDIA_DEBUG_LOG("enter");

    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriStr);
    string networkId = MediaFileUtils::GetNetworkIdFromUri(uriStr);

    if ((id.empty()) || (!MediaLibraryDataManagerUtils::IsNumber(id)) || (stoi(id) == -1)) {
        MEDIA_ERR_LOG("Id for the path is incorrect");
        return nullptr;
    }

    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.SetOprnDevice(networkId);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, id);

    shared_ptr<AbsSharedResultSet> resultSet = QueryWithCondition(cmd, {});
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

int32_t MediaLibraryObjectUtils::UpdateFileInfoInDb(MediaLibraryCommand &cmd, const string &dstPath,
    const int32_t &bucketId, const string &bucketName)
{
    MEDIA_DEBUG_LOG("enter, dstPath: %{private}s,", dstPath.c_str());
    if (dstPath.empty()) {
        MEDIA_ERR_LOG("Input argument is empty.");
        return DATA_ABILITY_INVALID_PATH;
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
        return DATA_ABILITY_HAS_FS_ERROR;
    }
    string fileId = cmd.GetOprnFileId();
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, dstPath);
    values.PutString(MEDIA_DATA_DB_BUCKET_NAME, bucketName);
    values.PutInt(MEDIA_DATA_DB_BUCKET_ID, bucketId);
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, bucketId);
    values.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime);
    cmd.SetValueBucket(values);

    return ModifyInfoByIdInDb(cmd, fileId);
}

string MediaLibraryObjectUtils::GetPathByIdFromDb(const string &id)
{
    return GetStringColumnByIdFromDb(id, MEDIA_DATA_DB_FILE_PATH);
}

string MediaLibraryObjectUtils::GetRecyclePathByIdFromDb(const string &id)
{
    return GetStringColumnByIdFromDb(id, MEDIA_DATA_DB_RECYCLE_PATH);
}

string MediaLibraryObjectUtils::GetStringColumnByIdFromDb(const string &id, const string &column)
{
    MEDIA_DEBUG_LOG("enter column %{private}s", column.c_str());
    string value;
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return value;
    }

    if ((id.empty()) || (!MediaLibraryDataManagerUtils::IsNumber(id)) || (stoi(id) == -1)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return value;
    }

    int32_t columnIndex = 0;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, id);

    vector<string> columns;
    columns.push_back(column);

    auto queryResultSet = uniStore->Query(cmd, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, value, "Failed to obtain value from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, value, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(column, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, value, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, value);
    CHECK_AND_RETURN_RET_LOG(ret == 0, value, "Failed to obtain value");

    return value;
}

int32_t MediaLibraryObjectUtils::GetIdByPathFromDb(const string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    if (path.empty()) {
        return DATA_ABILITY_INVALID_PATH;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    int32_t columnIndex = 0;
    string newPath = path;
    if (newPath.back() == '/') {
        newPath.pop_back();
    }
    int32_t fileId = -1;

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_ID);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, newPath);

    auto queryResultSet = uniStore->Query(cmd, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, fileId, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain column index");

    ret = queryResultSet->GetInt(columnIndex, fileId);
    CHECK_AND_RETURN_RET_LOG(ret == 0, fileId, "Failed to obtain file id");

    return fileId;
}

int32_t MediaLibraryObjectUtils::GetParentIdByIdFromDb(const string &fileId)
{
    MEDIA_DEBUG_LOG("enter, fileId = %{private}s", fileId.c_str());
    if (fileId.empty() || fileId == "-1") {
        return DATA_ABILITY_INVALID_FILEID;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    int32_t parentIdVal = -1;
    int32_t columnIndex = 0;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    auto queryResultSet = uniStore->Query(cmd, {});
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, parentIdVal, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToNextRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, parentIdVal, "Failed to shift at next row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, parentIdVal, "Failed to obtain column index");

    ret = queryResultSet->GetInt(columnIndex, parentIdVal);
    CHECK_AND_RETURN_RET_LOG(ret == 0, parentIdVal, "Failed to obtain file id");

    return parentIdVal;
}

int32_t MediaLibraryObjectUtils::InsertInDb(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    int64_t outRowId = DATA_ABILITY_HAS_DB_ERROR;
    int32_t result = uniStore->Insert(cmd, outRowId);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert operation failed. Result %{public}d. Deleted %{public}d",
            result, static_cast<int32_t>(outRowId));
        return DATA_ABILITY_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}

int32_t MediaLibraryObjectUtils::DeleteInfoByPathInDb(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    int32_t deletedRows = DATA_ABILITY_HAS_DB_ERROR;
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, path);
    int32_t result = uniStore->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{public}d. Deleted %{public}d", result, deletedRows);
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryObjectUtils::DeleteInfoByIdInDb(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_DEBUG_LOG("enter, fileId = %{private}s", fileId.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryObjectUtils DeleteFile: Index not digit");
            return DATA_ABILITY_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, strRow);
    }

    int32_t deletedRows = DATA_ABILITY_HAS_DB_ERROR;
    int32_t result = uniStore->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{public}d. Deleted %{public}d", result, deletedRows);
    }

    return deletedRows;
}

int32_t MediaLibraryObjectUtils::ModifyInfoByPathInDb(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, path);
    int32_t updatedRows = DATA_ABILITY_HAS_DB_ERROR;
    int32_t result = uniStore->Update(cmd, updatedRows);
    if (result != NativeRdb::E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{public}d. Updated %{public}d", result, updatedRows);
    }

    return updatedRows;
}

int32_t MediaLibraryObjectUtils::ModifyInfoByIdInDb(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_DEBUG_LOG("enter, fileId = %{private}s", fileId.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return DATA_ABILITY_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow) || (stoi(strRow) == -1)) {
            MEDIA_ERR_LOG("DeleteFile: Index not digit");
            return DATA_ABILITY_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, strRow);
    }

    int32_t updatedRows = DATA_ABILITY_HAS_DB_ERROR;
    int32_t result = uniStore->Update(cmd, updatedRows);
    if (result != NativeRdb::E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{public}d. Updated %{public}d", result, updatedRows);
    }

    return updatedRows;
}

shared_ptr<AbsSharedResultSet> MediaLibraryObjectUtils::QueryWithCondition(MediaLibraryCommand &cmd,
    const vector<string> &columns, const string &conditionColumn)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return nullptr;
    }

    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strQueryCondition.empty()) {
        if (conditionColumn.empty()) {
            return uniStore->QuerySql("SELECT * FROM " + cmd.GetTableName());
        }
        string strFileId = cmd.GetOprnFileId();
        if (strFileId.empty()) {
            MEDIA_ERR_LOG("Get file id from uri or valuebucket failed!");
            return nullptr;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(conditionColumn, strFileId);
    }

    return uniStore->Query(cmd, columns);
}