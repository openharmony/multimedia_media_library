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
#define MLOG_TAG "ObjectUtils"

#include "medialibrary_object_utils.h"

#include <cerrno>

#include "album_asset.h"
#include "datashare_predicates.h"
#include "directory_ex.h"
#include "fetch_result.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_privacy_manager.h"
#include "media_scanner_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_smartalbum_map_db.h"
#include "result_set_utils.h"
#include "thumbnail_service.h"
#include "value_object.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const string NO_MEDIA_TAG = ".nomedia";
int32_t MediaLibraryObjectUtils::CreateDirWithPath(const string &dirPath)
{
    if (dirPath.empty()) {
        return E_INVALID_PATH;
    }

    int64_t rowId = -1;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, dirPath);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::CREATE, values);
    int32_t ret = CreateDirObj(cmd, rowId);
    if (ret == E_FILE_EXIST || ret == E_SUCCESS) {
        return rowId;
    }
    return ret;
}

NativeAlbumAsset MediaLibraryObjectUtils::GetDirAsset(const string &path)
{
    NativeAlbumAsset dirAsset;
    if (path.empty()) {
        MEDIA_ERR_LOG("Path is empty, create failed!");
        dirAsset.SetAlbumId(E_INVALID_PATH);
        return dirAsset;
    }

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        dirAsset.SetAlbumId(E_HAS_DB_ERROR);
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
        return E_SUCCESS;
    }

    FileAsset fileAsset;
    if (fileAsset.IsFileExists(path)) {
        // File aready exist, not need to create again
        return E_SUCCESS;
    }

    MediaLibraryCommand deleteCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    if (DeleteInfoByPathInDb(deleteCmd, path) != E_SUCCESS) {
        // Delete the record in database if file is not in filesystem any more
        MEDIA_ERR_LOG("CreateFileAsset: delete info in db failed");
        return E_DELETE_DIR_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibraryObjectUtils::InsertFileInDb(MediaLibraryCommand &cmd,
    const FileAsset &fileAsset, const NativeAlbumAsset &dirAsset)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    // Fill basic file information into DB
    string displayName = fileAsset.GetDisplayName();
    ValuesBucket assetInfo;
    assetInfo.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset.GetMediaType());
    assetInfo.PutString(MEDIA_DATA_DB_URI, MediaLibraryDataManagerUtils::GetMediaTypeUri(fileAsset.GetMediaType()));
    string extension = ScannerUtils::GetFileExtensionFromFileUri(displayName);
    assetInfo.PutString(MEDIA_DATA_DB_MIME_TYPE, ScannerUtils::GetMimeTypeFromExtension(extension));
    assetInfo.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset.GetRelativePath());
    assetInfo.PutString(MEDIA_DATA_DB_NAME, displayName);
    assetInfo.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    struct stat statInfo {};
    if (stat(fileAsset.GetPath().c_str(), &statInfo) == 0) {
        assetInfo.PutLong(MEDIA_DATA_DB_SIZE, statInfo.st_size);
        assetInfo.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::UTCTimeSeconds());
        assetInfo.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime);
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

void GetRelativePathFromValues(ValuesBucket &values, string &relativePath, int32_t mediaType)
{
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
        return;
    }
    if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        string albumUri;
        valueObject.GetString(albumUri);
        auto albumAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(albumUri);
        if (albumAsset != nullptr) {
            relativePath = albumAsset->GetRelativePath() + albumAsset->GetDisplayName() + SLASH_CHAR;
        }
    } else {
        MediaLibraryObjectUtils::GetDefaultRelativePath(mediaType, relativePath);
    }
}

// create
int32_t MediaLibraryObjectUtils::CreateFileObj(MediaLibraryCommand &cmd)
{
    string relativePath;
    string path;
    string displayName;
    int32_t mediaType = static_cast<int32_t>(MEDIA_TYPE_FILE);
    FileAsset fileAsset;
    ValueObject valueObject;
    ValuesBucket &values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(displayName);
        fileAsset.SetDisplayName(displayName);
    }

    if (values.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject)) {
        valueObject.GetInt(mediaType);
        fileAsset.SetMediaType(static_cast<MediaType>(mediaType));
    }

    GetRelativePathFromValues(values, relativePath, mediaType);
    if (!relativePath.empty()) {
        values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        path = ROOT_MEDIA_DIR + relativePath + displayName;
        fileAsset.SetRelativePath(relativePath);
        fileAsset.SetPath(path);
    }

    MediaLibraryDirOperations dirOprn;
    int32_t errCode = dirOprn.HandleDirOperations(MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION, values,
        MediaLibraryDataManager::GetInstance()->rdbStore_, MediaLibraryDataManager::GetInstance()->GetDirQuerySetMap());
    if (errCode != E_SUCCESS) {
        return errCode;
    }

    NativeAlbumAsset dirAsset = GetDirAsset(ROOT_MEDIA_DIR + relativePath);
    if (dirAsset.GetAlbumId() < 0) {
        return dirAsset.GetAlbumId();
    }

    // delete rows in database but not in real filesystem
    errCode = DeleteInvalidRowInDb(path);
    if (errCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Delete invalid row in database failed");
        return errCode;
    }

    errCode = fileAsset.CreateAsset(path);
    if (errCode != E_SUCCESS) {
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

int32_t SetDirValuesByPath(ValuesBucket &values, const string &path, int32_t parentId)
{
    string title = MediaLibraryDataManagerUtils::GetFileName(path);
    if (!MediaFileUtils::CheckDisplayName(title)) {
        MEDIA_ERR_LOG("Check display name failed!");
        return E_INVAVLID_DISPLAY_NAME;
    }

    string relativePath;
    string parentPath = MediaLibraryDataManagerUtils::GetParentPath(path);
    if (parentPath.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = parentPath.substr(ROOT_MEDIA_DIR.length()) + "/";
    }

    values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    values.PutString(MEDIA_DATA_DB_TITLE, title);
    values.PutString(MEDIA_DATA_DB_NAME, title);
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentId);
    values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::UTCTimeSeconds());

    struct stat statInfo {};
    if (stat(path.c_str(), &statInfo) == 0) {
        values.PutLong(MEDIA_DATA_DB_SIZE, statInfo.st_size);
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime);
    }
    return E_SUCCESS;
}

int32_t MediaLibraryObjectUtils::InsertDirToDbRecursively(const std::string &dirPath, int64_t &rowId)
{
    CHECK_AND_RETURN_RET_LOG(!dirPath.empty(), E_VIOLATION_PARAMETERS, "Input parameter dirPath is empty!");

    NativeAlbumAsset dirAsset = GetLastDirExistInDb(dirPath);
    string parentPath = dirAsset.GetAlbumPath();
    int32_t parentId = dirAsset.GetAlbumId();
    if ((parentId == 0) && ((parentPath + "/") != ROOT_MEDIA_DIR)) {
        return E_INVALID_PATH;
    }
    vector<int64_t> outIds;
    rowId = parentId;

    string path = dirPath;
    if (path.back() != '/') {
        path.append("/");
    }
    while (parentPath.length() < (path.length() - 1)) {
        size_t index = path.find("/", parentPath.length() + 1);
        string currentPath = path.substr(0, index);
        ValuesBucket values;
        auto ret = SetDirValuesByPath(values, currentPath, parentId);
        if (ret == E_INVAVLID_DISPLAY_NAME) {
            DeleteRows(outIds);
        }
        if (ret != E_SUCCESS) {
            return ret;
        }

        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::CREATE, values);
        rowId = InsertInDb(cmd);
        if (rowId <= 0) {
            rowId = parentId;
            return E_HAS_DB_ERROR;
        }
        parentId = rowId;
        parentPath = currentPath;
        outIds.push_back(rowId);
    }
    return E_SUCCESS;
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
        return E_INVALID_PATH;
    }

    AlbumAsset dirAsset;
    dirAsset.SetAlbumPath(dirPath);
    rowId = GetIdByPathFromDb(dirPath);
    MEDIA_DEBUG_LOG("dirPath %{private}s id in database is %{private}d", dirPath.c_str(), static_cast<int>(rowId));
    if (rowId < 0) {
        if (!dirAsset.CreateAlbumAsset()) {
            return E_FAIL;
        }
        return InsertDirToDbRecursively(dirPath, rowId);
    }

    if (!MediaFileUtils::IsDirectory(dirPath)) {
        dirAsset.CreateAlbumAsset();
        return E_SUCCESS;
    }
    return E_FILE_EXIST;
}

int32_t MediaLibraryObjectUtils::DeleteEmptyDirsRecursively(int32_t dirId)
{
    if (dirId <= 0) {
        return E_INVALID_FILEID;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    int err = E_ERR;
    const int32_t MAX_DIR_DEPTH = 15;
    int depth = 0;
    while ((depth++ < MAX_DIR_DEPTH) && (dirId > 0)) {
        if (IsColumnValueExist(to_string(dirId), MEDIA_DATA_DB_PARENT_ID)) {
            return E_SUCCESS;
        }

        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(dirId));
        auto queryParentResultSet = uniStore->Query(cmd, {});
        if (queryParentResultSet->GoToNextRow() != NativeRdb::E_OK) {
            return E_SUCCESS;
        }
        int32_t colIndex = 0;
        int32_t parentIdVal = 0;
        string dirVal;
        queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, colIndex);
        queryParentResultSet->GetInt(colIndex, parentIdVal);
        queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, colIndex);
        queryParentResultSet->GetString(colIndex, dirVal);
        if (parentIdVal == 0) {
            return E_SUCCESS;
        }
        MEDIA_DEBUG_LOG("dirVal = %{private}s, parentIdVal = %{public}d", dirVal.c_str(), parentIdVal);

        // Do not delete user created dir
        if (MediaFileUtils::IsFileExists(dirVal + "/" + ".nofile")) {
            return E_SUCCESS;
        }
        if (!MediaFileUtils::IsDirEmpty(dirVal)) {
            return E_SUCCESS;
        }

        if (!MediaFileUtils::DeleteDir(dirVal)) {
            MEDIA_ERR_LOG("Delete dir in filesystem failed, errno = %{public}d", errno);
            err = E_HAS_FS_ERROR;
            break;
        }
        MediaLibraryCommand deleteDirCmd(OperationObject::FILESYSTEM_DIR, OperationType::DELETE);
        int32_t deletedRows = DeleteInfoByIdInDb(deleteDirCmd, to_string(dirId));
        if (deletedRows < 0) {
            MEDIA_ERR_LOG("Delete dir info failed, err: %{public}d", deletedRows);
            err = deletedRows;
            break;
        } else if (deletedRows == 0) {
            MEDIA_ERR_LOG("Failed to delete dir in db!");
            return E_HAS_DB_ERROR;
        }
        dirId = parentIdVal;
    }
    return err;
}

static inline void InvalidateThumbnail(const string &id)
{
    auto thumbnailService = ThumbnailService::GetInstance();
    if (thumbnailService != nullptr) {
        thumbnailService->InvalidateThumbnail(id);
    }
}

bool GetFileInfoById(const string &fileId, int32_t &mediaType, int32_t &isTrash)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }
    auto result = uniStore->Query(cmd, {});
    if (result->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t colIndex = 0;
    CHECK_AND_RETURN_RET_LOG(result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, colIndex) == NativeRdb::E_OK, false,
        "failed to obtain the index");
    CHECK_AND_RETURN_RET_LOG(result->GetInt(colIndex, mediaType) == NativeRdb::E_OK, false,
        "get media_type failed");
    CHECK_AND_RETURN_RET_LOG(result->GetColumnIndex(MEDIA_DATA_DB_IS_TRASH, colIndex) == NativeRdb::E_OK, false,
        "failed to obtain the index");
    CHECK_AND_RETURN_RET_LOG(result->GetInt(colIndex, isTrash) == NativeRdb::E_OK, false,
        "get is_trash failed");
    return true;
}

bool DeleteInfoRecursively(const string &fileId)
{
    int32_t mediaType = MEDIA_TYPE_ALL;
    int32_t isTrash = -1;
    if (!GetFileInfoById(fileId, mediaType, isTrash)) {
        return false;
    }
    if (mediaType == MEDIA_TYPE_ALBUM) {
        MediaLibraryCommand queryCmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
        queryCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_PARENT_ID, fileId);
        if (isTrash == NOT_ISTRASH) {
            queryCmd.GetAbsRdbPredicates()->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_ISTRASH));
        } else {
            queryCmd.GetAbsRdbPredicates()->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(CHILD_ISTRASH));
        }
        auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        if (uniStore == nullptr) {
            MEDIA_ERR_LOG("uniStore is nullptr!");
            return E_HAS_DB_ERROR;
        }
        auto result = uniStore->Query(queryCmd, {});
        while (result->GoToNextRow() == NativeRdb::E_OK) {
            int32_t colIndex = 0;
            int32_t childId = -1;
            CHECK_AND_RETURN_RET_LOG(result->GetColumnIndex(MEDIA_DATA_DB_ID, colIndex) == NativeRdb::E_OK, false,
                "failed to obtain the index");
            CHECK_AND_RETURN_RET_LOG(result->GetInt(colIndex, childId) == NativeRdb::E_OK, false,
                "get file_id failed");
            if (!DeleteInfoRecursively(to_string(childId))) {
                return false;
            }
        }
    }

    InvalidateThumbnail(fileId);
    MediaLibraryCommand deleteCmd(Uri(MEDIALIBRARY_DATA_URI), OperationType::DELETE);
    int32_t deleteRows = MediaLibraryObjectUtils::DeleteInfoByIdInDb(deleteCmd, fileId);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete file info in database failed, file_id: %{public}s", fileId.c_str());
        return false;
    }
    return true;
}

// Restriction: input param cmd MUST have file id in either uri or valuebucket
int32_t MediaLibraryObjectUtils::DeleteFileObj(MediaLibraryCommand &cmd, const string &filePath)
{
    MEDIA_DEBUG_LOG("enter");
    FileAsset fileAsset;
    int32_t errCode = fileAsset.DeleteAsset(filePath);
    if (errCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Delete file in filesystem failed!");
        return errCode;
    }
    // must get parent id BEFORE deleting file in database
    string fileId = cmd.GetOprnFileId();
    if (fileId.empty()) {
        MEDIA_ERR_LOG("Get id from uri or valuebucket failed!");
        return E_INVALID_FILEID;
    }

    int32_t parentId = GetParentIdByIdFromDb(fileId);
    if (!DeleteInfoRecursively(fileId)) {
        MEDIA_ERR_LOG("Delete file info in database failed, file_id: %{public}s", fileId.c_str());
    }

    // if delete successfully, 1) update modify time
    string dirPath = MediaLibraryDataManagerUtils::GetParentPath(filePath);
    UpdateDateModified(dirPath);
    // 2) recursively delete empty parent dirs
    if (DeleteEmptyDirsRecursively(parentId) != E_SUCCESS) {
        return E_DELETE_DIR_FAIL;
    }
    // 3) delete relative records in smart album
    MediaLibraryCommand deleteSmartMapCmd(OperationObject::SMART_ALBUM_MAP, OperationType::DELETE);
    deleteSmartMapCmd.GetAbsRdbPredicates()->EqualTo(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
    return DeleteInfoByIdInDb(deleteSmartMapCmd);
}

int32_t MediaLibraryObjectUtils::DeleteDirObj(MediaLibraryCommand &cmd, const string &dirPath)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", dirPath.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    AlbumAsset dirAsset;
    if (!dirAsset.DeleteAlbumAsset(dirPath)) {
        MEDIA_ERR_LOG("Delete album asset failed!");
        return E_DELETE_DIR_FAIL;
    }

    int32_t parentId = GetParentIdByIdFromDb(cmd.GetOprnFileId());
    int32_t deleteRows = DeleteInfoByIdInDb(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete album info in database failed!");
        return E_DELETE_DIR_FAIL;
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
    if (DeleteEmptyDirsRecursively(parentId) != E_SUCCESS) {
        return E_DELETE_DIR_FAIL;
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
        return E_INVALID_PATH;
    }
    if (srcFilePath.compare(dstFilePath) == 0) {
        MEDIA_DEBUG_LOG("Skip modify the file, the path of new file is the same as old");
        return E_SUCCESS;
    }

    MediaLibraryDirOperations dirOprn;
    int32_t errCode = dirOprn.HandleDirOperations(MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION, cmd.GetValueBucket(),
        MediaLibraryDataManager::GetInstance()->rdbStore_, MediaLibraryDataManager::GetInstance()->GetDirQuerySetMap());
    if (errCode != E_SUCCESS) {
        return errCode;
    }

    string dstAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(dstFilePath);
    NativeAlbumAsset dirAsset = GetDirAsset(dstAlbumPath);
    if (dirAsset.GetAlbumId() <= 0) {
        MEDIA_ERR_LOG("Failed to get or create directory");
        return dirAsset.GetAlbumId();
    }

    FileAsset fileAsset;
    errCode = fileAsset.ModifyAsset(srcFilePath, dstFilePath);
    if (errCode != E_SUCCESS) {
        if (errCode != E_FILE_EXIST) {
            MEDIA_ERR_LOG("Failed to modify the file in the device, errCode = %{public}d", errCode);
        }
        return errCode;
    }
    string dstFileName = MediaLibraryDataManagerUtils::GetFileName(dstFilePath);
    if (ProcessNoMediaFile(dstFileName, dstAlbumPath) || ProcessHiddenFile(dstFileName, srcFilePath)) {
        MEDIA_ERR_LOG("New file is a .nomedia file or hidden file.");
        // why: return fail insteal of success
        return E_FAIL;
    }

    auto ret = UpdateFileInfoInDb(cmd, dstFilePath, dirAsset.GetAlbumId(), dirAsset.GetAlbumName());
    if (ret > 0) {
        UpdateDateModified(dstAlbumPath);
        string srcAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(srcFilePath);
        UpdateDateModified(srcAlbumPath);
    }
    return ret;
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
        return E_HAS_DB_ERROR;
    }

    if (srcDirPath.empty() || dstDirPath.empty()) {
        MEDIA_ERR_LOG("srcDirPath or dstDirPath is empty, rename failed!");
        return E_INVALID_PATH;
    }
    if (!MediaFileUtils::RenameDir(srcDirPath, dstDirPath)) {
        MEDIA_ERR_LOG("Rename directory failed!");
        return E_HAS_FS_ERROR;
    }
    string dstDirName = MediaLibraryDataManagerUtils::GetFileName(dstDirPath);
    if (ProcessHiddenDir(dstDirName, srcDirPath) == E_SUCCESS) {
        MEDIA_ERR_LOG("New album is a hidden album.");
        return E_SUCCESS;
    }

    ValuesBucket &values = cmd.GetValueBucket();
    values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, MediaLibraryDataManagerUtils::GetParentPath(dstDirPath));
    values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, dstDirPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(dstDirPath));
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
        return E_HAS_DB_ERROR;
    }
    return E_SUCCESS;
}

static int32_t OpenAsset(const string &filePath, const string &mode)
{
    std::string absFilePath;
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("Failed to get real path: %{private}s", filePath.c_str());
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("File absFilePath is %{private}s", absFilePath.c_str());

    return MediaPrivacyManager(absFilePath, mode).Open();
}

int32_t MediaLibraryObjectUtils::OpenFile(MediaLibraryCommand &cmd, const string &mode)
{
    MEDIA_DEBUG_LOG("enter");
    string uriString = cmd.GetUri().ToString();
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(uriString);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain path from Database");
        return E_INVALID_URI;
    }

    string path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    int32_t fd = OpenAsset(path, mode);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{private}d, errno %{private}d", fd, errno);
        return E_HAS_FS_ERROR;
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
        return E_INVALID_FILEID;
    }

    string srcPath = GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{public}s from database file!", strFileId.c_str());
        return E_INVALID_FILEID;
    }

    string fileName = MediaLibraryDataManagerUtils::GetFileName(srcPath);
    if ((fileName.length() != 0) && (fileName.at(0) != '.')) {
        string dirPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModified(dirPath);
    }

    InvalidateThumbnail(strFileId);
    ScanFile(srcPath);
    return E_SUCCESS;
}

void MediaLibraryObjectUtils::ScanFile(string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
    if (scanFileCb == nullptr) {
        MEDIA_ERR_LOG("Failed to create scan file callback object");
        return ;
    }
    int ret = MediaScannerManager::GetInstance()->ScanFileSync(path, scanFileCb);
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
        return E_HAS_DB_ERROR;
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
    if (DeleteInfoByPathInDb(deleteCmd, srcPath) != E_SUCCESS) {
        MEDIA_ERR_LOG("Delete rows for the old path failed");
    }
    return true;
}

int32_t MediaLibraryObjectUtils::ProcessHiddenDir(const string &dstDirName, const string &srcDirPath)
{
    if (dstDirName.empty() || srcDirPath.empty() || dstDirName.at(0) != '.') {
        MEDIA_INFO_LOG("Not a hidden dir(name begin with \'.\'), no need to do anything.");
        return E_INVALID_PATH;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryCommand deleteCmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    string dstAlbumPathPrefix = srcDirPath.back() != '/' ? (srcDirPath + "/") : srcDirPath;
    deleteCmd.GetAbsRdbPredicates()->BeginsWith(MEDIA_DATA_DB_FILE_PATH, dstAlbumPathPrefix);
    deleteCmd.GetAbsRdbPredicates()->Or()->EqualTo(MEDIA_DATA_DB_FILE_PATH, srcDirPath);

    int32_t deletedRows = -1;
    if (uniStore->Delete(deleteCmd, deletedRows) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete src dir in database failed!");
        return E_HAS_DB_ERROR;
    }
    return E_SUCCESS;
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
        MEDIA_ERR_LOG("Id for the path is incorrect: %{public}s", id.c_str());
        return nullptr;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY, networkId);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, id);

    shared_ptr<AbsSharedResultSet> resultSet = QueryWithCondition(cmd, {});
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain file asset from database");
        return nullptr;
    }

    shared_ptr<FetchResult<FileAsset>> fetchFileResult = make_shared<FetchResult<FileAsset>>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain fetch file result");
        return nullptr;
    }
    fetchFileResult->SetNetworkId(networkId);
    return fetchFileResult->GetObjectFromRdb(resultSet, 0);
}

void MediaLibraryObjectUtils::GetDefaultRelativePath(const int32_t mediaType, string &relativePath)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_DIR, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, to_string(mediaType));

    shared_ptr<AbsSharedResultSet> resultSet = QueryWithCondition(cmd, {});
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain file asset from database, mediaType: %{public}d", static_cast<int>(mediaType));
        return;
    }

    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        relativePath = get<string>(ResultSetUtils::GetValFromColumn(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY,
            resultSet, TYPE_STRING));
    }
}

string GetRelativePathFromFilePath(const string &path)
{
    string relativePath;
    if (path.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = path.substr(ROOT_MEDIA_DIR.length());
    }
    size_t pos = relativePath.rfind('/');
    if (pos != string::npos) {
        relativePath = relativePath.substr(0, pos + 1);
    }
    return relativePath;
}

int32_t MediaLibraryObjectUtils::UpdateFileInfoInDb(MediaLibraryCommand &cmd, const string &dstPath,
    const int32_t &bucketId, const string &bucketName)
{
    MEDIA_DEBUG_LOG("enter, dstPath: %{private}s,", dstPath.c_str());
    if (dstPath.empty()) {
        MEDIA_ERR_LOG("Input argument is empty.");
        return E_INVALID_PATH;
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
        return E_HAS_FS_ERROR;
    }
    string fileId = cmd.GetOprnFileId();
    string mimeType = ScannerUtils::GetMimeTypeFromExtension(ScannerUtils::GetFileExtensionFromFileUri(dstPath));
    MediaType mediaType = ScannerUtils::GetMediatypeFromMimetype(mimeType);
    string displayName = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(dstPath);
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, displayName);
    values.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    values.PutString(MEDIA_DATA_DB_FILE_PATH, dstPath);
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, GetRelativePathFromFilePath(dstPath));
    values.PutString(MEDIA_DATA_DB_BUCKET_NAME, bucketName);
    values.PutString(MEDIA_DATA_DB_MIME_TYPE, mimeType);
    values.PutString(MEDIA_DATA_DB_URI, MediaLibraryDataManagerUtils::GetMediaTypeUri(mediaType));
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    values.PutInt(MEDIA_DATA_DB_BUCKET_ID, bucketId);
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, bucketId);
    values.PutLong(MEDIA_DATA_DB_SIZE, statInfo.st_size);
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
        return E_INVALID_PATH;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    int32_t columnIndex = 0;
    string newPath = path;
    if (newPath.back() == '/') {
        newPath.pop_back();
    }
    int32_t fileId = E_INVALID_FILEID;

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_ID);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, newPath);
    cmd.GetAbsRdbPredicates()->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_ISTRASH));

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
        return E_INVALID_FILEID;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
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
        return E_HAS_DB_ERROR;
    }

    int64_t outRowId = E_HAS_DB_ERROR;
    int32_t result = uniStore->Insert(cmd, outRowId);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert operation failed. Result %{public}d. Deleted %{public}d",
            result, static_cast<int32_t>(outRowId));
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}

int32_t MediaLibraryObjectUtils::DeleteInfoByPathInDb(MediaLibraryCommand &cmd, const string &path)
{
    MEDIA_DEBUG_LOG("enter, path = %{private}s", path.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    int32_t deletedRows = E_HAS_DB_ERROR;
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, path);
    int32_t result = uniStore->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{public}d. Deleted %{public}d", result, deletedRows);
        return E_HAS_DB_ERROR;
    }

    return E_SUCCESS;
}

int32_t MediaLibraryObjectUtils::DeleteInfoByIdInDb(MediaLibraryCommand &cmd, const string &fileId)
{
    MEDIA_DEBUG_LOG("enter, fileId = %{private}s", fileId.c_str());
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryObjectUtils DeleteFile: Index not digit");
            return E_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, strRow);
    }

    int32_t deletedRows = E_HAS_DB_ERROR;
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
        return E_HAS_DB_ERROR;
    }

    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, path);
    int32_t updatedRows = E_HAS_DB_ERROR;
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
        return E_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = fileId.empty() ? cmd.GetOprnFileId() : fileId;
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow) || (stoi(strRow) == -1)) {
            MEDIA_ERR_LOG("DeleteFile: Index not digit");
            return E_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, strRow);
    }

    int32_t updatedRows = E_HAS_DB_ERROR;
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

bool MediaLibraryObjectUtils::IsColumnValueExist(const string &value, const string &column)
{
    if (column.empty()) {
        MEDIA_ERR_LOG("Empty column param");
        return false;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return false;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(column, value);
    vector<string> columns;
    columns.push_back(column);
    auto queryResultSet = uniStore->Query(cmd, columns);
    if (queryResultSet != nullptr) {
        int32_t count = 0;
        queryResultSet->GetRowCount(count);
        MEDIA_DEBUG_LOG("count is %{private}d", count);
        if (count > 0) {
            return true;
        }
    }
    return false;
}

bool MediaLibraryObjectUtils::IsAssetExistInDb(const int32_t id)
{
    if (id <= 0) {
        MEDIA_ERR_LOG("Invalid id param");
        return false;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(id));
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_ISTRASH));
    vector<string> columns;
    auto queryResultSet = QueryWithCondition(cmd, columns);
    if (queryResultSet != nullptr && queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        return true;
    }
    return false;
}

bool MediaLibraryObjectUtils::IsFileExistInDb(const string &path)
{
    if (path.empty()) {
        MEDIA_ERR_LOG("path is incorrect");
        return false;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_FILE_PATH, path)
        ->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    auto queryResultSet = QueryWithCondition(cmd, columns);
    if (queryResultSet != nullptr && queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        return true;
    }

    return false;
}
} // namespace Media
} // namespace OHOS
