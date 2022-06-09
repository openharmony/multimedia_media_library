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

#include "medialibrary_real_file_manager.h"

#include "album_asset.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_thumbnail_manager.h"
#include "value_object.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
using namespace std;

ValuesBucket MediaLibraryRealFileManager::UpdateBasicAssetDetails(int32_t mediaType, const string &fileName,
                                                                  const string &relPath, const string &path)
{
    ValuesBucket assetInfoBucket;
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, relPath);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_NAME, fileName);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(fileName));
    struct stat statInfo {
    };
    if (stat(path.c_str(), &statInfo) == 0) {
        assetInfoBucket.PutLong(Media::MEDIA_DATA_DB_SIZE, statInfo.st_size);
        assetInfoBucket.PutLong(Media::MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    }
    assetInfoBucket.PutInt(Media::MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_FILE_PATH, path);
    return assetInfoBucket;
}

int32_t MediaLibraryRealFileManager::CreateDirectorys(const string &path)
{
    if (!path.empty()) {
        ValuesBucket values;
        string albumPath = ROOT_MEDIA_DIR + path;
        values.PutString(MEDIA_DATA_DB_FILE_PATH, albumPath);
        MediaLibraryCommand cmd(FILESYSTEM_ALBUM, CREATE, values);
        return CreateAlbum(cmd, false);
    }
    return DATA_ABILITY_FAIL;
}

NativeAlbumAsset MediaLibraryRealFileManager::GetAlbumAsset(const std::string &relativePath)
{
    NativeAlbumAsset albumAsset;
    if (relativePath.empty()) {
        MEDIA_ERR_LOG("Path is empty, create failed!");
        albumAsset.SetAlbumId(DATA_ABILITY_FAIL);
        return albumAsset;
    }

    int32_t albumId = CreateDirectorys(relativePath);
    MEDIA_ERR_LOG("After CreateDirectorys, get albumId = %{private}d!", albumId);
    if (albumId < 0) {
        albumAsset.SetAlbumId(albumId);
        return albumAsset;
    }

    vector<string> columns;
    MediaLibraryCommand cmd(FILESYSTEM_ALBUM, QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(albumId));
    albumAsset.SetAlbumId(albumId);

    auto queryResultSet = uniStore_->Query(cmd, columns);
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexName;
        string nameVal;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndexName);
        queryResultSet->GetString(columnIndexName, nameVal);
        albumAsset.SetAlbumName(nameVal);
        MEDIA_INFO_LOG("HandleModifyAsset bucketId = %{private}d bucketName = %{private}s", albumId, nameVal.c_str());
    }
    return albumAsset;
}

void MediaLibraryRealFileManager::UpdateDateModifiedForAlbum(const string &albumPath)
{
    if (albumPath.empty()) {
        MEDIA_ERR_LOG("Path is empty, update failed!");
        return;
    }

    MediaLibraryCommand cmd(FILESYSTEM_ALBUM, UPDATE);
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(albumPath));
    cmd.SetValueBucket(valuesBucket);

    int32_t updateResult = ModifyInfoInDbWithPath(cmd, albumPath);
    if (updateResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Update failed for album");
    }
}

// create
int32_t MediaLibraryRealFileManager::CreateFileAsset(MediaLibraryCommand &cmd)
{
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

    NativeAlbumAsset nativeAlbumAsset = GetAlbumAsset(relativePath);
    if (GetIdByPathFromDb(path) >= 0) {
        if (fileAsset.IsFileExists(path)) {
            // File aready exist, not need to create again
            return DATA_ABILITY_DUPLICATE_CREATE;
        }
        MediaLibraryCommand deleteCmd(FILESYSTEM_ASSET, DELETE);
        if (DeleteInfoInDbWithPath(deleteCmd, path) != DATA_ABILITY_SUCCESS) {
            // Delete the record in database if file is not in filesystem any more
            MEDIA_ERR_LOG("MediaLibraryRealFileManager CreateFileAsset: delete info in db failed");
            return DATA_ABILITY_FAIL;
        }
    }

    int32_t errCode = fileAsset.CreateAsset(path);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("MediaLibraryRealFileManager CreateFileAsset: create file asset failed");
        return errCode;
    }
    // Fill basic file information into DB
    ValuesBucket updatedAssetInfo = UpdateBasicAssetDetails(mediaType, displayName, relativePath, path);
    updatedAssetInfo.PutInt(MEDIA_DATA_DB_BUCKET_ID, nativeAlbumAsset.GetAlbumId());
    updatedAssetInfo.PutInt(MEDIA_DATA_DB_PARENT_ID, nativeAlbumAsset.GetAlbumId());
    updatedAssetInfo.PutString(MEDIA_DATA_DB_BUCKET_NAME, nativeAlbumAsset.GetAlbumName());
    MEDIA_ERR_LOG("[lqh]nativeAlbumAsset.GetAlbumId() = %d, nativeAlbumAsset.GetAlbumName() = %s",
                  nativeAlbumAsset.GetAlbumId(), nativeAlbumAsset.GetAlbumName().c_str());
    cmd.SetValueBucket(updatedAssetInfo);
    int64_t outRowId = -1;
    errCode = uniStore_->Insert(cmd, outRowId);
    MEDIA_ERR_LOG("[lqh]insert errCode = %d, outRowId = %lld", errCode, outRowId);
    if (errCode == E_OK) {
        return outRowId;
    }
    return errCode;
}

NativeAlbumAsset MediaLibraryRealFileManager::GetLastAlbumExistInDb(const std::string &albumPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    NativeAlbumAsset nativeAlbumAsset;
    string lastPath = albumPath;
    if (lastPath.back() == '/') {
        lastPath.pop_back();
    }
    int32_t albumId = 0;
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
            albumId = lastPathId;
        }
    } while (lastPathId < 0);
    nativeAlbumAsset.SetAlbumId(albumId);
    nativeAlbumAsset.SetAlbumPath(lastPath);
    return nativeAlbumAsset;
}

int32_t MediaLibraryRealFileManager::DeleteRows(const std::vector<int64_t> &rowIds)
{
    int32_t errCode = 0;

    for (auto id : rowIds) {
        MediaLibraryCommand cmd(FILESYSTEM_ALBUM, DELETE);
        DeleteInfoInDbWithId(cmd, to_string(id));
    }
    return errCode;
}

int32_t MediaLibraryRealFileManager::InsertAlbumToDb(const std::string &albumPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    NativeAlbumAsset albumAsset = GetLastAlbumExistInDb(albumPath);
    string parentPath = albumAsset.GetAlbumPath();
    int32_t parentId = albumAsset.GetAlbumId();
    string path = albumPath;
    vector<int64_t> outIds;

    MEDIA_INFO_LOG("[lqh] albumPath = %{public}s, parentPath = %{public}s, parentId = %{public}d", albumPath.c_str(),
                   parentPath.c_str(), parentId);

    while (parentPath.length() < path.length() - 1) {
        ValuesBucket values;
        string relativePath;
        if (path.substr(path.length() - 1) != "/") {
            path = path + "/";
        }
        size_t index = path.find("/", parentPath.length() + 1);
        parentPath = path.substr(0, index);
        values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, parentPath);
        string title = parentPath;
        size_t titleIndex = parentPath.rfind('/');
        if (index != string::npos) {
            title = parentPath.substr(titleIndex + 1);
            relativePath = parentPath.substr(0, titleIndex);
            if (relativePath.length() > ROOT_MEDIA_DIR.length()) {
                relativePath = relativePath.substr(ROOT_MEDIA_DIR.length()) + "/";
            } else {
                relativePath = "";
            }
        }
        if (!MediaFileUtils::CheckDisplayName(title)) {
            parentId = DATA_ABILITY_VIOLATION_PARAMETERS;
            DeleteRows(outIds);
            break;
        }
        values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        values.PutString(Media::MEDIA_DATA_DB_TITLE, title);
        values.PutString(Media::MEDIA_DATA_DB_NAME, title);
        values.PutInt(Media::MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
        values.PutInt(Media::MEDIA_DATA_DB_PARENT_ID, parentId);
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, MediaFileUtils::GetAlbumDateModified(path));
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::GetAlbumDateModified(path));

        MediaLibraryCommand cmd(FILESYSTEM_ALBUM, CREATE);
        cmd.SetValueBucket(values);
        int64_t rowId = 0;
        if (uniStore_->Insert(cmd, rowId) != NativeRdb::E_OK) {
            parentId = DATA_ABILITY_FAIL;
            break;
        }
        parentId = rowId;
        outIds.push_back(rowId);
    }
    MEDIA_INFO_LOG("[lqh] parentId = %{public}d", parentId);
    return parentId;
}

int32_t MediaLibraryRealFileManager::CreateAlbum(MediaLibraryCommand &cmd, bool checkDup)
{
    MEDIA_INFO_LOG("[lqh] enter");
    AlbumAsset albumAsset;
    string albumPath = "";
    ValueObject valueObject;
    const ValuesBucket &values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject)) {
        valueObject.GetString(albumPath);
    }
    CHECK_AND_RETURN_RET_LOG(!albumPath.empty(), DATA_ABILITY_FAIL, "Path is empty");
    albumAsset.SetAlbumPath(albumPath);
    int32_t rowId = GetIdByPathFromDb(albumPath);
    MEDIA_INFO_LOG("albumPath %{private}s id in database is %{private}d", albumPath.c_str(), rowId);
    if (rowId < 0) {
        albumAsset.CreateAlbumAsset();
        return InsertAlbumToDb(albumPath); // success return rowId
    }

    if (!MediaFileUtils::IsDirectory(albumPath)) {
        albumAsset.CreateAlbumAsset();
        return rowId;
    }
    return (checkDup ? DATA_ABILITY_DUPLICATE_CREATE : rowId);
}

int32_t MediaLibraryRealFileManager::CreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // MEDIA_FILEOPRN_CREATEASSET, MEDIA_ALBUMOPRN_CREATEALBUM
    if (uniStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryFileManager Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }

    if (!MediaLibraryDataManagerUtils::CheckFileNameValid(cmd.GetValueBucket())) {
        return DATA_ABILITY_FILE_NAME_INVALID;
    }

    if (cmd.GetOprnObject() == FILESYSTEM_ASSET) {
        int32_t result = CreateFileAsset(cmd);
        return result;
    } else if (cmd.GetOprnObject() == FILESYSTEM_ALBUM) {
        return CreateAlbum(cmd, true);
    }
    // MEDIA_INFO_LOG("TODO here");
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryRealFileManager::BatchCreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryRealFileManager::DeleteFileAsset(MediaLibraryCommand &cmd, const string &srcPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    FileAsset fileAsset;
    int32_t errCode = fileAsset.DeleteAsset(srcPath);
    if (errCode != DATA_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("Delete file in filesystem failed!");
        return errCode;
    }

    int32_t deleteRows = DeleteInfoInDbWithId(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete file info in database failed!");
        return DATA_ABILITY_FAIL;
    }
    // if delete success, 1)get parent path, 2) update modify time, 3) delete smart album
    string albumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
    UpdateDateModifiedForAlbum(albumPath);

    MediaLibraryCommand deleteSmartMapCmd(SMART_ALBUM_MAP, DELETE);
    string strCondition = SMARTALBUM_MAP_DE_ASSETS_COND + " = ?";
    deleteSmartMapCmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    errCode = DeleteInfoInDbWithId(deleteSmartMapCmd, cmd.GetOprnFileId());
    return deleteRows;
}

int32_t MediaLibraryRealFileManager::DeleteAlbum(MediaLibraryCommand &cmd, const string &albumPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    AlbumAsset albumAsset;
    if (albumAsset.DeleteAlbumAsset(albumPath) == true) {
        MEDIA_ERR_LOG("Delete album asset failed!");
        return DATA_ABILITY_FAIL;
    }
    int32_t deleteRows = DeleteInfoInDbWithId(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete album info in database failed!");
        return DATA_ABILITY_FAIL;
    }
    // need to delete subfiles in the album when deleting album, delete: xx/xxx/album_name/%
    MediaLibraryCommand deleteSubfilesCmd(FILESYSTEM_ASSET, DELETE);
    string strCondition = MEDIA_DATA_DB_FILE_PATH + " LIKE ?";
    deleteSubfilesCmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    vector<string> whereArgs = {(albumPath.back() != '/' ? (albumPath + "/%") : (albumPath + "%"))};
    deleteSubfilesCmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = ALBUM_OPERATION_ERR;
    int32_t deleteResult = uniStore_->Delete(deleteSubfilesCmd, deletedRows);
    if (deleteResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete subfiles in album %{private}s failed", albumPath.c_str());
    }
    return deleteRows;
}

int32_t MediaLibraryRealFileManager::DeleteFile(MediaLibraryCommand &cmd)
{
    // get file id
    string strId = cmd.GetOprnFileId();
    if (strId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return DATA_ABILITY_FAIL;
    }
    string srcPath = GetPathFromDb(strId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strId.c_str());
        return DATA_ABILITY_FAIL;
    }

    if (cmd.GetOprnObject() == FILESYSTEM_ASSET) {
        return DeleteFileAsset(cmd, srcPath);
    } else if (cmd.GetOprnObject() == FILESYSTEM_ALBUM) {
        return DeleteAlbum(cmd, srcPath);
    }
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryRealFileManager::ModifyFileAsset(MediaLibraryCommand &cmd, const string &srcPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string dstFileName, dstReFilePath;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(dstFileName);
    }
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(dstReFilePath);
    }
    string dstFilePath = ROOT_MEDIA_DIR + dstReFilePath + dstFileName;
    if (srcPath.compare(dstFilePath) == 0) {
        // [todo] 如果不改名字，只改相关信息？
        MEDIA_ERR_LOG("Failed to modify the file, the path of new file is the same as old");
        return DATA_ABILITY_FAIL;
    }

    string dstAlbumPath = ROOT_MEDIA_DIR + dstReFilePath;
    if (dstAlbumPath.back() == '/') {
        dstAlbumPath.pop_back();
    }
    MEDIA_ERR_LOG("HandleModifyAsset dstAlbumPath = %{private}s", dstAlbumPath.c_str());
    NativeAlbumAsset albumAsset = GetAlbumAsset(dstReFilePath);

    FileAsset fileAsset;
    int32_t errCode = fileAsset.ModifyAsset(srcPath, dstFilePath);
    if (errCode == DATA_ABILITY_MODIFY_DATA_FAIL) {
        MEDIA_ERR_LOG("Failed to modify the file in the device");
        return errCode;
    }

    if (IsNoMediaFile(dstFileName, dstAlbumPath) || IsHiddenFile(dstFileName, srcPath)) {
        MEDIA_ERR_LOG("New file is a .nomedia file or hidden file.");
        return DATA_ABILITY_FAIL;
    }

    if (UpdateFileInfoInDb(cmd, dstFilePath, albumAsset.GetAlbumId(), albumAsset.GetAlbumName()) > 0) {
        UpdateDateModifiedForAlbum(dstAlbumPath);
        string srcAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModifiedForAlbum(srcAlbumPath);
    }
    return errCode;
}

int32_t MediaLibraryRealFileManager::ModifyAlbum(MediaLibraryCommand &cmd, const string &albumPath)
{
    ValuesBucket values = cmd.GetValueBucket();
    string albumNewName = "";
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_ALBUM_NAME, valueObject)) {
        valueObject.GetString(albumNewName);
    }

    if (albumPath.empty() || albumNewName.empty()) {
        MEDIA_ERR_LOG("AlbumPath or albumNewName is empty, modify failed!");
        return DATA_ABILITY_FAIL;
    }

    AlbumAsset albumAsset;
    albumAsset.SetAlbumName(albumNewName);
    if (!albumAsset.ModifyAlbumAsset(albumPath)) {
        MEDIA_ERR_LOG("Modify album asset failed!");
        return DATA_ABILITY_FAIL;
    }

    if (IsHiddenFile(albumNewName, albumPath)) {
        MEDIA_ERR_LOG("New album is a hidden album.");
        return DATA_ABILITY_SUCCESS;
    }

    string newAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(albumPath) + "/" + albumNewName;
    values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, MediaLibraryDataManagerUtils::GetParentPath(albumPath));
    values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaLibraryDataManagerUtils::GetPathDateModified(newAlbumPath));

    cmd.SetValueBucket(values);
    int32_t retVal = ModifyInfoInDbWithId(cmd);
    if (retVal == DATA_ABILITY_SUCCESS && !newAlbumPath.empty()) {
        // Update the path, relative path and album Name for internal files
        const std::string modifyAlbumInternalsStmt =
            "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace(" +
            MEDIA_DATA_DB_FILE_PATH + ", '" + albumPath + "/' , '" + newAlbumPath + "/'), " +
            MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH + ", '" + albumPath + "', '" +
            newAlbumPath + "'), " + MEDIA_DATA_DB_ALBUM_NAME + " = replace(" + MEDIA_DATA_DB_ALBUM_NAME + ", '" +
            MediaLibraryDataManagerUtils::GetFileName(albumPath) + "', '" + albumNewName + "')" + "where " +
            MEDIA_DATA_DB_FILE_PATH + " LIKE '" + albumPath + "/%'";

        auto ret = uniStore_->ExecuteSql(modifyAlbumInternalsStmt);
        if (ret != 0) {
            MEDIA_ERR_LOG("Album update sql failed");
            return DATA_ABILITY_FAIL;
        }
    }
    return retVal;
}

int32_t MediaLibraryRealFileManager::ModifyFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strFileId = cmd.GetOprnFileId();
    if (strFileId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return DATA_ABILITY_FAIL;
    }
    string srcPath = GetPathFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strFileId.c_str());
        return DATA_ABILITY_FAIL;
    }
    if (cmd.GetOprnObject() == FILESYSTEM_ASSET) {
        return ModifyFileAsset(cmd, srcPath);
    } else if (cmd.GetOprnObject() == FILESYSTEM_ALBUM) {
        return ModifyAlbum(cmd, srcPath);
    }

    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryRealFileManager::CloseFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strFileId = cmd.GetOprnFileId();
    if (strFileId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return DATA_ABILITY_FAIL;
    }
    string srcPath = GetPathFromDb(strFileId);
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
        string albumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModifiedForAlbum(albumPath);
    }

    MediaLibraryThumbnailManager thumbnail;
    string kvId;
    thumbnail.CreateThumbnail(strFileId, kvId);
    ScanFile(srcPath);
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryRealFileManager::ScanFile(const string &srcPath)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string path = srcPath;
    int ret = MediaScannerObj::GetMediaScannerInstance()->ScanFile(path, nullptr);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed!");
    }
}

bool MediaLibraryRealFileManager::IsNoMediaFile(const string &dstFileName, const string &dstAlbumPath)
{
    if (dstFileName.empty() || dstFileName != ".nomedia") {
        MEDIA_INFO_LOG("Not a .nomedia file, no need to do anything.");
        return false;
    }

    // the whole folder containing .nomedia file is invisible in database
    MediaLibraryCommand cmd(FILESYSTEM_ALBUM, DELETE);
    string strCondition = MEDIA_DATA_DB_FILE_PATH + " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ?";
    vector<string> whereArgs = {(dstAlbumPath.back() != '/' ? (dstAlbumPath + "/%") : (dstAlbumPath + "%")),
                                dstAlbumPath};
    cmd.GetAbsRdbPredicates()->SetWhereClause(strCondition);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);

    int32_t deletedRows = ALBUM_OPERATION_ERR;
    int32_t deleteResult = uniStore_->Delete(cmd, deletedRows);
    if (deleteResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete rows for the hidden album failed");
    }
    return true;
}

bool MediaLibraryRealFileManager::IsHiddenFile(const string &dstFileName, const string &srcPath)
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

int32_t MediaLibraryRealFileManager::UpdateFileInfoInDb(MediaLibraryCommand &cmd, const string &dstPath,
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

    stat statInfo;
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

} // namespace Media
} // namespace OHOS
