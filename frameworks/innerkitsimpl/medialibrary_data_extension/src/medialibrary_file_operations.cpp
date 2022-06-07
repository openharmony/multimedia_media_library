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

#include "medialibrary_file_operations.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_smartalbum_map_db.h"
#include "medialibrary_dir_operations.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
void UpdateDateModifiedForAlbum(const shared_ptr<RdbStore> &rdbStore, const string &albumPath)
{
    if (!albumPath.empty()) {
        int32_t count(0);
        vector<string> whereArgs = { albumPath };
        DataShareValuesBucket valuesBucket;
        valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED,
            MediaLibraryDataManagerUtils::GetAlbumDateModified(albumPath));

        int32_t updateResult = rdbStore->Update(count, MEDIALIBRARY_TABLE, RdbUtils::ToValuesBucket(valuesBucket),
                                                MEDIA_DATA_DB_FILE_PATH + " = ?", whereArgs);
        if (updateResult != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Update failed for album");
        }
    }
}

int32_t MediaLibraryFileOperations::HandleCreateAsset(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string relativePath(""), path(""), displayName("");
    int32_t errCode = DATA_ABILITY_FAIL;
    int32_t mediaType = static_cast<int32_t>(MEDIA_TYPE_FILE);
    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;
    ValueObject valueObject;
    NativeAlbumAsset  nativeAlbumAsset;
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
    vector<int32_t> outIds;
    nativeAlbumAsset = MediaLibraryDataManagerUtils::CreateDirectorys(relativePath, rdbStore, outIds);
    if (nativeAlbumAsset.GetAlbumId() < 0) {
        return nativeAlbumAsset.GetAlbumId();
    }
    nativeAlbumAsset = MediaLibraryDataManagerUtils::GetAlbumAsset(to_string(nativeAlbumAsset.GetAlbumId()), rdbStore);
    if (MediaLibraryDataManagerUtils::isFileExistInDb(path, rdbStore)) {
        if (fileAsset.IsFileExists(path)) {
            return DATA_ABILITY_DUPLICATE_CREATE;
        } else {
            int32_t deletedRows(FILE_OPERATION_ERR);
            vector<string> whereArgs = { path };
            int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, "data = ?", whereArgs);
            if (deleteResult != NativeRdb::E_OK) {
                return errCode;
            }
        }
    }
    errCode = fileAsset.CreateAsset(path);
    if (errCode == DATA_ABILITY_SUCCESS) {
        // Fill basic file information into DB
        ValuesBucket updatedAssetInfo = UpdateBasicAssetDetails(mediaType, displayName, relativePath, path);
        updatedAssetInfo.PutInt(MEDIA_DATA_DB_BUCKET_ID, nativeAlbumAsset.GetAlbumId());
        updatedAssetInfo.PutInt(MEDIA_DATA_DB_PARENT_ID, nativeAlbumAsset.GetAlbumId());
        updatedAssetInfo.PutString(MEDIA_DATA_DB_BUCKET_NAME, nativeAlbumAsset.GetAlbumName());
        // will return row id
        return fileDbOprn.Insert(updatedAssetInfo, rdbStore);
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::HandleCloseAsset(string &uriStr, string &srcPath, const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    int32_t errorCode = MediaLibraryDataManagerUtils::setFilePending(uriStr, false, rdbStore);
    if (errorCode == DATA_ABILITY_FAIL) {
        MEDIA_ERR_LOG("HandleCloseAsset Set file to pending DB error");
        return DATA_ABILITY_FAIL;
    }

    string fileName;

    if (!srcPath.empty() && ((fileName = MediaLibraryDataManagerUtils::GetFileName(srcPath)).length() != 0) &&
        (fileName.at(0) != '.')) {
        string albumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
        UpdateDateModifiedForAlbum(rdbStore, albumPath);
    }

    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryFileOperations::HandleGetAlbumCapacity(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    MEDIA_INFO_LOG("HandleGetAlbumCapacity IN");
    int32_t errorCode = DATA_ABILITY_FAIL;
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    ValueObject valueObject;
    bool isFavourite = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_FAV, valueObject)) {
        valueObject.GetBool(isFavourite);
    }

    bool isTrash = false;
    if (isFavourite) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isFavourite");
        resultSet= MediaLibraryDataManagerUtils::QueryFavFiles(rdbStore);
    } else if (isTrash) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isTrash");
        resultSet= MediaLibraryDataManagerUtils::QueryTrashFiles(rdbStore);
    }

    if (resultSet != nullptr) {
        resultSet->GetRowCount(errorCode);
        MEDIA_INFO_LOG("HandleGetAlbumCapacity GetRowCount %{private}d", errorCode);
    }

    MEDIA_INFO_LOG("HandleGetAlbumCapacity OUT");
    return errorCode;
}
int ModifyDisName(const string &dstFileName,
    const string &destAlbumPath, const string &srcPath, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t errCode = DATA_ABILITY_SUCCESS;
    if (dstFileName == ".nomedia") {
        int32_t deletedRows(ALBUM_OPERATION_ERR);
        vector<string> whereArgs = {(destAlbumPath.back() != '/' ?
            (destAlbumPath + "/%") : (destAlbumPath + "%")), destAlbumPath};

        int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE,
            MEDIA_DATA_DB_FILE_PATH + " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ?", whereArgs);
        if (deleteResult != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Delete rows for the hidden album failed");
        }
        whereArgs.clear();
        whereArgs.push_back(srcPath);
        deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, MEDIA_DATA_DB_FILE_PATH + " = ?", whereArgs);
        if (deleteResult != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Delete rows for the old path failed");
        }
        errCode = DATA_ABILITY_FAIL;
    }

    if ((!dstFileName.empty()) && (dstFileName.at(0) == '.')) {
        int32_t deletedRows(ALBUM_OPERATION_ERR);
        vector<string> whereArgs = { srcPath };

        int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE,
                                                MEDIA_DATA_DB_FILE_PATH + " = ?", whereArgs);
        if (deleteResult != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Delete rows failed");
        }
        errCode = DATA_ABILITY_FAIL;
    }
    return errCode;
}
int32_t MediaLibraryFileOperations::HandleModifyAsset(const string &rowNum, const string &srcPath,
    const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string dstFilePath, dstReFilePath, dstFileName, destAlbumPath, bucketName;
    int32_t errCode = DATA_ABILITY_SUCCESS;
    int32_t bucketId = 0;
    ValueObject valueObject;
    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(dstFileName);
    }
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(dstReFilePath);
    }
    dstFilePath = ROOT_MEDIA_DIR + dstReFilePath + dstFileName;
    destAlbumPath = ROOT_MEDIA_DIR + dstReFilePath;
    if (destAlbumPath.back() == '/') {
        destAlbumPath = destAlbumPath.substr(0, destAlbumPath.length() - 1);
    }
    bucketId = MediaLibraryDataManagerUtils::GetParentIdFromDb(destAlbumPath, rdbStore);
    if ((!dstReFilePath.empty()) && (bucketId == 0)) {
        vector<int32_t> outIds;
        NativeAlbumAsset nativeAlbumAsset = MediaLibraryDataManagerUtils::CreateDirectorys(dstReFilePath,
                                                                                           rdbStore, outIds);
        if (nativeAlbumAsset.GetAlbumId() < 0) {
            MEDIA_ERR_LOG("Failed to CreateDirectorys err:%{private}d", nativeAlbumAsset.GetAlbumId());
            return nativeAlbumAsset.GetAlbumId();
        }
        bucketId = nativeAlbumAsset.GetAlbumId();
    }
    bucketName = MediaLibraryDataManagerUtils::GetParentDisplayNameFromDb(bucketId, rdbStore);
    if (srcPath.compare(dstFilePath) != 0) {
        errCode = fileAsset.ModifyAsset(srcPath, dstFilePath);
        if (errCode == DATA_ABILITY_MODIFY_DATA_FAIL) {
            return errCode;
        }
        errCode = ModifyDisName(dstFileName, destAlbumPath, srcPath, rdbStore);
        if (errCode == DATA_ABILITY_FAIL) {
            return errCode;
        }
        if (fileDbOprn.Modify(rowNum, dstFilePath, bucketId, bucketName, rdbStore) > 0) {
            UpdateDateModifiedForAlbum(rdbStore, destAlbumPath);
            string srcAlbumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
            UpdateDateModifiedForAlbum(rdbStore, srcAlbumPath);
        }
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::HandleDeleteAsset(const string &rowNum,
    const string &srcPath,
    const shared_ptr<RdbStore> &rdbStore, const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    int32_t errCode = DATA_ABILITY_FAIL;
    FileAsset fileAsset;
    MediaLibraryFileDb fileDbOprn;
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    MediaLibraryDirOperations dirOprn;
    ValuesBucket values;
    if (!srcPath.empty()) {
        errCode = fileAsset.DeleteAsset(srcPath);
    }
    if (errCode == DATA_ABILITY_SUCCESS) {
        ValueObject valueObject;
        shared_ptr<AbsSharedResultSet> queryResultSet;
        vector<string> columns, selectionArgs;
        selectionArgs.push_back(rowNum);
        AbsRdbPredicates mediaLibAbsPred(MEDIALIBRARY_TABLE);
        mediaLibAbsPred.SetWhereClause(MEDIA_DATA_DB_ID + " = ?");
        mediaLibAbsPred.SetWhereArgs(selectionArgs);
        queryResultSet = rdbStore -> Query(mediaLibAbsPred, columns);
        if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexParentId, parentIdVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
            queryResultSet->GetInt(columnIndexParentId, parentIdVal);
            values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentIdVal);
        }
        errCode = fileDbOprn.Delete(rowNum, rdbStore);
        if (errCode > 0) {
            string albumPath = MediaLibraryDataManagerUtils::GetParentPath(srcPath);
            UpdateDateModifiedForAlbum(rdbStore, albumPath);
            dirOprn.HandleDirOperations(MEDIA_DIROPRN_DELETEDIR, values, rdbStore, dirQuerySetMap);
            smartAlbumMapDbOprn.DeleteAllAssetsMapInfo(std::stoi(rowNum), rdbStore);
        }
    }

    return errCode;
}
void CreateThumbnail(const shared_ptr<RdbStore> &rdbStore,
    const shared_ptr<MediaLibraryThumbnail> &mediaThumbnail, string id)
{
    if (!id.empty()) {
        string kvId;
        ThumbRdbOpt opts = {
            .store = rdbStore,
            .table = MEDIALIBRARY_TABLE,
            .row = id
        };

        if (!mediaThumbnail->CreateThumbnail(opts, kvId)) {
            MEDIA_ERR_LOG("Create thumbnail error");
        }
    }
}
int32_t MediaLibraryFileOperations::HandleIsDirectoryAsset(const ValuesBucket &values,
                                                           const shared_ptr<RdbStore> &rdbStore)
{
    int32_t errCode = DATA_ABILITY_FAIL;
    ValueObject valueObject;
    int32_t id = 0;
    shared_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    int32_t columnIndex;
    string path = "";
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(id);
    }
    MEDIA_ERR_LOG("HandleIsDirectoryAsset id = %{private}d", id);
    if (id != 0) {
        string tableName = MEDIALIBRARY_TABLE;
        AbsRdbPredicates mediaLibAbsPredFile(tableName);
        mediaLibAbsPredFile.EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
        queryResultSet = rdbStore->Query(mediaLibAbsPredFile, columns);
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
            queryResultSet->GetString(columnIndex, path);
            MEDIA_ERR_LOG("HandleIsDirectoryAsset path = %{private}s", path.c_str());
        }
        if (MediaFileUtils::IsDirectory(path)) {
            errCode = SUCCESS;
        }
    }
    return errCode;
}
int32_t MediaLibraryFileOperations::HandleFileOperation(const string &oprn, const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore, const std::shared_ptr<MediaLibraryThumbnail> &mediaThumbnail,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    int32_t errCode = DATA_ABILITY_FAIL;

    if (oprn == MEDIA_FILEOPRN_CREATEASSET) {
        return HandleCreateAsset(values, rdbStore, dirQuerySetMap);
    } else if (oprn == MEDIA_FILEOPRN_ISDIRECTORY) {
        return HandleIsDirectoryAsset(values, rdbStore);
    } else if (oprn == MEDIA_FILEOPRN_GETALBUMCAPACITY) {
        return HandleGetAlbumCapacity(values, rdbStore);
    }

    string actualUri;
    ValueObject valueObject;

    if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        valueObject.GetString(actualUri);
    }
    string srcPath;
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(actualUri);
    if (!networkId.empty()) {
        if (oprn == MEDIA_FILEOPRN_CLOSEASSET) {
            return HandleCloseAsset(actualUri, srcPath, values, rdbStore);
        } else {
            return errCode;
        }
    }

    string id = MediaLibraryDataManagerUtils::GetIdFromUri(actualUri);
    srcPath = MediaLibraryDataManagerUtils::GetPathFromDb(id, rdbStore);
    string recyclePath = MediaLibraryDataManagerUtils::GetRecyclePathFromDb(id, rdbStore);
    CHECK_AND_RETURN_RET_LOG(!srcPath.empty(), DATA_ABILITY_FAIL, "Failed to obtain path from Database");

    if (oprn == MEDIA_FILEOPRN_MODIFYASSET) {
        errCode = HandleModifyAsset(id, srcPath, values, rdbStore, dirQuerySetMap);
    } else if (oprn == MEDIA_FILEOPRN_DELETEASSET) {
        errCode = HandleDeleteAsset(id, srcPath, rdbStore, dirQuerySetMap);
    } else if (oprn == MEDIA_FILEOPRN_CLOSEASSET) {
        errCode = HandleCloseAsset(actualUri, srcPath, values, rdbStore);
    }
    if (oprn == MEDIA_FILEOPRN_CLOSEASSET) {
        CreateThumbnail(rdbStore, mediaThumbnail, id);
    }

    return errCode;
}

ValuesBucket MediaLibraryFileOperations::UpdateBasicAssetDetails(int32_t mediaType,
                                                                 const string &fileName,
                                                                 const string &relPath,
                                                                 const string &path)
{
    ValuesBucket assetInfoBucket;
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, relPath);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_NAME, fileName);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(fileName));
    struct stat statInfo {};
    if (stat(path.c_str(), &statInfo) == 0) {
        assetInfoBucket.PutLong(Media::MEDIA_DATA_DB_SIZE, statInfo.st_size);
        assetInfoBucket.PutLong(Media::MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
    }
    assetInfoBucket.PutInt(Media::MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    assetInfoBucket.PutString(Media::MEDIA_DATA_DB_FILE_PATH, path);
    return assetInfoBucket;
}
} // namespace Media
} // namespace OHOS
