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
#define MLOG_TAG "SmartAlbum"

#include "medialibrary_smartalbum_map_operations.h"

#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "fetch_result.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_object_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
static const std::string HASH_COLLISION_SUFFIX = "(1)";
static const std::string ASSET_RECYCLE_SUFFIX = "-copy";
static const std::string DIR_RECYCLE_SUFFIX = "_recycle";
const std::string RECYCLE_DIR = ".recycle/";
static const int64_t ONEDAY_TO_MS = 60*60*24*1000;
static const int32_t DEFAULT_RECYCLE_DAYS = 30;

int32_t MediaLibrarySmartAlbumMapOperations::InsertAlbumAssetsInfoUtil(
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    ValuesBucket values = const_cast<ValuesBucket &>(smartAlbumMapQueryData.values);
    int32_t insertResult = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapQueryData.smartAlbumMapDbOprn)
        .InsertSmartAlbumMapInfo(values, smartAlbumMapQueryData.rdbStore);
    return insertResult;
}

int32_t MediaLibrarySmartAlbumMapOperations::InsertTrashAssetsInfoUtil(const int32_t &fileAssetId,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(fileAssetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset is nullptr");
        return errorCode;
    }
    if (fileAsset->GetDateTrashed() == 0) {
        if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
            errorCode = TrashFileAssetsInfoUtil(fileAssetId, smartAlbumMapQueryData);
        } else {
            errorCode = TrashDirAssetsInfoUtil(fileAssetId, smartAlbumMapQueryData);
        }
    } else {
        errorCode = E_IS_RECYCLED;
    }
    return errorCode;
}


int32_t MediaLibrarySmartAlbumMapOperations::UpdateFavoriteAssetsInfoUtil(const int32_t &fileAssetId,
    const bool &isFavorite, SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    ValuesBucket fileValues;
    fileValues.PutBool(MEDIA_DATA_DB_IS_FAV, isFavorite);
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateFavoriteInfo(fileAssetId,
        fileValues, smartAlbumMapQueryData.rdbStore);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashFileAssetsInfoUtil(const int32_t &assetId,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string trashDirPath, oldPath, recyclePath;
    int32_t errorCode = GetAssetRecycle(assetId,
        oldPath, trashDirPath, smartAlbumMapQueryData.rdbStore, smartAlbumMapQueryData.dirQuerySetMap);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to GetAssetRecycle");
    if (!MediaFileUtils::IsDirectory(trashDirPath)) {
        if (!MediaFileUtils::CreateDirectory(trashDirPath)) {
            return E_FAIL;
        }
    }
    errorCode = MakeRecycleDisplayName(
        assetId, recyclePath, trashDirPath, smartAlbumMapQueryData.rdbStore);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to make recycle display name");
    FileAsset fileAsset;
    errorCode = fileAsset.ModifyAsset(oldPath, recyclePath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS,
        errorCode, "TrashFileAssetsInfoUtil Failed to ModifyAsset");
    int64_t trashDate = MediaFileUtils::UTCTimeSeconds();
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateAssetTrashInfo(assetId,
        trashDate, smartAlbumMapQueryData.rdbStore, recyclePath, oldPath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to UpdateAssetTrashInfo");
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashDirAssetsInfoUtil(const int32_t &assetId,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string trashDirPath, oldPath, recyclePath;
    int32_t errorCode = GetAssetRecycle(assetId,
        oldPath, trashDirPath, smartAlbumMapQueryData.rdbStore, smartAlbumMapQueryData.dirQuerySetMap);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to GetAssetRecycle");
    if (!MediaFileUtils::IsDirectory(trashDirPath)) {
        if (!MediaFileUtils::CreateDirectory(trashDirPath)) {
            return E_FAIL;
        }
    }
    errorCode = MakeRecycleDisplayName(
        assetId, recyclePath, trashDirPath, smartAlbumMapQueryData.rdbStore);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to MakeRecycleDisplayName");
    if (!MediaFileUtils::RenameDir(oldPath, recyclePath)) {
        return E_MODIFY_DATA_FAIL;
    };
    int64_t trashDate = MediaFileUtils::UTCTimeSeconds();
    errorCode = TrashChildAssetsInfoUtil(assetId, trashDate, smartAlbumMapQueryData);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to TrashChildAssetsInfoUtil");
    (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateDirTrashInfo(assetId,
        trashDate, smartAlbumMapQueryData.rdbStore, recyclePath, oldPath);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashChildAssetsInfoUtil(const int32_t &parentId,
    const int64_t &trashDate, SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    vector<string> columns;
    AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId))->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH,
        to_string(NOT_ISTRASH));
    shared_ptr<AbsSharedResultSet> queryResultSet = smartAlbumMapQueryData.rdbStore->Query(
        dirAbsPred, columns);
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count != 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexId, idVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
            queryResultSet->GetInt(columnIndexId, idVal);
            (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateChildTrashInfo(idVal,
                smartAlbumMapQueryData.rdbStore, trashDate);
            TrashChildAssetsInfoUtil(idVal, trashDate, smartAlbumMapQueryData);
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapOperations::RemoveAlbumAssetsInfoUtil(const int32_t &albumId,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    ValuesBucket values = const_cast<ValuesBucket &>(smartAlbumMapQueryData.values);
    ValueObject valueObject;
    int32_t assetId = 0;
    if (values.GetObject(SMARTALBUMMAP_DB_CHILD_ASSET_ID, valueObject)) {
        valueObject.GetInt(assetId);
    }
    int32_t deleteResult = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapQueryData.smartAlbumMapDbOprn)
        .DeleteSmartAlbumMapInfo(albumId, assetId, smartAlbumMapQueryData.rdbStore);
    return deleteResult;
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleAddAssetOperations(const int32_t &albumId,
                                                                      const int32_t &childFileAssetId,
                                                                      SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    if (albumId == TRASH_ALBUM_ID_VALUES) {
        errorCode = InsertTrashAssetsInfoUtil(childFileAssetId, smartAlbumMapQueryData);
    } else if (albumId == FAVOURITE_ALBUM_ID_VALUES) {
        errorCode = UpdateFavoriteAssetsInfoUtil(childFileAssetId, true, smartAlbumMapQueryData);
    }
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to HandleAddAssetOperations");
    errorCode = InsertAlbumAssetsInfoUtil(smartAlbumMapQueryData);
    return errorCode;
}

string MediaLibrarySmartAlbumMapOperations::MakeSuffixPathName(string &assetPath)
{
    string outSuffixPath;
    size_t displayNameIndex = assetPath.find(".");
    if (displayNameIndex != string::npos) {
        string extension, noExtensionPath;
        extension = assetPath.substr(displayNameIndex);
        noExtensionPath = assetPath.substr(0, displayNameIndex);
        MEDIA_INFO_LOG("extension = %{public}s", extension.c_str());
        MEDIA_INFO_LOG("noExtensionPath = %{public}s", noExtensionPath.c_str());
        outSuffixPath = noExtensionPath + ASSET_RECYCLE_SUFFIX + extension;
    } else {
        outSuffixPath = assetPath + ASSET_RECYCLE_SUFFIX;
    }
    MEDIA_INFO_LOG("outSuffixPath = %{public}s", outSuffixPath.c_str());
    return outSuffixPath;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleFile(const shared_ptr<FileAsset> &fileAsset,
    const string &recyclePath,
    string &sameNamePath,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    NativeAlbumAsset nativeAlbumAsset;
    string assetPath = fileAsset->GetRecyclePath();
    if (!MediaLibraryObjectUtils::IsAssetExistInDb(fileAsset->GetParent())) {
        MEDIA_INFO_LOG("RecycleFile GetRelativePath() = %{private}s", fileAsset->GetRelativePath().c_str());
        int32_t albumId = MediaLibraryObjectUtils::CreateDirWithPath(ROOT_MEDIA_DIR + fileAsset->GetRelativePath());
        nativeAlbumAsset.SetAlbumId(albumId);
        errorCode = fileAsset->ModifyAsset(recyclePath, assetPath);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode,
            "isAlbumExistInDb Failed to ModifyAsset");
        nativeAlbumAsset = GetAlbumAsset(to_string(albumId), smartAlbumMapQueryData.rdbStore);
        errorCode = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapQueryData.smartAlbumMapDbOprn)
            .UpdateParentDirRecycleInfo(fileAsset->GetId(), nativeAlbumAsset.GetAlbumId(),
            nativeAlbumAsset.GetAlbumName(), smartAlbumMapQueryData.rdbStore);
    } else {
        bool hasSameName = false;
        while (MediaLibraryObjectUtils::IsFileExistInDb(assetPath)) {
                hasSameName = true;
                assetPath = MakeSuffixPathName(assetPath);
        }
        errorCode = fileAsset->ModifyAsset(recyclePath, assetPath);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to ModifyAsset");
        if (hasSameName) {
            string assetDisplayName = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(assetPath);
            smartAlbumMapQueryData.smartAlbumMapDbOprn.UpdateSameNameInfo(fileAsset->GetId(),
                assetDisplayName, assetPath, smartAlbumMapQueryData.rdbStore);
            sameNamePath = assetPath;
        }
    }
    MEDIA_INFO_LOG("RecycleFile assetPath = %{private}s", assetPath.c_str());
    MEDIA_INFO_LOG("RecycleFile recyclePath = %{private}s", recyclePath.c_str());
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleChildSameNameInfoUtil(
    const int32_t &parentId, const string &relativePath, SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    vector<string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_RELATIVE_PATH};
    AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId));
    shared_ptr<AbsSharedResultSet> queryResultSet = smartAlbumMapQueryData.rdbStore->Query(
        dirAbsPred, columns);
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count != 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexId, idVal, columnIndexName, columnIndexIsTrash, isTrashVal;
            string nameVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
            queryResultSet->GetInt(columnIndexId, idVal);
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndexName);
            queryResultSet->GetString(columnIndexName, nameVal);
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_IS_TRASH, columnIndexIsTrash);
            queryResultSet->GetInt(columnIndexIsTrash, isTrashVal);
            string newPath = ROOT_MEDIA_DIR + relativePath + nameVal;
            string childRelativePath = relativePath + nameVal + "/";
            smartAlbumMapQueryData.smartAlbumMapDbOprn.UpdateChildPathInfo(idVal,
                newPath, relativePath, isTrashVal, smartAlbumMapQueryData.rdbStore);
            MEDIA_INFO_LOG("newPath = %{private}s", newPath.c_str());
            MEDIA_INFO_LOG("relativePath = %{private}s", relativePath.c_str());
            RecycleChildSameNameInfoUtil(idVal, childRelativePath, smartAlbumMapQueryData);
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleDir(const shared_ptr<FileAsset> &fileAsset,
    const string &recyclePath,
    string &outSameNamePath,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    NativeAlbumAsset nativeAlbumAsset;
    string assetPath = fileAsset->GetRecyclePath();
    MEDIA_INFO_LOG("RecycleDir assetPath = %{private}s", assetPath.c_str());
    if (!MediaLibraryObjectUtils::IsAssetExistInDb(fileAsset->GetParent())) {
        MEDIA_INFO_LOG("RecycleDir GetRelativePath() = %{private}s", fileAsset->GetRelativePath().c_str());
        int32_t albumId = MediaLibraryObjectUtils::CreateDirWithPath(ROOT_MEDIA_DIR + fileAsset->GetRelativePath());
        nativeAlbumAsset.SetAlbumId(albumId);

        if (MediaFileUtils::RenameDir(recyclePath, assetPath)) {
            nativeAlbumAsset = GetAlbumAsset(to_string(albumId), smartAlbumMapQueryData.rdbStore);
            string dirBucketDisplayName;
            errorCode = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapQueryData.smartAlbumMapDbOprn)
                .UpdateParentDirRecycleInfo(fileAsset->GetId(),
                nativeAlbumAsset.GetAlbumId(), dirBucketDisplayName, smartAlbumMapQueryData.rdbStore);
        } else {
            return E_RDIR_FAIL;
        }
    } else {
        int32_t albumId;
        bool hasSameName = false;
        while (IsAlbumExistInDb(assetPath, smartAlbumMapQueryData.rdbStore, albumId)) {
            hasSameName = true;
            assetPath = assetPath + DIR_RECYCLE_SUFFIX;
        }
        if (MediaFileUtils::RenameDir(recyclePath, assetPath)) {
            if (hasSameName) {
                string assetDisplayName, childRelativePath;
                assetDisplayName = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(assetPath);
                string assetRelativePath = fileAsset->GetRelativePath();
                childRelativePath = assetRelativePath + assetDisplayName + "/";
                RecycleChildSameNameInfoUtil(fileAsset->GetId(), childRelativePath, smartAlbumMapQueryData);
                errorCode = smartAlbumMapQueryData.smartAlbumMapDbOprn.UpdateSameNameInfo(fileAsset->GetId(),
                    assetDisplayName, assetPath, smartAlbumMapQueryData.rdbStore);
                outSameNamePath = assetPath;
            } else {
                errorCode = E_SUCCESS;
            }
        } else {
            return E_RDIR_FAIL;
        }
    }
    MEDIA_INFO_LOG("RecycleDir assetPath = %{private}s", assetPath.c_str());
    MEDIA_INFO_LOG("RecycleDir recyclePath = %{private}s", recyclePath.c_str());
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleFileAssetsInfoUtil(const shared_ptr<FileAsset> &fileAsset,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string recyclePath;
    int32_t errorCode = E_FAIL;
    if (!IsRecycleAssetExist(fileAsset->GetId(),
        recyclePath, smartAlbumMapQueryData.rdbStore)) {
        return E_RECYCLE_FILE_IS_NULL;
    }
    MEDIA_INFO_LOG("recyclePath = %{private}s", recyclePath.c_str());
    string sameNamePath;
    errorCode = RecycleFile(fileAsset, recyclePath, sameNamePath, smartAlbumMapQueryData);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to RecycleFile");
    string fileRealPath;
    if (sameNamePath.empty()) {
        fileRealPath = fileAsset->GetRecyclePath();
    } else {
        fileRealPath = sameNamePath;
    }
    int64_t date = MediaFileUtils::UTCTimeSeconds();
    string fileRecyclePath;
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateRecycleInfo(fileAsset->GetId(),
        date, smartAlbumMapQueryData.rdbStore, fileRecyclePath, fileRealPath);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleChildAssetsInfoUtil(const int32_t &parentId,
    const int64_t &recycleDate, SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    vector<string> columns;
    AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId));
    dirAbsPred.EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(CHILD_ISTRASH));
    shared_ptr<AbsSharedResultSet> queryResultSet = smartAlbumMapQueryData.rdbStore->Query(
        dirAbsPred, columns);
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count != 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexId, idVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
            queryResultSet->GetInt(columnIndexId, idVal);
            (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateChildRecycleInfo(idVal,
                smartAlbumMapQueryData.rdbStore, recycleDate);
            RecycleChildAssetsInfoUtil(idVal, recycleDate, smartAlbumMapQueryData);
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleDirAssetsInfoUtil(const shared_ptr<FileAsset> &fileAsset,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string recyclePath;
    int32_t errorCode = E_FAIL;
    if (!IsRecycleAssetExist(fileAsset->GetId(),
        recyclePath, smartAlbumMapQueryData.rdbStore)) {
        return E_RECYCLE_FILE_IS_NULL;
    }
    MEDIA_INFO_LOG("recyclePath = %{private}s", recyclePath.c_str());
    string sameNamePath;
    errorCode = RecycleDir(fileAsset, recyclePath, sameNamePath, smartAlbumMapQueryData);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to RecycleDir");
    int64_t recycleDate = MediaFileUtils::UTCTimeSeconds();
    errorCode = RecycleChildAssetsInfoUtil(fileAsset->GetId(), recycleDate, smartAlbumMapQueryData);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to RecycleChildAssetsInfoUtil");
    string dirRealPath;
    if (sameNamePath.empty()) {
        dirRealPath = fileAsset->GetRecyclePath();
    } else {
        dirRealPath = sameNamePath;
    }
    int64_t date = MediaFileUtils::UTCTimeSeconds();
    string dirRecyclePath;
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).UpdateRecycleInfo(fileAsset->GetId(),
        date, smartAlbumMapQueryData.rdbStore, dirRecyclePath, dirRealPath);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RemoveTrashAssetsInfoUtil(const int32_t &fileAssetId,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    int32_t errorCode = E_FAIL;
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(fileAssetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset is nullptr");
        return errorCode;
    }
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        errorCode = RecycleFileAssetsInfoUtil(fileAsset, smartAlbumMapQueryData);
    } else {
        errorCode = RecycleDirAssetsInfoUtil(fileAsset, smartAlbumMapQueryData);
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleRemoveAssetOperations(const int32_t &albumId,
                                                                         const int32_t &childFileAssetId,
                                                                         SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    if (albumId == TRASH_ALBUM_ID_VALUES) {
        RemoveTrashAssetsInfoUtil(childFileAssetId, smartAlbumMapQueryData);
    } else if (albumId == FAVOURITE_ALBUM_ID_VALUES) {
        UpdateFavoriteAssetsInfoUtil(childFileAssetId, false, smartAlbumMapQueryData);
    }
    return RemoveAlbumAssetsInfoUtil(albumId, smartAlbumMapQueryData);
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteDir(const string &recyclePath)
{
    int32_t errorCode = E_FAIL;
    if (MediaFileUtils::DeleteDir(recyclePath)) {
        errorCode = E_SUCCESS;
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteFile(const unique_ptr<FileAsset> &fileAsset,
    const string &recyclePath)
{
    int32_t errorCode = fileAsset->DeleteAsset(recyclePath);
    MEDIA_INFO_LOG("DeleteFile errorCode = %{public}d", errorCode);
    if (errorCode >= 0) {
        errorCode = E_SUCCESS;
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteFileAssetsInfoUtil(const unique_ptr<FileAsset> &fileAsset,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string recyclePath;
    int32_t errorCode = E_FAIL;
    if (!IsRecycleAssetExist(fileAsset->GetId(),
        recyclePath, smartAlbumMapQueryData.rdbStore)) {
        return E_RECYCLE_FILE_IS_NULL;
    }
    MEDIA_INFO_LOG("DeleteFileAssetsInfoUtil recyclePath = %{private}s", recyclePath.c_str());
    errorCode = DeleteFile(fileAsset, recyclePath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to DeleteFile");
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).DeleteTrashInfo(fileAsset->GetId(),
        smartAlbumMapQueryData.rdbStore);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteDirAssetsInfoUtil(const unique_ptr<FileAsset> &fileAsset,
    SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    string recyclePath;
    int32_t errorCode = E_FAIL;
    if (fileAsset->GetIsTrash() == DIR_ISTRASH) {
        if (!IsRecycleAssetExist(fileAsset->GetId(),
            recyclePath, smartAlbumMapQueryData.rdbStore)) {
            return E_RECYCLE_FILE_IS_NULL;
        }
        MEDIA_INFO_LOG("DeleteDirAssetsInfoUtil recyclePath = %{private}s", recyclePath.c_str());
        errorCode = DeleteDir(recyclePath);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to DeleteDir");
    }
    errorCode = (smartAlbumMapQueryData.smartAlbumMapDbOprn).DeleteTrashInfo(fileAsset->GetId(),
        smartAlbumMapQueryData.rdbStore);
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleAgeingOperations(SmartAlbumMapQueryData &smartAlbumMapQueryData)
{
    shared_ptr<AbsSharedResultSet> resultSet = QueryAgeingTrashFiles(smartAlbumMapQueryData.rdbStore);
    shared_ptr<ResultSetBridge> rsBridge = RdbUtils::ToResultSetBridge(resultSet);
    shared_ptr<DataShareResultSet> dataShareRs = make_shared<DataShareResultSet>(rsBridge);
    shared_ptr<FetchResult> fetchFileResult = make_shared<FetchResult>(dataShareRs);
    int32_t errorCode = E_FAIL;
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        MEDIA_INFO_LOG("fileAsset->GetIsTrash() = %{public}d", fileAsset->GetIsTrash());
        if (fileAsset->GetIsTrash() == ASSET_ISTRASH) {
            errorCode = DeleteFileAssetsInfoUtil(fileAsset, smartAlbumMapQueryData);
        } else {
            errorCode = DeleteDirAssetsInfoUtil(fileAsset, smartAlbumMapQueryData);
        }
        fileAsset = fetchFileResult->GetNextObject();
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperations(const string &oprn,
    const ValuesBucket &valuesBucket,
    const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    SmartAlbumMapQueryData smartAlbumMapQueryData;
    smartAlbumMapQueryData.smartAlbumMapDbOprn = smartAlbumMapDbOprn;
    smartAlbumMapQueryData.values = valuesBucket;
    smartAlbumMapQueryData.rdbStore = rdbStore;
    smartAlbumMapQueryData.dirQuerySetMap = dirQuerySetMap;
    int32_t albumId = 0;
    int32_t childAssetId = 0;
    ValueObject valueObject;
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    if (values.GetObject(SMARTALBUMMAP_DB_ALBUM_ID, valueObject)) {
        valueObject.GetInt(albumId);
    }
    if (values.GetObject(SMARTALBUMMAP_DB_CHILD_ASSET_ID, valueObject)) {
        valueObject.GetInt(childAssetId);
    }
    int32_t errorCode = E_FAIL;
    if (oprn == MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM) {
        errorCode = HandleAddAssetOperations(albumId, childAssetId, smartAlbumMapQueryData);
    } else if (oprn == MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM) {
        errorCode = HandleRemoveAssetOperations(albumId, childAssetId, smartAlbumMapQueryData);
    } else if (oprn == MEDIA_SMARTALBUMMAPOPRN_AGEINGSMARTALBUM) {
        errorCode = HandleAgeingOperations(smartAlbumMapQueryData);
    }
    return errorCode;
}

NativeAlbumAsset MediaLibrarySmartAlbumMapOperations::GetAlbumAsset(const std::string &id,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    NativeAlbumAsset albumAsset;
    vector<string> columns;
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, id);
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet->GoToNextRow() != NativeRdb::E_OK) {
        return albumAsset;
    }

    int32_t columnIndexId;
    int32_t idVal;
    int32_t columnIndexName;
    string nameVal;
    queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
    queryResultSet->GetInt(columnIndexId, idVal);
    queryResultSet->GetColumnIndex(MEDIA_DATA_DB_TITLE, columnIndexName);
    queryResultSet->GetString(columnIndexName, nameVal);
    albumAsset.SetAlbumId(idVal);
    albumAsset.SetAlbumName(nameVal);
    MEDIA_DEBUG_LOG("idVal = %{private}d, nameVal = %{private}s", idVal, nameVal.c_str());
    return albumAsset;
}

bool MediaLibrarySmartAlbumMapOperations::IsAlbumExistInDb(const std::string &path,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t &outRow)
{
    string realPath = path;
    if (realPath.back() == '/') {
        realPath.pop_back();
    }
    MEDIA_DEBUG_LOG("isAlbumExistInDb path = %{private}s", realPath.c_str());
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, realPath);
    absPredicates.And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");
    vector<string> columns;
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet == nullptr || queryResultSet->GoToNextRow() != NativeRdb::E_OK) {
        outRow = 0;
        return false;
    }
    int32_t columnIndexId;
    int32_t idVal;
    queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
    queryResultSet->GetInt(columnIndexId, idVal);
    MEDIA_DEBUG_LOG("id = %{private}d", idVal);
    outRow = idVal;
    return true;
}

int32_t MediaLibrarySmartAlbumMapOperations::GetAssetRecycle(const int32_t &assetId,
    string &outOldPath, string &outTrashDirPath, const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string path = MediaLibraryObjectUtils::GetPathByIdFromDb(to_string(assetId));
    outOldPath = path;
    int32_t errorCode = E_FAIL;
    string rootPath;
    for (pair<string, DirAsset> dirPair : dirQuerySetMap) {
        DirAsset dirAsset = dirPair.second;
        rootPath = ROOT_MEDIA_DIR + dirAsset.GetDirectory();
        if (path.find(rootPath) != string::npos) {
            MEDIA_DEBUG_LOG("GetAssetRecycle = %{public}s", rootPath.c_str());
            errorCode = E_SUCCESS;
            break;
        }
    }
    outTrashDirPath = rootPath + RECYCLE_DIR;
    return errorCode;
}

bool MediaLibrarySmartAlbumMapOperations::IsRecycleAssetExist(const int32_t &assetId,
    string &outRecyclePath, const shared_ptr<RdbStore> &rdbStore)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset is nullptr");
        return false;
    }
    outRecyclePath = fileAsset->GetPath();
    MEDIA_DEBUG_LOG("assetRescyclePath = %{private}s", outRecyclePath.c_str());
    if (fileAsset->GetMediaType() == MEDIA_TYPE_ALBUM) {
        return MediaFileUtils::IsDirectory(outRecyclePath);
    }
    return MediaFileUtils::IsFileExists(outRecyclePath);
}

int32_t MediaLibrarySmartAlbumMapOperations::MakeRecycleDisplayName(const int32_t &assetId,
    string &outRecyclePath, const string &trashDirPath, const shared_ptr<RdbStore> &rdbStore)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset not found");
        return E_FAIL;
    }
    string extension = "";
    string hashDisplayName = "";
    string name = to_string(fileAsset->GetId()) +
        fileAsset->GetRelativePath() + fileAsset->GetDisplayName();
    int32_t errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
    if (errorCode < 0) {
        MEDIA_ERR_LOG("Failed to make hash display name, err: %{public}d", errorCode);
        return errorCode;
    }
    MEDIA_DEBUG_LOG("hashDisplayName = %{public}s", hashDisplayName.c_str());
    outRecyclePath = trashDirPath + hashDisplayName;
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        size_t displayNameIndex = fileAsset->GetDisplayName().find(".");
        if (displayNameIndex != string::npos) {
            extension = fileAsset->GetDisplayName().substr(displayNameIndex);
        }
        outRecyclePath = outRecyclePath + extension;
        MEDIA_DEBUG_LOG("asset outRecyclePath = %{public}s", outRecyclePath.c_str());
    }
    while (MediaLibraryObjectUtils::IsColumnValueExist(outRecyclePath, MEDIA_DATA_DB_RECYCLE_PATH)) {
        name = name + HASH_COLLISION_SUFFIX;
        MEDIA_DEBUG_LOG("name = %{public}s", name.c_str());
        errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
        if (errorCode < 0) {
            MEDIA_ERR_LOG("Failed to make hash display name, err: %{public}d", errorCode);
            return errorCode;
        }
        if (!extension.empty()) {
            outRecyclePath = trashDirPath + hashDisplayName + extension;
        }
        outRecyclePath =  trashDirPath + hashDisplayName;
        MEDIA_DEBUG_LOG("outRecyclePath = %{public}s", outRecyclePath.c_str());
    }
    return errorCode;
}

shared_ptr<AbsSharedResultSet> MediaLibrarySmartAlbumMapOperations::QueryAgeingTrashFiles(
    const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> selectionArgs = {SMARTALBUM_DB_EXPIRED_TIME};
    string strQueryCondition = SMARTALBUM_DB_ID + " = " + to_string(TRASH_ALBUM_ID_VALUES);
    AbsRdbPredicates absPredicates(SMARTALBUM_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    int32_t columnIndex;
    int32_t recycleDays = DEFAULT_RECYCLE_DAYS;
    shared_ptr<AbsSharedResultSet> resultSet = rdbStore->Query(absPredicates, columns);
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        resultSet->GetColumnIndex(SMARTALBUM_DB_EXPIRED_TIME, columnIndex);
        resultSet->GetInt(columnIndex, recycleDays);
    }
    int64_t dateAgeing = MediaFileUtils::UTCTimeSeconds();
    string strAgeingQueryCondition = to_string(dateAgeing) + " - " +
        MEDIA_DATA_DB_DATE_TRASHED + " > " + to_string(recycleDays * ONEDAY_TO_MS);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(strAgeingQueryCondition);
    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}
} // namespace Media
} // namespace OHOS
