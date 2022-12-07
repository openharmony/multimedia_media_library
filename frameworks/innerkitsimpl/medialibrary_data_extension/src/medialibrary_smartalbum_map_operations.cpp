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
#include "medialibrary_smartalbum_operations.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "rdb_utils.h"
#include "result_set_utils.h"

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
constexpr int64_t ONEDAY_TO_SEC = 60 * 60 * 24;
constexpr int32_t DEFAULT_RECYCLE_DAYS = 30;
constexpr int32_t HASH_COLLISION_MAX_TRY = 10;
std::atomic<bool> MediaLibrarySmartAlbumMapOperations::isInterrupt_ = false;
string MediaLibrarySmartAlbumMapOperations::MakeSuffixPathName(string &assetPath)
{
    string outSuffixPath;
    size_t extensionIndex = assetPath.rfind(".");
    if (extensionIndex != string::npos) {
        string extension = assetPath.substr(extensionIndex);
        string noExtensionPath = assetPath.substr(0, extensionIndex);
        outSuffixPath = noExtensionPath + ASSET_RECYCLE_SUFFIX + extension;
    } else {
        outSuffixPath = assetPath + ASSET_RECYCLE_SUFFIX;
    }
    MEDIA_DEBUG_LOG("outSuffixPath = %{public}s", outSuffixPath.c_str());
    return outSuffixPath;
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteFileAssetsInfoUtil(const unique_ptr<FileAsset> &fileAsset)
{
    string recyclePath;
    if (!GetRecyclePath(fileAsset->GetId(), recyclePath)) {
        MEDIA_ERR_LOG("RecycleFile is null, fileId = %{private}d", fileAsset->GetId());
        return E_RECYCLE_FILE_IS_NULL;
    }
    ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, fileAsset->GetId());
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE, values);
    return MediaLibraryObjectUtils::DeleteFileObj(cmd, recyclePath);
}

int32_t MediaLibrarySmartAlbumMapOperations::DeleteDirAssetsInfoUtil(const unique_ptr<FileAsset> &fileAsset)
{
    string recyclePath;
    int32_t errorCode;
    if (fileAsset->GetIsTrash() == TRASHED_DIR) {
        if (!GetRecyclePath(fileAsset->GetId(), recyclePath)) {
            MEDIA_ERR_LOG("RecycleFile is null, fileId = %{private}d", fileAsset->GetId());
            return E_RECYCLE_FILE_IS_NULL;
        }
        MEDIA_INFO_LOG("DeleteDirAssetsInfoUtil recyclePath = %{private}s", recyclePath.c_str());
        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
        errorCode = MediaLibraryObjectUtils::DeleteFileObj(cmd, recyclePath);
    } else {
        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
        errorCode = MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd, to_string(fileAsset->GetId()));
    }
    return errorCode;
}

shared_ptr<AbsSharedResultSet> MediaLibrarySmartAlbumMapOperations::QueryAgeingTrashFiles()
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return nullptr;
    }
    MediaLibraryCommand querySmartAlbumCmd(OperationObject::SMART_ALBUM, OperationType::QUERY);
    querySmartAlbumCmd.GetAbsRdbPredicates()->EqualTo(SMARTALBUM_DB_ID, to_string(TRASH_ALBUM_ID_VALUES));
    vector<string> columns = { SMARTALBUM_DB_EXPIRED_TIME };
    int32_t recycleDays = DEFAULT_RECYCLE_DAYS;
    auto resultSet = uniStore->Query(querySmartAlbumCmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query rdb");
        return nullptr;
    }
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        recycleDays = get<int32_t>(ResultSetUtils::GetValFromColumn(SMARTALBUM_DB_EXPIRED_TIME, resultSet, TYPE_INT32));
    } else {
        MEDIA_ERR_LOG("Failed to query rdb");
        return nullptr;
    }
    int64_t dateAgeing = MediaFileUtils::UTCTimeSeconds();
    string strAgeingQueryCondition = MEDIA_DATA_DB_DATE_TRASHED + "> 0" + " AND " + to_string(dateAgeing) + " - " +
        MEDIA_DATA_DB_DATE_TRASHED + " > " + to_string(recycleDays * ONEDAY_TO_SEC);
    MEDIA_INFO_LOG("StrAgeingQueryCondition = %{public}s", strAgeingQueryCondition.c_str());
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(strAgeingQueryCondition);
    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleAgingOperation()
{
    shared_ptr<AbsSharedResultSet> resultSet = QueryAgeingTrashFiles();
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query ageing trash files");
        return E_HAS_DB_ERROR;
    }
    int32_t count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    if (count == 0) {
        MEDIA_ERR_LOG("Have no ageing trash file");
        return E_SUCCESS;
    }
    int32_t errorCode = E_ERR;
    auto fetchFileResult = make_shared<FetchResult<FileAsset>>();
    for (int32_t row = 0; row < count; row++) {
        if (MediaLibrarySmartAlbumMapOperations::GetInterrupt()) {
            break;
        }
        unique_ptr<FileAsset> fileAsset = fetchFileResult->GetObjectFromRdb(resultSet, row);
        if (fileAsset == nullptr) {
            errorCode = E_HAS_DB_ERROR;
            break;
        }
        if (fileAsset->GetIsTrash() == TRASHED_ASSET) {
            errorCode = DeleteFileAssetsInfoUtil(fileAsset);
        } else {
            errorCode = DeleteDirAssetsInfoUtil(fileAsset);
        }
        if (errorCode < 0) {
            MEDIA_ERR_LOG("Failed to delete during trash aging, error: %{public}d just continue here", errorCode);
        }
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::GetAssetRecycle(const int32_t assetId,
    string &outOldPath, string &outTrashDirPath,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    outOldPath = MediaLibraryObjectUtils::GetPathByIdFromDb(to_string(assetId));
    int32_t errorCode = E_ERR;
    string rootPath;
    for (pair<string, DirAsset> dirPair : dirQuerySetMap) {
        DirAsset dirAsset = dirPair.second;
        rootPath = ROOT_MEDIA_DIR + dirAsset.GetDirectory();
        if (outOldPath.find(rootPath) != string::npos) {
            errorCode = E_SUCCESS;
            break;
        }
    }
    outTrashDirPath = rootPath + RECYCLE_DIR;
    return errorCode;
}

bool MediaLibrarySmartAlbumMapOperations::GetRecyclePath(const int32_t assetId, string &outRecyclePath)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to get asset, return false to indicate an error here");
        return false;
    }
    outRecyclePath = fileAsset->GetPath();
    if (fileAsset->GetMediaType() == MEDIA_TYPE_ALBUM) {
        MEDIA_INFO_LOG("AssetRescyclePath = %{private}s", outRecyclePath.c_str());
        return MediaFileUtils::IsDirectory(outRecyclePath);
    } else {
        MEDIA_INFO_LOG("AssetRescyclePath = %{private}s", outRecyclePath.c_str());
        return MediaFileUtils::IsFileExists(outRecyclePath);
    }
}

int32_t MediaLibrarySmartAlbumMapOperations::MakeRecycleDisplayName(const int32_t assetId,
    const string &trashDirPath, string &outRecyclePath)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to get asset, assetId = %{public}d", assetId);
        return E_GET_ASSET_FAIL;
    }
    string hashDisplayName;
    string name = to_string(fileAsset->GetId()) + fileAsset->GetRelativePath() + fileAsset->GetDisplayName();
    int32_t errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to genKey, err: %{public}d", errorCode);
        return E_MAKE_HASHNAME_FAIL;
    }
    string extension;
    outRecyclePath = trashDirPath + hashDisplayName;
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        size_t extensionIndex = fileAsset->GetDisplayName().rfind(".");
        if (extensionIndex == string::npos) {
            MEDIA_ERR_LOG("Can not get extension");
            return E_GET_EXTENSION_FAIL;
        }
        extension = fileAsset->GetDisplayName().substr(extensionIndex);
        outRecyclePath += extension;
        MEDIA_INFO_LOG("Asset outRecyclePath = %{private}s", outRecyclePath.c_str());
    }
    int32_t suffixTime = 0;
    while (MediaLibraryObjectUtils::IsColumnValueExist(outRecyclePath, MEDIA_DATA_DB_RECYCLE_PATH)) {
        if (suffixTime > HASH_COLLISION_MAX_TRY) {
            MEDIA_ERR_LOG("Reach max hash collision times");
            errorCode = E_MAKE_HASHNAME_FAIL;
            break;
        }
        name += HASH_COLLISION_SUFFIX;
        errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
        if (errorCode != E_OK) {
            MEDIA_ERR_LOG("Failed to genKey, err: %{public}d", errorCode);
            return E_MAKE_HASHNAME_FAIL;
        }
        outRecyclePath = trashDirPath + hashDisplayName;
        if (!extension.empty()) {
            outRecyclePath += extension;
        }
        suffixTime++;
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::GetAlbumAsset(const std::string &id, NativeAlbumAsset &albumAsset)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, id);
    auto queryResultSet  = MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query rdb!");
        return E_HAS_DB_ERROR;
    }
    if (queryResultSet->GoToNextRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to go to next row!");
        return E_HAS_DB_ERROR;
    }
    albumAsset.SetAlbumId(get<int32_t>(
        ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, queryResultSet, TYPE_INT32)));
    albumAsset.SetAlbumName(get<string>(
        ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_TITLE, queryResultSet, TYPE_STRING)));
    return E_OK;
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateChildRecycleInfoInDb(const int32_t assetId,
    const int64_t recycleDate)
{
    ValuesBucket values;
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, recycleDate);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, 0);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleChildAssetsInfoUtil(const int32_t parentId,
    const int64_t recycleDate)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand querySmartAlbumCmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    querySmartAlbumCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId))->And()->
        EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(TRASHED_DIR_CHILD));
    vector<string> columns;
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore->Query(querySmartAlbumCmd, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("QueryResultSet is nullptr");
        return E_HAS_DB_ERROR;
    }
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    int32_t errCode = E_SUCCESS;
    if (count == 0) {
        return errCode;
    }
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t idVal = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, queryResultSet, TYPE_INT32));
        errCode = UpdateChildRecycleInfoInDb(idVal, recycleDate);
        CHECK_AND_RETURN_RET_LOG(errCode > 0, errCode, "Failed to UpdateChildRecycleInfoInDb");
        errCode = RecycleChildAssetsInfoUtil(idVal, recycleDate);
        CHECK_AND_RETURN_RET_LOG(errCode >= 0, errCode, "Failed to RecycleChildAssetsInfoUtil");
    }
    return errCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateChildPathInfoInDb(const int32_t assetId,
    const string &path, const string &relativePath, const int32_t isTrash)
{
    ValuesBucket values;
    if (isTrash == TRASHED_DIR_CHILD) {
        values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    } else {
        values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, path);
    }
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleChildSameNameInfoUtil(const int32_t parentId,
    const string &relativePath)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand querySmartAlbumCmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    querySmartAlbumCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId));
    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME,
        MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_IS_TRASH };
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore->Query(querySmartAlbumCmd, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("QueryResultSet is nullptr");
        return E_HAS_DB_ERROR;
    }
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    int32_t errCode = E_SUCCESS;
    if (count == 0) {
        return E_SUCCESS;
    }

    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t idVal = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, queryResultSet, TYPE_INT32));
        int32_t isTrashVal = get<int32_t>(
            ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_IS_TRASH, queryResultSet, TYPE_INT32));
        string nameVal = get<string>(
            ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, queryResultSet, TYPE_STRING));
        string newPath = ROOT_MEDIA_DIR + relativePath + nameVal;
        string childRelativePath = relativePath + nameVal + "/";
        errCode = UpdateChildPathInfoInDb(idVal, newPath, relativePath, isTrashVal);
        CHECK_AND_RETURN_RET_LOG(errCode > 0, errCode, "Failed to updateChildPathInfoInDb");
        errCode = RecycleChildSameNameInfoUtil(idVal, childRelativePath);
        CHECK_AND_RETURN_RET_LOG(errCode >= 0, errCode, "Failed to recycleChildSameNameInfoUtil");
    }
    return errCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleDir(const shared_ptr<FileAsset> &fileAsset,
    const string &recyclePath, string &outSameNamePath)
{
    int32_t errorCode = E_ERR;
    NativeAlbumAsset nativeAlbumAsset;
    string assetPath = fileAsset->GetRecyclePath();
    MEDIA_INFO_LOG("RecycleDir assetPath = %{private}s", assetPath.c_str());
    if (!MediaLibraryObjectUtils::IsAssetExistInDb(fileAsset->GetParent())) {
        MEDIA_INFO_LOG("RecycleDir getRelativePath() = %{private}s", fileAsset->GetRelativePath().c_str());
        nativeAlbumAsset = MediaLibraryObjectUtils::GetDirAsset((ROOT_MEDIA_DIR + fileAsset->GetRelativePath()));
        if (!MediaFileUtils::RenameDir(recyclePath, assetPath)) {
            return E_RECYCLE_DIR_FAIL;
        }
        errorCode = UpdateParentDirRecycleInfoInDb(fileAsset->GetId(), nativeAlbumAsset.GetAlbumId(),
            nativeAlbumAsset.GetAlbumName());
    } else {
        bool hasSameName = false;
        while (MediaLibraryObjectUtils::IsFileExistInDb(assetPath)) {
            hasSameName = true;
            assetPath = assetPath + DIR_RECYCLE_SUFFIX;
        }
        if (!MediaFileUtils::RenameDir(recyclePath, assetPath)) {
            return E_RECYCLE_DIR_FAIL;
        }
        if (!hasSameName) {
            return E_SUCCESS;
        }
        string assetDisplayName, childRelativePath;
        assetDisplayName = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(assetPath);
        string assetRelativePath = fileAsset->GetRelativePath();
        childRelativePath = assetRelativePath + assetDisplayName + "/";
        errorCode = RecycleChildSameNameInfoUtil(fileAsset->GetId(), childRelativePath);
        CHECK_AND_RETURN_RET_LOG(errorCode >= 0,
            errorCode, "Failed to recycleChildSameNameInfoUtil");
        errorCode = UpdateSameNameInfoInDb(fileAsset->GetId(), assetDisplayName, assetPath);
        outSameNamePath = assetPath;
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleDirAssetsInfoUtil(const shared_ptr<FileAsset> &fileAsset)
{
    string recyclePath;
    int32_t errorCode = E_ERR;
    if (!GetRecyclePath(fileAsset->GetId(), recyclePath)) {
        MEDIA_ERR_LOG("RecycleFile is null, fileid = %{private}d", fileAsset->GetId());
        return E_RECYCLE_FILE_IS_NULL;
    }
    MEDIA_INFO_LOG("RecyclePath = %{private}s", recyclePath.c_str());
    string sameNamePath;
    errorCode = RecycleDir(fileAsset, recyclePath, sameNamePath);
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, errorCode, "Failed to recycleDir");
    int64_t recycleDate = MediaFileUtils::UTCTimeSeconds();
    errorCode = RecycleChildAssetsInfoUtil(fileAsset->GetId(), recycleDate);
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, errorCode, "Failed to recycleChildAssetsInfoUtil");
    string dirRealPath;
    if (sameNamePath.empty()) {
        dirRealPath = fileAsset->GetRecyclePath();
    } else {
        dirRealPath = sameNamePath;
    }
    int64_t date = MediaFileUtils::UTCTimeSeconds();
    string dirRecyclePath;
    return UpdateRecycleInfoInDb(fileAsset->GetId(), date, dirRecyclePath, dirRealPath);
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateRecycleInfoInDb(const int32_t assetId,
    const int64_t recycleDate, const string &recyclePath, const string &realPath)
{
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, realPath);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, recyclePath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, recycleDate);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, 0);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateParentDirRecycleInfoInDb(const int32_t assetId,
    const int32_t parentId, const string &parentName)
{
    if (parentId < 0) {
        MEDIA_ERR_LOG("ParentId is invalid");
        return E_INVALID_VALUES;
    }
    ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentId);
    if (!parentName.empty()) {
        values.PutInt(MEDIA_DATA_DB_BUCKET_ID, parentId);
        values.PutString(MEDIA_DATA_DB_BUCKET_NAME, parentName);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateSameNameInfoInDb(const int32_t assetId,
    const string &displayName, const string &path)
{
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, displayName);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, path);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleFile(const shared_ptr<FileAsset> &fileAsset,
    const string &recyclePath, string &sameNamePath)
{
    int32_t errorCode;
    string assetPath = fileAsset->GetRecyclePath();
    if (!MediaLibraryObjectUtils::IsAssetExistInDb(fileAsset->GetParent())) {
        MEDIA_INFO_LOG("RecycleFile getRelativePath() = %{private}s", fileAsset->GetRelativePath().c_str());
        int32_t albumId = MediaLibraryObjectUtils::CreateDirWithPath(ROOT_MEDIA_DIR + fileAsset->GetRelativePath());
        NativeAlbumAsset nativeAlbumAsset;
        nativeAlbumAsset.SetAlbumId(albumId);
        errorCode = fileAsset->ModifyAsset(recyclePath, assetPath);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "IsAlbumExistInDb failed to modifyAsset");
        errorCode = GetAlbumAsset(to_string(albumId), nativeAlbumAsset);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_OK, errorCode, "Failed to get album asset");
        errorCode = UpdateParentDirRecycleInfoInDb(fileAsset->GetId(), nativeAlbumAsset.GetAlbumId(),
            nativeAlbumAsset.GetAlbumName());
    } else {
        bool hasSameName = false;
        while (MediaLibraryObjectUtils::IsFileExistInDb(assetPath)) {
            hasSameName = true;
            assetPath = MakeSuffixPathName(assetPath);
        }
        errorCode = fileAsset->ModifyAsset(recyclePath, assetPath);
        CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to modifyAsset");
        if (hasSameName) {
            string assetDisplayName = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(assetPath);
            errorCode = UpdateSameNameInfoInDb(fileAsset->GetId(), assetDisplayName, assetPath);
            sameNamePath = assetPath;
        }
    }
    return errorCode;
}

int32_t MediaLibrarySmartAlbumMapOperations::RecycleFileAssetsInfoUtil(const shared_ptr<FileAsset> &fileAsset)
{
    string recyclePath;
    if (!GetRecyclePath(fileAsset->GetId(), recyclePath)) {
        MEDIA_ERR_LOG("RecycleFile is null, fileid = %{private}d", fileAsset->GetId());
        return E_RECYCLE_FILE_IS_NULL;
    }
    MEDIA_INFO_LOG("RecyclePath = %{private}s", recyclePath.c_str());
    string sameNamePath;
    int32_t errorCode = RecycleFile(fileAsset, recyclePath, sameNamePath);
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, errorCode, "Failed to recycleFile");
    string fileRealPath = sameNamePath.empty() ? fileAsset->GetRecyclePath() : sameNamePath;
    string fileRecyclePath;
    int64_t date = MediaFileUtils::UTCTimeSeconds();
    return UpdateRecycleInfoInDb(fileAsset->GetId(), date, fileRecyclePath, fileRealPath);
}

int32_t MediaLibrarySmartAlbumMapOperations::RemoveTrashAssetsInfoUtil(const int32_t fileAssetId)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(fileAssetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset is nullptr, assetId: %{public}d", fileAssetId);
        return E_GET_ASSET_FAIL;
    }
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        return RecycleFileAssetsInfoUtil(fileAsset);
    } else {
        return RecycleDirAssetsInfoUtil(fileAsset);
    }
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleRemoveAssetOperation(const int32_t albumId,
    const int32_t childFileAssetId, MediaLibraryCommand &cmd)
{
    int32_t errorCode = E_SUCCESS;
    if (albumId == TRASH_ALBUM_ID_VALUES) {
        errorCode = RemoveTrashAssetsInfoUtil(childFileAssetId);
    } else if (albumId == FAVOURITE_ALBUM_ID_VALUES) {
        errorCode = UpdateFavoriteAssetsInfoUtil(childFileAssetId, false);
    }
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, errorCode, "Failed to handleRemoveAssetOperations");
    cmd.GetAbsRdbPredicates()->EqualTo(SMARTALBUMMAP_DB_ALBUM_ID, to_string(albumId))->And()->
        EqualTo(SMARTALBUMMAP_DB_CHILD_ASSET_ID, to_string(childFileAssetId));
    return MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd);
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateDirTrashInfoInDb(const int32_t assetId, const int64_t trashDate,
    string &recyclePath, const string &oldPath)
{
    return UpdateTrashInfoInDb(assetId, trashDate, recyclePath, oldPath, TRASHED_DIR);
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateChildTrashInfoInDb(const int32_t assetId, const int64_t trashDate)
{
    ValuesBucket values;
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, trashDate);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, trashDate);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, TRASHED_DIR_CHILD);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashChildAssetsInfoUtil(const int32_t parentId, const int64_t &trashDate)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand querySmartAlbumCmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    string parentPath = MediaLibraryObjectUtils::GetPathByIdFromDb(to_string(parentId));
    querySmartAlbumCmd.GetAbsRdbPredicates()->Like(MEDIA_DATA_DB_FILE_PATH, parentPath + "%")->And()->
        EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_TRASHED));
    vector<string> columns = { MEDIA_DATA_DB_ID };
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore->Query(querySmartAlbumCmd, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("QueryResultSet is nullptr");
        return E_HAS_DB_ERROR;
    }
    auto count = 0;
    int32_t err = queryResultSet->GetRowCount(count);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get count failed, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    if (count == 0) {
        MEDIA_ERR_LOG("Have no child assets");
        return E_SUCCESS;
    }
    err = queryResultSet->GoToFirstRow();
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GoToFirstRow failed, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    do {
        err = UpdateChildTrashInfoInDb(get<int32_t>(
            ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID, queryResultSet, TYPE_INT32)), trashDate);
        CHECK_AND_RETURN_RET_LOG(err > 0, err, "Failed to updateChildTrashInfoInDb");
        err = queryResultSet->GoToNextRow();
    } while (err == NativeRdb::E_OK);
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashDirAssetsInfoUtil(const int32_t assetId, MediaLibraryCommand &cmd)
{
    string oldPath;
    string trashDirPath;
    int32_t errorCode = GetAssetRecycle(assetId, oldPath, trashDirPath, cmd.GetDirQuerySetMap());
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to getAssetRecycle");
    if (!MediaFileUtils::IsDirectory(trashDirPath)) {
        if (!MediaFileUtils::CreateDirectory(trashDirPath)) {
            MEDIA_ERR_LOG("TrashDirPath create failed");
            return E_CREATE_TRASHDIR_FAIL;
        }
    }
    string recyclePath;
    errorCode = MakeRecycleDisplayName(assetId, trashDirPath, recyclePath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to makeRecycleDisplayName");
    if (!MediaFileUtils::RenameDir(oldPath, recyclePath)) {
        return E_MODIFY_DATA_FAIL;
    }
    int64_t trashDate = MediaFileUtils::UTCTimeSeconds();
    errorCode = TrashChildAssetsInfoUtil(assetId, trashDate);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to trashChildAssetsInfoUtil");
    return UpdateDirTrashInfoInDb(assetId, trashDate, recyclePath, oldPath);
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateAssetTrashInfoInDb(const int32_t assetId,
    const int64_t trashDate, string &recyclePath, const string &oldPath)
{
    return UpdateTrashInfoInDb(assetId, trashDate, recyclePath, oldPath, TRASHED_ASSET);
}

int32_t MediaLibrarySmartAlbumMapOperations::TrashFileAssetsInfoUtil(const int32_t assetId, MediaLibraryCommand &cmd)
{
    string trashDirPath;
    string oldPath;
    int32_t errorCode = GetAssetRecycle(assetId, oldPath, trashDirPath, cmd.GetDirQuerySetMap());
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to getAssetRecycle");
    if (!MediaFileUtils::IsDirectory(trashDirPath)) {
        if (!MediaFileUtils::CreateDirectory(trashDirPath)) {
            MEDIA_ERR_LOG("TrashDirPath create failed");
            return E_CREATE_TRASHDIR_FAIL;
        }
    }
    string recyclePath;
    errorCode = MakeRecycleDisplayName(assetId, trashDirPath, recyclePath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to make recycle display name");
    FileAsset fileAsset;
    errorCode = fileAsset.ModifyAsset(oldPath, recyclePath);
    CHECK_AND_RETURN_RET_LOG(errorCode == E_SUCCESS, errorCode, "Failed to modifyAsset");
    int64_t trashDate = MediaFileUtils::UTCTimeSeconds();
    return UpdateAssetTrashInfoInDb(assetId, trashDate, recyclePath, oldPath);
}

int32_t MediaLibrarySmartAlbumMapOperations::InsertTrashAssetsInfoUtil(const int32_t fileAssetId,
    MediaLibraryCommand &cmd)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(fileAssetId);
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(uri);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("FileAsset is nullptr");
        return E_GET_ASSET_FAIL;
    }
    if (fileAsset->GetDateTrashed() != 0) {
        return E_IS_RECYCLED;
    }
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        return TrashFileAssetsInfoUtil(fileAssetId, cmd);
    } else {
        return TrashDirAssetsInfoUtil(fileAssetId, cmd);
    }
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateFavoriteAssetsInfoUtil(const int32_t fileAssetId,
    const bool isFavorites)
{
    ValuesBucket values;
    values.PutBool(MEDIA_DATA_DB_IS_FAV, isFavorites);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(fileAssetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleAddAssetOperation(const int32_t albumId,
    const int32_t childFileAssetId, const int32_t childAlbumId, MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("HandleAddAssetOperations albumId = %{public}d, childFileAssetId = %{public}d",
        albumId, childFileAssetId);
    int32_t errorCode = E_SUCCESS;
    if (albumId == TRASH_ALBUM_ID_VALUES) {
        errorCode = InsertTrashAssetsInfoUtil(childFileAssetId, cmd);
    } else if (albumId == FAVOURITE_ALBUM_ID_VALUES) {
        errorCode = UpdateFavoriteAssetsInfoUtil(childFileAssetId, true);
    }
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, errorCode, "Failed to handleAddAssetOperations");
    if (childAlbumId != DEFAULT_ALBUMID) {
        if (!MediaLibraryObjectUtils::IsParentSmartAlbum(albumId, true)) {
            MEDIA_ERR_LOG("Child can not add smart album");
            return E_CHILD_CAN_NOT_ADD_SMARTALBUM;
        }
    }
    if (childFileAssetId != DEFAULT_ASSETID) {
        if (MediaLibraryObjectUtils::IsParentSmartAlbum(albumId)) {
            MEDIA_ERR_LOG("Parent can not add assets");
            return E_PARENT_CAN_NOT_ADDASSETS;
        }
    }
    return MediaLibraryObjectUtils::InsertInDb(cmd);
}

int32_t MediaLibrarySmartAlbumMapOperations::UpdateTrashInfoInDb(const int32_t assetId, const int64_t trashDate,
    string &recyclePath, const string &oldPath, const uint32_t trashType)
{
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, recyclePath);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, oldPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, trashDate);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, trashDate);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, trashType);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE, values);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, to_string(assetId));
}

int32_t MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperation(MediaLibraryCommand &cmd)
{
    ValueObject valueObject;
    ValuesBucket values = cmd.GetValueBucket();
    int32_t albumId = DEFAULT_ALBUMID;
    if (values.GetObject(SMARTALBUMMAP_DB_ALBUM_ID, valueObject)) {
        valueObject.GetInt(albumId);
    }
    CHECK_AND_RETURN_RET_LOG(MediaLibraryObjectUtils::IsSmartAlbumExistInDb(albumId),
        E_SMARTALBUM_IS_NOT_EXISTED, "Failed to get smartAlbumId");
    int32_t childAssetId = DEFAULT_ASSETID;
    int32_t childAlbumId = DEFAULT_ALBUMID;
    if (values.GetObject(SMARTALBUMMAP_DB_CHILD_ASSET_ID, valueObject)) {
        valueObject.GetInt(childAssetId);
    }
    if (values.GetObject(SMARTALBUMMAP_DB_CHILD_ALBUM_ID, valueObject)) {
        valueObject.GetInt(childAlbumId);
    }
    // childAssetId and childAlbumId only one has value
    if ((childAlbumId == DEFAULT_ALBUMID) && (childAssetId == DEFAULT_ASSETID)) {
        MEDIA_ERR_LOG("GetObject failed");
        return E_GET_VALUEBUCKET_FAIL;
    }
    if (childAlbumId != DEFAULT_ALBUMID) {
        CHECK_AND_RETURN_RET_LOG(MediaLibraryObjectUtils::IsSmartAlbumExistInDb(childAlbumId),
            E_SMARTALBUM_IS_NOT_EXISTED, "Failed to get childAlbumId");
    }
    if (childAssetId != DEFAULT_ASSETID) {
        CHECK_AND_RETURN_RET_LOG(MediaLibraryObjectUtils::IsAssetExistInDb(childAssetId,
            true), E_GET_ASSET_FAIL, "Failed to get childAssetId");
    }
    MEDIA_INFO_LOG("childAssetId = %{public}d , childAlbumId = %{public}d", childAssetId, childAlbumId);
    int32_t errCode = E_ERR;
    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            errCode = HandleAddAssetOperation(albumId, childAssetId, childAlbumId, cmd);
            break;
        case OperationType::DELETE:
            errCode = HandleRemoveAssetOperation(albumId, childAssetId, cmd);
            break;
        case OperationType::AGING:
            errCode = HandleAgingOperation();
        default:
            MEDIA_WARN_LOG("Unknown operation type %{private}d", cmd.GetOprnType());
            break;
        }
    return errCode;
}

void MediaLibrarySmartAlbumMapOperations::SetInterrupt(bool interrupt)
{
    isInterrupt_ = interrupt;
}

bool MediaLibrarySmartAlbumMapOperations::GetInterrupt()
{
    return isInterrupt_.load();
}
} // namespace Media
} // namespace OHOS
