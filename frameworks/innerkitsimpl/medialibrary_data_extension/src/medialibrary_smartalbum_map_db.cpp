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

#include "medialibrary_smartalbum_map_db.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const std::string SMARTALBUM_MAP_DE_SMARTALBUM_COND = SMARTALBUMMAP_DB_ALBUM_ID + " = ?";
static const std::string SMARTALBUM_MAP_DE_ASSETS_COND = SMARTALBUMMAP_DB_CHILD_ASSET_ID + " = ?";
static const std::string SMARTALBUM_MAP_DB_COND = SMARTALBUMMAP_DB_ALBUM_ID +
    " = ? AND " + SMARTALBUMMAP_DB_CHILD_ASSET_ID + " = ?";
int64_t MediaLibrarySmartAlbumMapDb::InsertSmartAlbumMapInfo(const ValuesBucket &values,
                                                             const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid RDB store");
    int64_t outRowId(0);
    int32_t insertResult = rdbStore->Insert(outRowId, SMARTALBUM_MAP_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Insert failed");
    return outRowId;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteSmartAlbumMapInfo(const int32_t albumId,
                                                             const int32_t assetId,
                                                             const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0) && (assetId > 0),
        E_ALBUM_OPER_ERR, "Invalid input");
    int32_t deletedRows(E_ALBUM_OPER_ERR);
    vector<string> whereArgs = { std::to_string(albumId), std::to_string(assetId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows, SMARTALBUM_MAP_TABLE, SMARTALBUM_MAP_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Delete failed");
    return (deletedRows > 0) ? E_SUCCESS : E_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteAllSmartAlbumMapInfo(const int32_t albumId,
                                                                const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0), E_ALBUM_OPER_ERR, "Invalid input");
    int32_t deletedRows(E_ALBUM_OPER_ERR);
    vector<string> whereArgs = { std::to_string(albumId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows,
        SMARTALBUM_MAP_TABLE, SMARTALBUM_MAP_DE_SMARTALBUM_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Delete failed");
    return (deletedRows > 0) ? E_SUCCESS : E_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteAllAssetsMapInfo(const int32_t assetId,
                                                            const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (assetId > 0), E_ALBUM_OPER_ERR, "Invalid input");
    int32_t deletedRows(E_ALBUM_OPER_ERR);
    vector<string> whereArgs = { std::to_string(assetId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows, SMARTALBUM_MAP_TABLE,
        SMARTALBUM_MAP_DE_ASSETS_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Delete failed");
    return (deletedRows > 0) ? E_SUCCESS : E_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateAssetTrashInfo(const int32_t &assetId,
                                                          const int64_t &trashDate,
                                                          const shared_ptr<RdbStore> &rdbStore,
                                                          string &recyclePath,
                                                          const string &oldPath)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid input");
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    MEDIA_DEBUG_LOG("UpdateAssetTrashInfo isTrash != 0");
    values.PutString(MEDIA_DATA_DB_FILE_PATH, recyclePath);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, oldPath);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, trashDate);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, trashDate);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, ASSET_ISTRASH);
    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return E_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateSameNameInfo(const int32_t &assetId,
    const string &displayName, const string &path, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;
    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        ValuesBucket values;
        values.PutString(MEDIA_DATA_DB_NAME, displayName);
        values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, path);
        values.PutString(MEDIA_DATA_DB_TITLE, MediaLibraryDataManagerUtils::GetFileTitle(displayName));
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return E_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateParentDirRecycleInfo(const int32_t &assetId, const int32_t &parentId,
    const string &parentName, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;

    if ((rdbStore != nullptr) && (assetId > 0) && (parentId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        ValuesBucket values;
        values.PutInt(MEDIA_DATA_DB_PARENT_ID, parentId);
        if (!parentName.empty()) {
            values.PutInt(MEDIA_DATA_DB_BUCKET_ID, parentId);
            values.PutString(MEDIA_DATA_DB_BUCKET_NAME, parentName);
        }
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return E_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateChildFileRecycleInfo(const int32_t &assetId,
    const string &parentName, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;

    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        ValuesBucket values;
        if (!parentName.empty()) {
            values.PutString(MEDIA_DATA_DB_BUCKET_NAME, parentName);
        }
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return E_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateChildPathInfo(const int32_t &assetId,
    const string &path, const string &relativePath, const int32_t isTrash, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;

    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        ValuesBucket values;
        if (isTrash == CHILD_ISTRASH) {
            values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
        } else {
            values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, path);
        }
        values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return E_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteTrashInfo(const int32_t &assetId, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs = {};
    int32_t deletedRows = E_FAIL;
    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strDeleteCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        int32_t result = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);
        if (result != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
        }
    }

    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateFavoriteInfo(const int32_t &assetId,
    const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;
    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return E_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateRecycleInfo(const int32_t &assetId,
                                                       const shared_ptr<RdbStore> &rdbStore,
                                                       const string &realPath)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid input");
    vector<string> whereArgs;
    int32_t changedRows = -1;
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, realPath);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, "");
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, 0);
    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return E_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateChildRecycleInfo(const int32_t &assetId,
                                                            const shared_ptr<RdbStore> &rdbStore,
                                                            const int64_t &recycleDate)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid input");
    vector<string> whereArgs;
    int32_t changedRows = -1;
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, recycleDate);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, 0);
    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return E_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateDirTrashInfo(const int32_t &assetId,
                                                        const int64_t &trashDate,
                                                        const shared_ptr<RdbStore> &rdbStore,
                                                        string &recyclePath,
                                                        const string &oldPath)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid input");
    vector<string> whereArgs;
    int32_t changedRows = -1;
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, recyclePath);
    values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, oldPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, trashDate);
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, trashDate);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, DIR_ISTRASH);

    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return E_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateChildTrashInfo(const int32_t &assetId,
                                                          const shared_ptr<RdbStore> &rdbStore,
                                                          const int64_t &trashDate)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid input");
    vector<string> whereArgs;
    int32_t changedRows = -1;
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, trashDate);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, trashDate);
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, CHILD_ISTRASH);
    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return E_FAIL;
    }
    return E_SUCCESS;
}
}  // namespace Media
}  // namespace OHOS
