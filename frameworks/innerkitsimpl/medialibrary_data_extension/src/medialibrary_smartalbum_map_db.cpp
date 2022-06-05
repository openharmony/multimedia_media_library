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

#include "medialibrary_smartalbum_map_db.h"
#include "media_log.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int64_t MediaLibrarySmartAlbumMapDb::InsertSmartAlbumMapInfo(const ValuesBucket &values,
                                                             const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ALBUM_OPERATION_ERR, "Invalid RDB store");
    int64_t outRowId(0);
    int32_t insertResult = rdbStore->Insert(outRowId, SMARTALBUM_MAP_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == NativeRdb::E_OK, ALBUM_OPERATION_ERR, "Insert failed");
    return outRowId;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteSmartAlbumMapInfo(const int32_t albumId,
                                                             const int32_t assetId,
                                                             const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0) && (assetId > 0),
        ALBUM_OPERATION_ERR, "Invalid input");
    int32_t deletedRows(ALBUM_OPERATION_ERR);
    vector<string> whereArgs = { std::to_string(albumId), std::to_string(assetId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows, SMARTALBUM_MAP_TABLE, SMARTALBUM_MAP_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, ALBUM_OPERATION_ERR, "Delete failed");
    return (deletedRows > 0) ? DATA_ABILITY_SUCCESS : DATA_ABILITY_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteAllSmartAlbumMapInfo(const int32_t albumId,
                                                                const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0), ALBUM_OPERATION_ERR, "Invalid input");
    int32_t deletedRows(ALBUM_OPERATION_ERR);
    vector<string> whereArgs = { std::to_string(albumId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows,
        SMARTALBUM_MAP_TABLE, SMARTALBUM_MAP_DE_SMARTALBUM_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, ALBUM_OPERATION_ERR, "Delete failed");
    return (deletedRows > 0) ? DATA_ABILITY_SUCCESS : DATA_ABILITY_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteAllAssetsMapInfo(const int32_t assetId,
                                                            const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (assetId > 0), ALBUM_OPERATION_ERR, "Invalid input");
    int32_t deletedRows(ALBUM_OPERATION_ERR);
    vector<string> whereArgs = { std::to_string(assetId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows, SMARTALBUM_MAP_TABLE,
        SMARTALBUM_MAP_DE_ASSETS_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, ALBUM_OPERATION_ERR, "Delete failed");
    return (deletedRows > 0) ? DATA_ABILITY_SUCCESS : DATA_ABILITY_FAIL;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateTrashInfo(const int32_t &assetId,
                                                     const int32_t &isTrash,
                                                     const shared_ptr<RdbStore> &rdbStore,
                                                     string &recyclePath,
                                                     const int64_t &date)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ALBUM_OPERATION_ERR, "Invalid input");
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
    ValuesBucket values;
    if (isTrash == 0) {
        MEDIA_INFO_LOG("UpdateTrashInfo isTrash == 0");
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date);
        values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    } else {
        MEDIA_INFO_LOG("UpdateTrashInfo isTrash != 0");
        if (isTrash == ASSET_ISTRASH || isTrash == DIR_ISTRASH) {
            values.PutString(MEDIA_DATA_DB_RECYCLE_PATH, recyclePath);
            values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date);
        }
        values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, date);
    }
    values.PutInt(MEDIA_DATA_DB_IS_TRASH, isTrash);
    int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
    if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
        MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
        return DATA_ABILITY_FAIL;
    }
    return DATA_ABILITY_SUCCESS;
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
        values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return DATA_ABILITY_FAIL;
        }
    }
    return DATA_ABILITY_SUCCESS;
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
            return DATA_ABILITY_FAIL;
        }
    }
    return DATA_ABILITY_SUCCESS;
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
            return DATA_ABILITY_FAIL;
        }
    }
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::UpdateChildPathInfo(const int32_t &assetId,
    const string &path, const string &relativePath, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs;
    int32_t changedRows = -1;

    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        ValuesBucket values;
        if (!path.empty()) {
            values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
            values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        }
        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if ((result != NativeRdb::E_OK) || (changedRows <= 0)) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{private}d. Updated count %{private}d", result, changedRows);
            return DATA_ABILITY_FAIL;
        }
    }
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibrarySmartAlbumMapDb::DeleteTrashInfo(const int32_t &assetId, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs = {};
    int32_t deletedRows = DATA_ABILITY_FAIL;
    if ((rdbStore != nullptr) && (assetId > 0)) {
        string strDeleteCondition = MEDIA_DATA_DB_ID + " = " + to_string(assetId);
        int32_t result = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);
        if (result != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Delete operation failed. Result %{private}d. Deleted %{private}d", result, deletedRows);
        }
    }

    return DATA_ABILITY_SUCCESS;
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
            return DATA_ABILITY_FAIL;
        }
    }
    return DATA_ABILITY_SUCCESS;
}
}  // namespace Media
}  // namespace OHOS