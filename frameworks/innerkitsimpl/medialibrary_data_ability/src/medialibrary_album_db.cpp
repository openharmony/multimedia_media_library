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

#include "medialibrary_album_db.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int64_t MediaLibraryAlbumDb::InsertAlbumInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ALBUM_OPERATION_ERR, "Invalid RDB store");

    int64_t outRowId(0);
    int32_t insertResult = rdbStore->Insert(outRowId, MEDIALIBRARY_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == E_OK, ALBUM_OPERATION_ERR, "Insert failed");

    return outRowId;
}

int32_t MediaLibraryAlbumDb::UpdateAlbumInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ALBUM_OPERATION_ERR, "Invalid input");

    // Get album_id from valuebucket
    ValueObject obj;
    int32_t albumId(0);

    auto contains = values.GetObject(MEDIA_DATA_DB_ID, obj);
    if (contains) {
        obj.GetInt(albumId);
    }
    CHECK_AND_RETURN_RET_LOG(albumId > 0, ALBUM_OPERATION_ERR, "Invalid album ID %{public}d", albumId);

    int32_t updatedRows(0);
    vector<string> whereArgs = { std::to_string(albumId) };

    int32_t updateResult = rdbStore->Update(updatedRows, MEDIALIBRARY_TABLE, values, ALBUM_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(updateResult == E_OK, ALBUM_OPERATION_ERR, "Update failed");

    return updatedRows;
}

int32_t MediaLibraryAlbumDb::DeleteAlbumInfo(const int32_t albumId, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0), ALBUM_OPERATION_ERR, "Invalid input");

    int32_t deletedRows(ALBUM_OPERATION_ERR);
    vector<string> whereArgs = { std::to_string(albumId) };

    int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, ALBUM_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == E_OK, ALBUM_OPERATION_ERR, "Delete failed");

    return deletedRows;
}

string MediaLibraryAlbumDb::GetAlbumPath(const int32_t albumId, const shared_ptr<RdbStore> &rdbStore)
{
    string filePath;

    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0), filePath, "Invalid input");

    vector<string> selectionArgs = { std::to_string(albumId) };
    AbsRdbPredicates albumPredicates(MEDIALIBRARY_TABLE);
    albumPredicates.SetWhereClause(ALBUM_DB_COND);
    albumPredicates.SetWhereArgs(selectionArgs);

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);

    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(albumPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Unable to find the path");

    auto rowCount(0);
    (void)queryResultSet->GetRowCount(rowCount);

    int32_t columnIndex;
    auto ret = queryResultSet->GoToFirstRow();
    if (ret == E_OK) {
        ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
        if (ret == E_OK) {
            ret = queryResultSet->GetString(columnIndex, filePath);
        }
    }

    return filePath;
}
}  // namespace Media
}  // namespace OHOS