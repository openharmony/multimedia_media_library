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

#include "medialibrary_file_db.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryFileDb::Insert(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    int64_t outRowId = -1;
    (void)rdbStore->Insert(outRowId, MEDIALIBRARY_TABLE, values);

    return outRowId;
}

int32_t MediaLibraryFileDb::Delete(const string &strRow, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs = {};
    int32_t deletedRows = DATA_ABILITY_FAIL;
    string strDeleteCondition = MEDIA_DATA_DB_ID + " = " + strRow;

    int32_t result = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);
    if (result != E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result is %{public}d. Deleted count %{public}d", result, deletedRows);
    }

    return deletedRows;
}

int32_t MediaLibraryFileDb::Modify(const string &rowNum, const string &dstPath,
    const shared_ptr<RdbStore> &rdbStore)
{
    string dispName;
    vector<string> whereArgs;
    int32_t changedRows = -1;

    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + rowNum;

    size_t found = dstPath.rfind("/");
    if (found != string::npos) {
        dispName = dstPath.substr(found + 1);
    }

    struct stat statInfo {};
    if (stat(dstPath.c_str(), &statInfo) == 0) {
        ValuesBucket values;
        values.PutString(MEDIA_DATA_DB_FILE_PATH, dstPath);
        values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, dstPath);
        values.PutString(MEDIA_DATA_DB_NAME, dispName);
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime * SECONDS_TO_MILLISECONDS);
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime * SECONDS_TO_MILLISECONDS);

        int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
        if (result != E_OK || changedRows <= 0) {
            MEDIA_ERR_LOG("Update DB failed. Error is %{public}d. Updated count %{public}d", result, changedRows);
            return DATA_ABILITY_FAIL;
        }
    }

    return changedRows;
}

string MediaLibraryFileDb::QueryFilePath(const string &rowNum, const shared_ptr<RdbStore> &rdbStore)
{
    string filePath;
    vector<string> selectionArgs;
    vector<string> columns;
    int32_t columnIndex;

    AbsRdbPredicates mediaLibAbsPred(MEDIALIBRARY_TABLE);
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);

    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + rowNum;

    mediaLibAbsPred.SetWhereClause(strQueryCondition);
    mediaLibAbsPred.SetWhereArgs(selectionArgs);

    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(mediaLibAbsPred, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("Resultset is null \n");
        return filePath;
    }

    auto rowCount(0);
    (void)queryResultSet->GetRowCount(rowCount);

    auto ret = queryResultSet->GoToFirstRow();
    if (ret == E_OK) {
        ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
        if (ret == E_OK) {
            ret = queryResultSet->GetString(columnIndex, filePath);
        }
    }

    return filePath;
}
} // namespace Media
} // namespace OHOS