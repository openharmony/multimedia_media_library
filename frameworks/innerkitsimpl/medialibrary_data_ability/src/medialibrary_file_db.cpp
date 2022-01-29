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
    MEDIA_ERR_LOG("MediaLibraryFileDb::Insert in");
    int64_t outRowId = -1;
    if (rdbStore != nullptr) {
        (void)rdbStore->Insert(outRowId, MEDIALIBRARY_TABLE, values);
    }

    return outRowId;
}

int32_t MediaLibraryFileDb::Delete(const string &strRow, const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> whereArgs = {};
    int32_t deletedRows = DATA_ABILITY_FAIL;

    if (!strRow.empty()) {
        string strDeleteCondition = MEDIA_DATA_DB_ID + " = " + strRow;

        if (rdbStore != nullptr) {
            int32_t result = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);
            if (result != E_OK) {
                MEDIA_ERR_LOG("Delete operation failed. Result %{public}d. Deleted %{public}d", result, deletedRows);
            }
        }
    }

    return deletedRows;
}

int32_t MediaLibraryFileDb::Modify(const string &rowNum, const string &dstPath,
    const int &bucketId, const std::string &bucketName, const shared_ptr<RdbStore> &rdbStore)
{
    string dispName;
    vector<string> whereArgs;
    int32_t changedRows = -1;

    if ((!rowNum.empty()) && (!dstPath.empty()) && (rdbStore != nullptr)) {
        string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + rowNum;

        size_t found = dstPath.rfind("/");
        if (found != string::npos) {
            dispName = dstPath.substr(found + 1);
        }

        struct stat statInfo {};
        if (stat(dstPath.c_str(), &statInfo) == 0) {
            ValuesBucket values;
            values.PutString(MEDIA_DATA_DB_FILE_PATH, dstPath);
            values.PutString(MEDIA_DATA_DB_BUCKET_NAME, bucketName);
            values.PutInt(MEDIA_DATA_DB_BUCKET_ID, bucketId);
            values.PutInt(MEDIA_DATA_DB_PARENT_ID, bucketId);
            values.PutLong(MEDIA_DATA_DB_DATE_ADDED, statInfo.st_ctime);
            values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, statInfo.st_mtime);

            int32_t result = rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, values, strUpdateCondition, whereArgs);
            if ((result != E_OK) || (changedRows <= 0)) {
                MEDIA_ERR_LOG("Update DB failed. Error is %{public}d. Updated count %{public}d", result, changedRows);
                return DATA_ABILITY_FAIL;
            }
        }
    }

    return changedRows;
}
} // namespace Media
} // namespace OHOS