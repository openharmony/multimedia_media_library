/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "db_upgrade_utils.h"

#include <string>
#include <vector>

#include "rdb_store.h"
#include "media_log.h"

namespace OHOS::Media {
namespace DataTransfer {
/**
 * @brief Check table exists or not.
 */
bool DbUpgradeUtils::IsTableExists(NativeRdb::RdbStore &store, const std::string &tableName)
{
    std::string querySql = this->SQL_SQLITE_MASTER_QUERY;
    std::vector<NativeRdb::ValueObject> bindArgs = {tableName};
    auto resultSet = store.QuerySql(querySql, bindArgs);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return false;
    }
    int rowCount = 0;
    bool isExists = !resultSet->GetRowCount(rowCount) && rowCount > 0;
    MEDIA_INFO_LOG("Media_Restore: tableName=%{public}s, isExists:%{public}d", tableName.c_str(), isExists);
    return isExists;
}

/**
 * @brief Check table column exists or not.
 */
bool DbUpgradeUtils::IsColumnExists(
    NativeRdb::RdbStore &store, const std::string &tableName, const std::string &columnName)
{
    std::string querySql = this->SQL_PRAGMA_TABLE_INFO_QUERY;
    std::vector<NativeRdb::ValueObject> bindArgs = {tableName, columnName};
    auto resultSet = store.QuerySql(querySql, bindArgs);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return false;
    }
    int rowCount = 0;
    bool isExists = !resultSet->GetRowCount(rowCount) && rowCount > 0;
    MEDIA_INFO_LOG("Media_Restore: tableName=%{public}s, columnName=%{public}s, isExists:%{public}d",
        tableName.c_str(),
        columnName.c_str(),
        isExists);
    return isExists;
}
}  // namespace DataTransfer
}  // namespace OHOS::Media