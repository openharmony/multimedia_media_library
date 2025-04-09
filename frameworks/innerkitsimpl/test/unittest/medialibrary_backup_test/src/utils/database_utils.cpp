/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "database_utils.h"

#include "backup_database_utils.h"
#include "media_log.h"

namespace OHOS::Media {
void DatabaseUtils::ExecuteSql(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    int32_t errCode = rdbStore->ExecuteSql(sql, bindArgs);
    if (errCode == NativeRdb::E_OK) {
        return;
    }
    MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
}

void DatabaseUtils::ExecuteSqls(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::vector<std::string> &sqls)
{
    for (const auto &sql : sqls) {
        ExecuteSql(rdbStore, sql);
    }
}

int32_t DatabaseUtils::QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &columnName,
    const std::string &querySql, const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return 0;
    }
    auto resultSet = rdbStore->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(columnName, resultSet);
    MEDIA_INFO_LOG("Query %{public}s result: %{public}d", querySql.c_str(), result);
    return result;
}

std::shared_ptr<NativeRdb::RdbStore> DatabaseUtils::GetRdbStore(const std::string &dbPath)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetHaMode(NativeRdb::HAMode::MANUAL_TRIGGER);
    config.SetAllowRebuild(true);
    int errCode = 0;
    RdbCallback cb;
    std::shared_ptr<NativeRdb::RdbStore> rdbStorePtr = NativeRdb::RdbHelper::GetRdbStore(config, 1, cb, errCode);
    MEDIA_INFO_LOG("RdbStore instance. errCode: %{public}d, dbPath: %{public}s", errCode, dbPath.c_str());
    return rdbStorePtr;
}
}  // namespace OHOS::Media