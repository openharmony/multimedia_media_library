/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Upgrade"

#include "media_library_sql_command.h"

#include "media_log.h"
#include <sstream>

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;

int32_t RawSqlCommand::Execute(RdbStore& store)
{
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql_.c_str());
    return store.ExecuteSql(sql_);
}

int32_t ParameterizedSqlCommand::Execute(RdbStore& store)
{
    MEDIA_DEBUG_LOG("Executing parameterized SQL: %{public}s, args count: %{public}zu",
        sql_.c_str(), args_.size());
    return store.ExecuteSql(sql_, args_);
}

string AddColumnCommand::GetSql() const
{
    std::stringstream ss;
    ss << "ALTER TABLE " << tableName_ << " ADD COLUMN " << columnName_ << " " << columnType_;
    return ss.str();
}

int32_t AddColumnCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

string DropColumnCommand::GetSql() const
{
    std::stringstream ss;
    ss << "ALTER TABLE " << tableName_ << " DROP COLUMN " << columnName_;
    return ss.str();
}

int32_t DropColumnCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

string CreateIndexCommand::GetSql() const
{
    std::stringstream ss;
    ss << "CREATE INDEX IF NOT EXISTS " << indexName_ << " ON " << tableName_ << " (" << columnName_ << ")";
    return ss.str();
}

int32_t CreateIndexCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

string DropIndexCommand::GetSql() const
{
    std::stringstream ss;
    ss << "DROP INDEX IF EXISTS " << indexName_;
    return ss.str();
}

int32_t DropIndexCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

string DropTriggerCommand::GetSql() const
{
    std::stringstream ss;
    ss << "DROP TRIGGER IF EXISTS " << triggerName_;
    return ss.str();
}

int32_t DropTriggerCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

string DropTableCommand::GetSql() const
{
    std::stringstream ss;
    ss << "DROP TABLE IF EXISTS " << tableName_;
    return ss.str();
}

int32_t DropTableCommand::Execute(RdbStore& store)
{
    string sql = GetSql();
    MEDIA_DEBUG_LOG("Executing SQL: %{public}s", sql.c_str());
    return store.ExecuteSql(sql);
}

} // namespace Media
} // namespace OHOS