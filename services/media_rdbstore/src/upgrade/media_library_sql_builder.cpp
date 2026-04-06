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

#include "media_library_sql_builder.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;

SqlBuilder& SqlBuilder::AddRawSql(const string& sql)
{
    commands_.push_back(make_shared<RawSqlCommand>(sql));
    return *this;
}

SqlBuilder& SqlBuilder::AddParameterizedSql(const string& sql, const vector<ValueObject>& args)
{
    commands_.push_back(make_shared<ParameterizedSqlCommand>(sql, args));
    return *this;
}

SqlBuilder& SqlBuilder::AddColumn(const string& tableName,
                                  const string& columnName,
                                  const string& columnType)
{
    commands_.push_back(make_shared<AddColumnCommand>(tableName, columnName, columnType));
    return *this;
}

SqlBuilder& SqlBuilder::DropColumn(const string& tableName, const string& columnName)
{
    commands_.push_back(make_shared<DropColumnCommand>(tableName, columnName));
    return *this;
}

SqlBuilder& SqlBuilder::CreateIndex(const string& indexName,
                                    const string& tableName,
                                    const string& columnName)
{
    commands_.push_back(make_shared<CreateIndexCommand>(indexName, tableName, columnName));
    return *this;
}

SqlBuilder& SqlBuilder::DropIndex(const string& indexName)
{
    commands_.push_back(make_shared<DropIndexCommand>(indexName));
    return *this;
}

SqlBuilder& SqlBuilder::DropTrigger(const string& triggerName)
{
    commands_.push_back(make_shared<DropTriggerCommand>(triggerName));
    return *this;
}

SqlBuilder& SqlBuilder::DropTable(const string& tableName)
{
    commands_.push_back(make_shared<DropTableCommand>(tableName));
    return *this;
}

vector<shared_ptr<ISqlCommand>> SqlBuilder::Build() const
{
    return commands_;
}

void SqlBuilder::Clear()
{
    commands_.clear();
}

} // namespace Media
} // namespace OHOS