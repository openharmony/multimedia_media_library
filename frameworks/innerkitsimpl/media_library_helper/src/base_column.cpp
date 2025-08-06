/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "base_column.h"

using namespace std;

namespace OHOS::Media {
const string &BaseColumn::CreateTable()
{
    static const string CREATE_TABLE = "CREATE TABLE IF NOT EXISTS ";
    return CREATE_TABLE;
}

const string &BaseColumn::CreateIndex()
{
    static const string CREATE_INDEX = "CREATE INDEX IF NOT EXISTS ";
    return CREATE_INDEX;
}

const string &BaseColumn::CreateTrigger()
{
    static const string CREATE_TRIGGER = "CREATE TRIGGER IF NOT EXISTS ";
    return CREATE_TRIGGER;
}

const string &BaseColumn::DropTrigger()
{
    static const string DROP_TRIGGER = "DROP TRIGGER IF EXISTS ";
    return DROP_TRIGGER;
}

const string &BaseColumn::DropIndex()
{
    static const string DROP_INDEX = "DROP INDEX IF EXISTS ";
    return DROP_INDEX;
}

string BaseColumn::AlterTableAddIntColumn(const std::string &table, const std::string &column)
{
    return "ALTER TABLE " + table + " ADD COLUMN " + column + " INT DEFAULT 0;";
}

string BaseColumn::AlterTableAddTextColumn(const std::string &table, const std::string &column)
{
    return "ALTER TABLE " + table + " ADD COLUMN " + column + " TEXT DEFAULT '';";
}

string BaseColumn::AlterTableAddBlobColumn(const std::string &table, const std::string &column)
{
    return "ALTER TABLE " + table + " ADD COLUMN " + column + " BLOB;";
}
} // namespace OHOS::Media
