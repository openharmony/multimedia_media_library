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

#ifndef OHOS_MEDIA_DATATRANSFER_DB_UPGRADE_UTILS_TEST_H
#define OHOS_MEDIA_DATATRANSFER_DB_UPGRADE_UTILS_TEST_H

#include "gtest/gtest.h"

namespace OHOS::Media {
class DbUpgradeUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    void CreateTempTriggersTable(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
    {
        std::string sql = SQL_TEMP_TRIGGERS_TABLE_CREATE;
        rdbStore->ExecuteSql(sql);
        sql = SQL_TEMP_TRIGGERS_TABLE_TRIGGER;
        rdbStore->ExecuteSql(sql);
        return;
    }

    void CreateTempUniqueTable(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
    {
        std::string sql = SQL_TEMP_UNIQUE_TABLE_CREATE;
        rdbStore->ExecuteSql(sql);
        sql = SQL_TEMP_UNIQUE_TABLE_INDEX;
        rdbStore->ExecuteSql(sql);
        return;
    }

public:
    const std::string NAME_TEMP_TRIGGERS_TABLE = "temp_triggers";
    const std::string SQL_TEMP_TRIGGERS_TABLE_CREATE = "\
        CREATE TABLE IF NOT EXISTS temp_triggers \
        AS \
        SELECT * FROM PhotoMap;";
    const std::string SQL_TEMP_TRIGGERS_TABLE_TRIGGER = "\
        CREATE TRIGGER temp_triggers_example \
            AFTER INSERT \
                ON temp_triggers \
        FOR EACH ROW \
        BEGIN \
            SELECT 1; \
        END;";
    const std::string NAME_TEMP_UNIQUE_TABLE = "temp_unique";
    const std::string SQL_TEMP_UNIQUE_TABLE_CREATE = "\
        CREATE TABLE IF NOT EXISTS temp_unique \
        AS \
        SELECT * FROM PhotoMap;";
    const std::string SQL_TEMP_UNIQUE_TABLE_INDEX = "\
        CREATE INDEX temp_unique_example \
            ON temp_unique (map_ablum);";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_DATATRANSFER_DB_UPGRADE_UTILS_TEST_H