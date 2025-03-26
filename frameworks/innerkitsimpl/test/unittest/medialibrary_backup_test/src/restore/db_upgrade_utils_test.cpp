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

#define MLOG_TAG "DbUpgradeUtilsTest"

#define private public
#define protected public
#include "db_upgrade_utils.h"
#undef private
#undef protected

#include "db_upgrade_utils_test.h"

#include <string>

#include "rdb_store.h"
#include "media_log.h"
#include "userfile_manager_types.h"
#include "database_mock.h"
#include "database_utils.h"

using namespace testing::ext;

namespace OHOS::Media {
const std::string DB_PATH_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases/rdb/media_library.db";
const std::string BASE_DIR_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases";
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void DbUpgradeUtilsTest::SetUpTestCase(void)
{
    DatabaseMock().MediaLibraryDbMock(BASE_DIR_MEDIALIBRARY);
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DbUpgradeUtilsTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}

void DbUpgradeUtilsTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DbUpgradeUtilsTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(DbUpgradeUtilsTest, DropAllTriggersTest, TestSize.Level0)
{
    MEDIA_INFO_LOG("DropAllTriggersTest start");
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    ASSERT_NE(medialibraryRdbPtr, nullptr);
    this->CreateTempTriggersTable(medialibraryRdbPtr);
    std::vector<std::string> triggerNames =
        DataTransfer::DbUpgradeUtils().GetAllTriggers(*medialibraryRdbPtr, this->NAME_TEMP_TRIGGERS_TABLE);
    EXPECT_FALSE(triggerNames.empty());
    int32_t ret = DataTransfer::DbUpgradeUtils().DropAllTriggers(*medialibraryRdbPtr, this->NAME_TEMP_TRIGGERS_TABLE);
    EXPECT_EQ(ret, 0);
    triggerNames = DataTransfer::DbUpgradeUtils().GetAllTriggers(*medialibraryRdbPtr, this->NAME_TEMP_TRIGGERS_TABLE);
    EXPECT_TRUE(triggerNames.empty());
    MEDIA_INFO_LOG("DropAllTriggersTest end");
}

HWTEST_F(DbUpgradeUtilsTest, GetAllUniqueIndexTest, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAllUniqueIndexTest start");
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    ASSERT_NE(medialibraryRdbPtr, nullptr);
    this->CreateTempUniqueTable(medialibraryRdbPtr);
    std::vector<std::string> UniqueIndex =
        DataTransfer::DbUpgradeUtils().GetAllUniqueIndex(*medialibraryRdbPtr, this->NAME_TEMP_UNIQUE_TABLE);
    EXPECT_TRUE(UniqueIndex.empty());
    MEDIA_INFO_LOG("GetAllUniqueIndexTest end");
}
}  // namespace OHOS::Media