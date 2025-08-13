/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "table_event_handler_on_upgrade_test.h"

#include "medialibrary_unittest_utils.h"

#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_db_const.h"
#include "database_utils.h"
#include "media_column.h"
#include "photo_album_column.h"
#include "photo_map_column.h"

namespace OHOS::Media {
using namespace testing::ext;
void TableEventHandlerOnUpgradeTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MediaLibraryUnitTestUtils::Init();
    TableEventHandlerOnUpgradeTest::MockDatabase();
    TableEventHandler tableEventHandler;
    tableEventHandler.OnUpgrade(MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), 1, MEDIA_RDB_VERSION);
}

void TableEventHandlerOnUpgradeTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void TableEventHandlerOnUpgradeTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void TableEventHandlerOnUpgradeTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

int32_t TableEventHandlerOnUpgradeTest::MockDatabase()
{
    return 0;
}

HWTEST_F(TableEventHandlerOnUpgradeTest, TableEventHandler_OnUpgrade_PhotoAlbum_Trigger, TestSize.Level0)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(rdbStore, nullptr);
    const std::string tableName = PhotoAlbumColumns::TABLE;
    const std::vector<std::string> triggers = {
        "album_delete_trigger",
        "album_modify_trigger",
    };
    bool isExists = true;
    for (auto trigger : triggers) {
        isExists = DatabaseUtils().IsTriggerExists(rdbStore, tableName, trigger);
    }
}

HWTEST_F(TableEventHandlerOnUpgradeTest, TableEventHandler_OnUpgrade_PhotoMap_Trigger, TestSize.Level0)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(rdbStore, nullptr);
    const std::string tableName = PhotoMap::TABLE;
    const std::vector<std::string> triggers = {
        "album_map_delete_trigger",
        "album_map_insert_cloud_sync_trigger",
        "album_map_insert_search_trigger",
        "album_map_delete_search_trigger",
    };
    bool isExists = true;
    for (auto trigger : triggers) {
        isExists = DatabaseUtils().IsTriggerExists(rdbStore, tableName, trigger);
        EXPECT_FALSE(isExists);
    }
}
}  // namespace OHOS::Media