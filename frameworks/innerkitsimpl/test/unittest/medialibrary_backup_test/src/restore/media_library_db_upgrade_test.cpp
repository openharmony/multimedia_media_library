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

#define MLOG_TAG "MediaLibraryDbUpgradeTest"

#define private public
#define protected public
#include "media_library_db_upgrade.h"
#undef private
#undef protected

#include "media_library_db_upgrade_test.h"
#include <string>
#include "media_log.h"
#include "userfile_manager_types.h"
#include "database_utils.h"

using namespace testing::ext;

namespace OHOS::Media {
const std::string DB_PATH_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases/rdb/media_library.db";
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void MediaLibraryDbUpgradeTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void MediaLibraryDbUpgradeTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}

void MediaLibraryDbUpgradeTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void MediaLibraryDbUpgradeTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(MediaLibraryDbUpgradeTest, OnUpgrade_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("OnUpgrade_Test start");
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    ASSERT_NE(medialibraryRdbPtr, nullptr);
    MEDIA_INFO_LOG("OnUpgrade_Test end");
}
}  // namespace OHOS::Media