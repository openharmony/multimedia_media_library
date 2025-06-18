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

#define MLOG_TAG "FileExtUnitTest"

#include "bg_task_processor_test.h"

#include "ability_context_impl.h"
#include "media_column.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_old_photos_column.h"
#include "media_app_uri_permission_column.h"

#include <string>
#include <vector>

using namespace std;
using namespace OHOS;
using namespace testing::ext;
namespace OHOS {
namespace Media {
std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
const std::string CREATE_TAB_OLD_PHOTO_TABLE = "CREATE TABLE IF NOT EXISTS " +
    PhotoColumn::TAB_OLD_PHOTOS_TABLE + " (" +
    TabOldPhotosColumn::MEDIA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    TabOldPhotosColumn::MEDIA_FILE_PATH + " TEXT, " +
    TabOldPhotosColumn::MEDIA_OLD_ID + " INTEGER, " +
    TabOldPhotosColumn::MEDIA_OLD_FILE_PATH + " TEXT" +
    ") ";

static void CleanTestTables()
{
    std::vector<std::string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        PhotoColumn::TAB_OLD_PHOTOS_TABLE,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE,
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

static void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        CREATE_TAB_OLD_PHOTO_TABLE,
        AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbStore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_INFO_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    system("rm -rf /storage/cloud/files/.cache");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    SetTables();
}

void MediaLibraryBgTaskProcessorTest::SetUpTestCase(void)
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    g_rdbStore = std::make_shared<MediaLibraryRdbStore>(abilityContextImpl);
    int32_t ret = g_rdbStore->Init();
    CleanTestTables();
    SetTables();
    MEDIA_INFO_LOG("MediaLibraryBgTaskProcessorTest rdbstore start ret = %{public}d", ret);
}

void MediaLibraryBgTaskProcessorTest::TearDownTestCase(void)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    ClearAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(1));
    MEDIA_INFO_LOG("Clean is finish");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MediaLibraryBgTaskProcessorTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryCloudAssetDownloadTest failed, can not get rdbstore");
        exit(1);
    }
    ClearAndRestart();
}

void MediaLibraryBgTaskProcessorTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}
} // namespace Media
} // namespace OHOS