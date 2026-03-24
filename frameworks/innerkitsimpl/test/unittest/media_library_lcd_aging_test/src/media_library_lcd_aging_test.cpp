/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "media_library_lcd_aging_test.h"

#include "lcd_aging_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"


#include "ithumbnail_helper.h"
#include "media_file_utils.h"
#include "media_upgrade.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "thumbnail_source_loading.h"

using namespace std;
using namespace OHOS;
using namespace::testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static int64_t g_id;
// const string KV_STORE_DIR = "/data/medialibrary/database";
const int64_t DATE_TAKEN_TEST_VALUE = 1756111539577;
const string TEST_IMAGE_PATH = "/storage/cloud/files/Photo/1/CreateImageThumbnailTest_001.jpg";

class TddRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return E_OK;
    }
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

static void InitRdbStore()
{
    const string dbPath = "/data/test/medialibrary_thumbnail_rdb_utils_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    TddRdbOpenCallback openCallback;

    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, openCallback);
    ASSERT_EQ(ret, E_OK);
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);

    ret = g_rdbStore->ExecuteSql(PhotoUpgrade::CREATE_PHOTO_TABLE);
    ASSERT_EQ(ret, NativeRdb::E_OK);

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, 0);
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, DATE_TAKEN_TEST_VALUE);
    ret = g_rdbStore->Insert(g_id, PhotoColumn::PHOTOS_TABLE, values);
    ASSERT_EQ(ret, NativeRdb::E_OK);
}

static void DeleteRdbStore()
{
    string dropSql = "DROP TABLE IF EXIST " + PhotoColumn::PHOTOS_TABLE + ";";
    int32_t ret = g_rdbStore->ExecuteSql(dropSql);
    MEDIA_INFO_LOG("Drop photos table ret: %{public}d", ret == NativeRdb::E_OK);
    MediaLibraryUnitTestUtils::StopUnistore();
}

void MediaLibraryLcdAgingTest::SetUpTestCase(void)
{
    InitRdbStore();
}

void MediaLibraryLcdAgingTest::TearDownTestCase(void)
{
    DeleteRdbStore();
}

void MediaLibraryLcdAgingTest::SetUp() {}

void MediaLibraryLcdAgingTest::TearDown(void) {}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetMaxThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin lcd_aging_GetMaxThresholdOfLcd_test_001");
    ThumbRdbOpt opts;
    ThumbnailData data;
    opts.store = g_rdbStore;
    opts.table = PhotoColumn::PHOTOS_TABLE;
    data.id = std::to_string(g_id);
    data.path = TEST_IMAGE_PATH;
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    bool result = IThumbnailHelper::DoCreateLcdAndThumbnail(opts, data);
    EXPECT_EQ(result, true);

    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetMaxThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 20000);
}


HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetScaleThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin lcd_aging_GetScaleThresholdOfLcd_test_001");
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 16000);
}
} // namespace Media
} // namespace OHOS