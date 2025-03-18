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

#define MLOG_TAG "PhotosCountStatisticTest"

#include <string>
#include <thread>

#define private public
#define protected public
#include "photos_count_statistic.h"
#undef private
#undef protected

#include "database_mock.h"
#include "database_utils.h"
#include "media_backup_report_data_type.h"
#include "media_log.h"
#include "photos_count_statistic_test.h"

using namespace testing::ext;
using namespace std;
namespace OHOS::Media {

const std::string DB_PATH_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases/rdb/media_library.db";
const std::string BASE_DIR_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases";
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
const std::string TEST_TASK_ID = "1";
const int32_t TEST_UPGRADE_RESTORE_ID = 0;
const int32_t TEST_PERIOD = 0;
const int32_t EXPECTED_COUNT_0 = 0;
 
void PhotosCountStatisticTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    DatabaseMock().MediaLibraryDbMock(BASE_DIR_MEDIALIBRARY);
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
}
 
void PhotosCountStatisticTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}
 
void PhotosCountStatisticTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}
 
void PhotosCountStatisticTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}
 
HWTEST_F(PhotosCountStatisticTest, load_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start load_test_001");
    PhotosCountStatistic photosCountStatistic;
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = photosCountStatistic.Load();
    EXPECT_TRUE(albumMediaStatisticInfos.empty());
}

HWTEST_F(PhotosCountStatisticTest, load_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start load_test_002");
    auto medialibraryRdbPtr_ = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    PhotosCountStatistic photosCountStatistic;
    photosCountStatistic.SetMediaLibraryRdb(medialibraryRdbPtr_).SetSceneCode(TEST_UPGRADE_RESTORE_ID).
        SetTaskId(TEST_TASK_ID).SetPeriod(TEST_PERIOD);
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = photosCountStatistic.Load();
    EXPECT_GT(albumMediaStatisticInfos.size(), 0);
}
} // namespace OHOS::Media