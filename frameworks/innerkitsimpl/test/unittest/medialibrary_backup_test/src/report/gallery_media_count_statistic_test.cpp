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

#define MLOG_TAG "GalleryMediaCountStatisticTest"

#include <string>
#include <thread>

#define private public
#define protected public
#include "gallery_media_count_statistic.h"
#undef private
#undef protected

#include "media_backup_report_data_type.h"
#include "media_log.h"
#include "gallery_media_count_statistic_test.h"

using namespace testing::ext;
using namespace std;
namespace OHOS::Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
const int32_t EXPECTED_COUNT_0 = 0;
 
void GalleryMediaCountStatisticTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}
 
void GalleryMediaCountStatisticTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}
 
void GalleryMediaCountStatisticTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}
 
void GalleryMediaCountStatisticTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}
 
HWTEST_F(GalleryMediaCountStatisticTest, query_gallery_clone_count_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start query_gallery_clone_count_test");
    GalleryMediaCountStatistic galleryMediaCountStatistic;
    int32_t count = galleryMediaCountStatistic.QueryGalleryCloneCount();
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}
} // namespace OHOS::Media