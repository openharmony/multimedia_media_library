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

#define MLOG_TAG "UpgradeRestoreTaskReportTest"

#include <string>
#include <thread>

#define private public
#define protected public
#include "upgrade_restore_task_report.h"
#undef private
#undef protected

#include "media_log.h"
#include "upgrade_restore_task_report_test.h"

using namespace testing::ext;
using namespace std;
namespace OHOS::Media {
 
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
const int32_t EXPECTED_COUNT_0 = 0;
const int32_t EXPECTED_COUNT_1 = 1;
  
void UpgradeRestoreTaskReportTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}
  
void UpgradeRestoreTaskReportTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}
  
void UpgradeRestoreTaskReportTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}
  
void UpgradeRestoreTaskReportTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}
  
HWTEST_F(UpgradeRestoreTaskReportTest, report_progress_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start report_progress_test_001");
    UpgradeRestoreTaskReport upgradeRestoreTaskReport;
    EXPECT_EQ(&upgradeRestoreTaskReport, &upgradeRestoreTaskReport.ReportProgress("", "", EXPECTED_COUNT_1));
}

HWTEST_F(UpgradeRestoreTaskReportTest, report_progress_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start report_progress_test_002");
    UpgradeRestoreTaskReport upgradeRestoreTaskReport;
    EXPECT_EQ(&upgradeRestoreTaskReport, &upgradeRestoreTaskReport.ReportProgress("", "", EXPECTED_COUNT_0));
}

HWTEST_F(UpgradeRestoreTaskReportTest, report_timeout_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start report_timeout_test_001");
    UpgradeRestoreTaskReport upgradeRestoreTaskReport;
    EXPECT_EQ(&upgradeRestoreTaskReport, &upgradeRestoreTaskReport.ReportTimeout(EXPECTED_COUNT_1));
}

HWTEST_F(UpgradeRestoreTaskReportTest, report_timeout_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start report_timeout_test_002");
    UpgradeRestoreTaskReport upgradeRestoreTaskReport;
    EXPECT_EQ(&upgradeRestoreTaskReport, &upgradeRestoreTaskReport.ReportTimeout(EXPECTED_COUNT_0));
}
} // namespace OHOS::Media