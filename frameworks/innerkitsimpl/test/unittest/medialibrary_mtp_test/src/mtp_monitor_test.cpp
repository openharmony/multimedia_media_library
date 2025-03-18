/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mtp_monitor.h"
#include "mtp_monitor_test.h"
#include "media_log.h"
#include "mtp_file_observer.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_store_observer.h"

using namespace std;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
 
void MtpMonitorTest::SetUpTestCase(void) {}
void MtpMonitorTest::TearDownTestCase(void) {}
void MtpMonitorTest::SetUp() {}
void MtpMonitorTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: mtpMonitor
 */
HWTEST_F(MtpMonitorTest, mtp_monitor_test_001, TestSize.Level0)
{
    std::shared_ptr<MtpMonitor> mtpMonitor = make_shared<MtpMonitor>();
    ASSERT_NE(mtpMonitor, nullptr);
    mtpMonitor->threadRunning_.store(true);
    mtpMonitor->operationPtr_ = make_shared<MtpOperation>();
    mtpMonitor->Start();
    mtpMonitor->Stop();
    mtpMonitor->threadRunning_.store(false);
    EXPECT_EQ(mtpMonitor->threadRunning_.load(), false);
    mtpMonitor = nullptr;
}
} // namespace Media
} // namespace OHOS