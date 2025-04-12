/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "mtp_native_test.h"
#include "mtp_monitor.h"

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {
HWTEST_F(MtpNativeTest, mtp_monitor_test_001, TestSize.Level1)
{
    MtpMonitor mtpMonitor;
    EXPECT_EQ(mtpMonitor.interruptFlag, false);
}

HWTEST_F(MtpNativeTest, mtp_monitor_test_002, TestSize.Level1)
{
    MtpMonitor mtpMonitor;
    mtpMonitor.Stop();
    EXPECT_EQ(mtpMonitor.interruptFlag, true);
}
} // namespace Media
} // ohos