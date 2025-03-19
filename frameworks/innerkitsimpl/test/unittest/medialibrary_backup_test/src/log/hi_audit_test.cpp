/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hi_audit_test.h"
#include <fstream>

#include "media_log.h"
#define private public
#include "backup_hi_audit.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void HiAuditTest::SetUpTestCase(void) {}

void HiAuditTest::TearDownTestCase(void) {}

void HiAuditTest::SetUp(void) {}

void HiAuditTest::TearDown(void) {}

HWTEST_F(HiAuditTest, Get_Instance_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Get_Instance_Test_001 begin");
    BackupHiAudit& instance1 = BackupHiAudit::GetInstance();
    BackupHiAudit& instance2 = BackupHiAudit::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
    MEDIA_INFO_LOG("Get_Instance_Test_001 end");
}

HWTEST_F(HiAuditTest, Get_Milliseconds_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Get_Milliseconds_Test_001 begin");
    uint64_t time1 = BackupHiAudit::GetInstance().GetMilliseconds();
    uint64_t time2 = BackupHiAudit::GetInstance().GetMilliseconds();

    EXPECT_GE(time2, time1);
    MEDIA_INFO_LOG("Get_Milliseconds_Test_001 end");
}

HWTEST_F(HiAuditTest, Get_Formatted_Timestamp_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Get_Formatted_Timestamp_Test_001 begin");
    time_t now = time(nullptr);
    std::string result = BackupHiAudit::GetInstance().GetFormattedTimestamp(now * 1000, "%Y%m%d%H%M%S");

    EXPECT_EQ(result.length(), 14); // YYYYMMDDHHMMSS
    MEDIA_INFO_LOG("Get_Formatted_Timestamp_Test_001 end");
}

HWTEST_F(HiAuditTest, Write_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Write_Log_Test_001 begin");
    BackupAuditLog log;
    log.operationType = "TEST";
    log.operationScenario = "1";
    log.taskId = "12345";
    log.cause = "TEST_CASE";
    log.operationCount = 1;
    log.operationStatus = "SUCCESS";
    log.extend = "test log";

    BackupHiAudit::GetInstance().Write(log);
    MEDIA_INFO_LOG("Write_Log_Test_001 end");
}
} // namespace Media
} // namespace OHOS