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

#include "hi_audit_helper_test.h"
#include "media_backup_report_data_type.h"
#include "media_log.h"

#include "backup_hi_audit_helper.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void HiAuditHelperTest::SetUpTestCase(void) {}

void HiAuditHelperTest::TearDownTestCase(void) {}

void HiAuditHelperTest::SetUp(void) {}

void HiAuditHelperTest::TearDown(void) {}

HWTEST_F(HiAuditHelperTest, Write_Error_Audit_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Write_Error_Audit_Log_Test_001 begin");
    BackupHiAuditHelper helper;
    ErrorInfo info(0, 1, "failed", "test error");

    helper.WriteErrorAuditLog(info);
    MEDIA_INFO_LOG("Write_Error_Audit_Log_Test_001 end");
}

HWTEST_F(HiAuditHelperTest, Write_Progress_Audit_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Write_Progress_Audit_Log_Test_001 begin");
    BackupHiAuditHelper helper;
    std::string status = "50%";
    std::string extend = "progress info";

    helper.WriteProgressAuditLog(status, extend);
    MEDIA_INFO_LOG("Write_Progress_Audit_Log_Test_001 end");
}

HWTEST_F(HiAuditHelperTest, Write_Report_Audit_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Write_Report_Audit_Log_Test_001 begin");
    BackupHiAuditHelper helper;
    std::string extend = "report info";

    helper.WriteReportAuditLog(extend);
    MEDIA_INFO_LOG("Write_Report_Audit_Log_Test_001 end");
}

HWTEST_F(HiAuditHelperTest, Set_Basic_Audit_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Set_Basic_Audit_Log_Test_001 begin");
    BackupHiAuditHelper helper;
    BackupAuditLog auditLog;
    std::string extend = "basic info";

    helper.SetBasicAuditLog(auditLog, extend);
    EXPECT_FALSE(auditLog.extend.empty());
    MEDIA_INFO_LOG("Set_Basic_Audit_Log_Test_001 end");
}

HWTEST_F(HiAuditHelperTest, Set_Error_Audit_Log_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Set_Error_Audit_Log_Test_001 begin");
    BackupHiAuditHelper helper;
    BackupAuditLog auditLog;
    ErrorInfo info(-1, 0, "failed", "test error");

    helper.SetErrorAuditLog(auditLog, info);
    EXPECT_EQ(auditLog.operationType, "RESTORE");

    MEDIA_INFO_LOG("Set_Error_Audit_Log_Test_001 end");
}
} // namespace Media
} // namespace OHOS