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

#define private public
#include "backup_hi_audit_helper.h"
#include "backup_log_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void HiAuditHelperTest::SetUpTestCase(void) {}

void HiAuditHelperTest::TearDownTestCase(void) {}

void HiAuditHelperTest::SetUp(void) {}

void HiAuditHelperTest::TearDown(void) {}

HWTEST_F(HiAuditHelperTest, WriteErrorAuditLog_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("WriteErrorAuditLog_Test begin");

    BackupHiAuditHelper helper;
    helper.SetSceneCode(123)
          .SetTaskId("test_task_id");

    ErrorInfo info(1001, 5, "custom_status", "error_extend");

    BackupAuditLog auditLog;
    helper.SetErrorAuditLog(auditLog, info);

    EXPECT_EQ(auditLog.operationType, "RESTORE");
    EXPECT_EQ(auditLog.cause, BackupLogUtils::RestoreErrorToString(1001));
    EXPECT_EQ(auditLog.operationCount, 5u);
    EXPECT_EQ(auditLog.operationStatus, "custom_status");
    EXPECT_EQ(auditLog.operationScenario, "123");
    EXPECT_EQ(auditLog.taskId, "test_task_id");
    EXPECT_EQ(auditLog.extend, BackupLogUtils::Format("error_extend"));

    MEDIA_INFO_LOG("WriteErrorAuditLog_Test end");
}

HWTEST_F(HiAuditHelperTest, WriteProgressAuditLog_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("WriteProgressAuditLog_Test begin");

    BackupHiAuditHelper helper;
    helper.SetSceneCode(456)
          .SetTaskId("progress_task");

    std::string status = "50%";
    std::string extend = "progress_info";

    BackupAuditLog auditLog;
    helper.SetProgressAuditLog(auditLog, status, extend);

    EXPECT_EQ(auditLog.operationType, "STAT");
    EXPECT_EQ(auditLog.cause, "PROGRESS");
    EXPECT_EQ(auditLog.operationStatus, "50%");
    EXPECT_EQ(auditLog.operationScenario, "456");
    EXPECT_EQ(auditLog.taskId, "progress_task");
    EXPECT_EQ(auditLog.extend, BackupLogUtils::Format("progress_info"));

    MEDIA_INFO_LOG("WriteProgressAuditLog_Test end");
}

HWTEST_F(HiAuditHelperTest, WriteReportAuditLog_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("WriteReportAuditLog_Test begin");

    BackupHiAuditHelper helper;
    helper.SetSceneCode(789)
          .SetTaskId("report_task");

    std::string extend = "report_info";

    BackupAuditLog auditLog;
    helper.SetReportAuditLog(auditLog, extend);

    EXPECT_EQ(auditLog.operationType, "STAT");
    EXPECT_EQ(auditLog.cause, "DFX");
    EXPECT_EQ(auditLog.operationStatus, "success");
    EXPECT_EQ(auditLog.operationScenario, "789");
    EXPECT_EQ(auditLog.taskId, "report_task");
    EXPECT_EQ(auditLog.extend, BackupLogUtils::Format("report_info"));

    MEDIA_INFO_LOG("WriteReportAuditLog_Test end");
}

HWTEST_F(HiAuditHelperTest, WriteEmptyStatusAndExtend_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("WriteEmptyStatusAndExtend_Test begin");

    BackupHiAuditHelper helper;
    helper.SetSceneCode(999)
          .SetTaskId("empty_test");

    BackupAuditLog progressLog;
    helper.SetProgressAuditLog(progressLog, "", "");
    EXPECT_EQ(progressLog.operationStatus, "success");
    EXPECT_EQ(progressLog.extend, BackupLogUtils::Format(""));

    BackupAuditLog reportLog;
    helper.SetReportAuditLog(reportLog, "");
    EXPECT_EQ(reportLog.extend, BackupLogUtils::Format(""));

    BackupAuditLog errorLog;
    ErrorInfo emptyInfo(1001, 0, "", "");
    helper.SetErrorAuditLog(errorLog, emptyInfo);
    EXPECT_EQ(errorLog.operationStatus, "failed");
    EXPECT_EQ(errorLog.extend, BackupLogUtils::Format(""));

    MEDIA_INFO_LOG("WriteEmptyStatusAndExtend_Test end");
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