/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include <dirent.h>
#include <fcntl.h>
#define private public
#include "hi_audit.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
struct HiAuditConfig {
    std::string logPath;
    std::string logName;
    uint32_t logSize;
    uint32_t fileSize;
    uint32_t fileCount;
};

HiAuditConfig HIAUDIT_CONFIG = { "/data/storage/el2/log/audit/", "media_library", 2 * 1024, 3 * 1024 * 1024, 10 };
const std::string HIAUDIT_LOG_NAME = HIAUDIT_CONFIG.logPath + HIAUDIT_CONFIG.logName + "_audit.csv";

void HiAuditTest::SetUpTestCase(void) {}

void HiAuditTest::TearDownTestCase(void) {}

void HiAuditTest::SetUp(void)
{
    // Clear the test environment
    if (access(HIAUDIT_CONFIG.logPath.c_str(), F_OK) == 0) {
        std::string command = "rm -rf " + HIAUDIT_CONFIG.logPath;
        system(command.c_str());
    }
}

void HiAuditTest::TearDown(void) {}

HWTEST_F(HiAuditTest, HiAuditTest_DirectoryExists_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HiAuditTest_DirectoryExists_test_001 begin");
    // Create a Log Directory
    ASSERT_EQ(mkdir(HIAUDIT_CONFIG.logPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH), 0);

    // Create a Log Directory
    int fd =
        open(HIAUDIT_LOG_NAME.c_str(), O_CREAT | O_APPEND | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    ASSERT_GT(fd, 0);
    close(fd);

    // Obtain the HiAudit Instance
    HiAudit &audit = HiAudit::GetInstance();

    // Check Result
    EXPECT_GT(audit.writeFd_, 0);
    struct stat st;
    ASSERT_EQ(stat(HIAUDIT_LOG_NAME.c_str(), &st), 0);
    EXPECT_EQ(audit.writeLogSize_.load(), static_cast<uint64_t>(st.st_size));
    MEDIA_INFO_LOG("HiAuditTest_DirectoryExists_test_001 end");
}

HWTEST_F(HiAuditTest, HiAuditTest_DirectoryNotExists_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("HiAuditTest_DirectoryNotExists_test_002 begin");
    // Obtain the HiAudit Instance
    HiAudit &audit = HiAudit::GetInstance();

    // Check Result
    EXPECT_GT(audit.writeFd_, 0);
    EXPECT_EQ(audit.writeLogSize_.load(), 0);
    MEDIA_INFO_LOG("HiAuditTest_DirectoryNotExists_test_002 end");
}
} // namespace Media
} // namespace OHOS