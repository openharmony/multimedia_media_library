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

#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <filesystem>
#include "media_log.h"
#define private public
#include "backup_hi_audit.h"
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
void HiAuditTest::SetUp(void) {
    std::error_code errcode;
    if (std::filesystem::exists(HIAUDIT_LOG_NAME)) {
        std::filesystem::remove(HIAUDIT_LOG_NAME, errcode);
    }
}

void HiAuditTest::TearDown(void) {
    std::error_code errcode;
    if (std::filesystem::exists(HIAUDIT_LOG_NAME)) {
        std::filesystem::remove(HIAUDIT_LOG_NAME, errcode);
    }
}

HWTEST_F(HiAuditTest, HiAuditTest_DirectoryExists_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_DirectoryExists_test_001 begin");
    std::error_code errcode;
    std::filesystem::create_directories(HIAUDIT_CONFIG.logPath, errcode);
    ASSERT_TRUE(errcode.value() == 0) << "create dit fail: " << errcode.message();
    DIR *dir = opendir(HIAUDIT_CONFIG.logPath.c_str());
    ASSERT_NE(dir, nullptr) << "open dir fail";
    closedir(dir);
    int fd = open(HIAUDIT_LOG_NAME.c_str(), O_CREAT | O_APPEND | O_RDWR, 0644);
    ASSERT_GT(fd, 0) << "create file fail " << strerror(errno);
    close(fd);
    BackupHiAudit &audit = BackupHiAudit::GetInstance();
    EXPECT_GT(audit.writeFd_, 0);
    struct stat st;
    ASSERT_EQ(stat(HIAUDIT_LOG_NAME.c_str(), &st), 0);
    MEDIA_INFO_LOG("HiAuditTest_DirectoryExists_test_001 end");
}

HWTEST_F(HiAuditTest, HiAuditTest_DirectoryNotExists_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_DirectoryNotExists_test_002 begin");
    std::error_code errcode;
    std::string nonExistPath = "/data/storage/el2/log/audit_nonexist/";
    if (std::filesystem::exists(nonExistPath)) {
        std::filesystem::remove_all(nonExistPath, errcode);
    }

    HiAuditConfig tempConfig = { nonExistPath, "media_library", 2 * 1024, 3 * 1024 * 1024, 10 };
    std::string tempLogName = tempConfig.logPath + tempConfig.logName + "_audit.csv";

    DIR *dir = opendir(tempConfig.logPath.c_str());
    ASSERT_EQ(dir, nullptr) << "dir is not exsit";
    if (dir != nullptr) {
        closedir(dir);
    }

    BackupHiAudit &audit = BackupHiAudit::GetInstance();

    dir = opendir(HIAUDIT_CONFIG.logPath.c_str());
    EXPECT_NE(dir, nullptr);
    if (dir != nullptr) {
        closedir(dir);
    }

    EXPECT_GT(audit.writeFd_, 0);
    MEDIA_INFO_LOG("HiAuditTest_DirectoryNotExists_test_002 end");
}

HWTEST_F(HiAuditTest, HiAuditTest_GetInstance_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_GetInstance_test_003 begin");
    BackupHiAudit &instance1 = BackupHiAudit::GetInstance();
    BackupHiAudit &instance2 = BackupHiAudit::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
    MEDIA_INFO_LOG("HiAuditTest_GetInstance_test_003 end");
}

HWTEST_F(HiAuditTest, HiAuditTest_GetMilliseconds_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_GetMilliseconds_test_004 begin");
    uint64_t time1 = BackupHiAudit::GetInstance().GetMilliseconds();

    usleep(10000);

    uint64_t time2 = BackupHiAudit::GetInstance().GetMilliseconds();

    EXPECT_GT(time2, time1);
    MEDIA_INFO_LOG("HiAuditTest_GetMilliseconds_test_004 end");
}

HWTEST_F(HiAuditTest, HiAuditTest_GetFormattedTimestamp_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_GetFormattedTimestamp_test_005 begin");
    time_t now = time(nullptr);
    std::string result = BackupHiAudit::GetInstance().GetFormattedTimestamp(now * 1000, "%Y%m%d%H%M%S");

    EXPECT_EQ(result.length(), 14); // YYYYMMDDHHMMSS

    for (char c : result) {
        EXPECT_TRUE(isdigit(c)) << "timestamp just include digit";
    }

    std::string result2 = BackupHiAudit::GetInstance().GetFormattedTimestamp(now * 1000, "%Y-%m-%d");
    EXPECT_EQ(result2.length(), 10); // YYYY-MM-DD
    EXPECT_EQ(result2[4], '-');
    EXPECT_EQ(result2[7], '-');

    MEDIA_INFO_LOG("HiAuditTest_GetFormattedTimestamp_test_005 end");
}
} // namespace Media
} // namespace OHOS