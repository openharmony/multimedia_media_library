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

#include "log_utils_test.h"
#include "media_log.h"
#include "media_backup_report_data_type.h"

#define private public
#include "backup_log_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void LogUtilsTest::SetUpTestCase(void) {}

void LogUtilsTest::TearDownTestCase(void) {}

void LogUtilsTest::SetUp(void) {}

void LogUtilsTest::TearDown(void) {}

HWTEST_F(LogUtilsTest, FileInfo_To_String_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("FileInfo_To_String_Test_001 begin");
    FileInfo info = {
        .fileIdOld = 1001,
        .localMediaId = 1001,
        .fileSize = 1024,
        .fileType = 1,
        .displayName = "test.jpg",
        .packageName = "com.example.test",
        .oldPath = "/data/test.jpg"
    };
    std::vector<std::string> extendList = {"ext1", "ext2"};

    std::string result = BackupLogUtils::FileInfoToString(1001, info, extendList);
    EXPECT_FALSE(result.empty());
    MEDIA_INFO_LOG("FileInfo_To_String_Test_001 end");
}

HWTEST_F(LogUtilsTest, ErrorInfo_To_String_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("ErrorInfo_To_String_Test_001 begin");
    ErrorInfo info(0, 1, "failed", "test error");

    std::string result = BackupLogUtils::ErrorInfoToString(info);
    EXPECT_FALSE(result.empty());
    MEDIA_INFO_LOG("ErrorInfo_To_String_Test_001 end");
}

HWTEST_F(LogUtilsTest, Format_String_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Format_String_Test_001 begin");
    std::string input = "test\"string";
    std::string result = BackupLogUtils::Format(input);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("\"\""), std::string::npos);
    MEDIA_INFO_LOG("Format_String_Test_001 end");
}

HWTEST_F(LogUtilsTest, FileDbCheckInfo_To_String_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("FileDbCheckInfo_To_String_Test_001 begin");
    FileDbCheckInfo info(1, 1, 1);

    std::string result = BackupLogUtils::FileDbCheckInfoToString(info);
    EXPECT_FALSE(result.empty());
    MEDIA_INFO_LOG("FileDbCheckInfo_To_String_Test_001 end");
}
} // namespace Media
} // namespace OHOS