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

#include "zip_util_test.h"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <filesystem>

#include <iostream>
#include "media_log.h"
#include <fstream>

#include "backup_zip_util.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void ZipUtilTest::SetUpTestCase(void) {}

void ZipUtilTest::TearDownTestCase(void) {}

void ZipUtilTest::SetUp(void) {}

void ZipUtilTest::TearDown(void) {}

HWTEST_F(ZipUtilTest, Create_Zip_Test_001, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Create_Zip_Test_001 begin");
    std::string filePath = "/data/storage/el2/log/test.zip";
    zipFile compressZip = BackupZipUtil::CreateZipFile(filePath, 0);
    ASSERT_NE(compressZip, nullptr);
    BackupZipUtil::CloseZipFile(compressZip);
    MEDIA_INFO_LOG("Create_Zip_Test_001 end");
}

HWTEST_F(ZipUtilTest, Create_Zip_Test_002, testing::ext::TestSize.Level0)
{
    MEDIA_INFO_LOG("Create_Zip_Test_002 begin");
    std::string filePath = "/data/storage/el2/log/test.csv";
    std::ofstream file(filePath);
    ASSERT_EQ(file.is_open(), true);
    file.close();
    std::string zipFilePath = "/data/storage/el2/log/test.zip";
    zipFile compressZip = BackupZipUtil::CreateZipFile(zipFilePath);
    ASSERT_NE(compressZip, nullptr);
    int ret = BackupZipUtil::AddFileInZip(compressZip, filePath, KEEP_NONE_PARENT_PATH);
    EXPECT_EQ(ret, 0);
    BackupZipUtil::CloseZipFile(compressZip);
    MEDIA_INFO_LOG("Create_Zip_Test_002 end");
}
} // namespace Media
} // namespace OHOS