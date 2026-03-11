/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "BackupAdaptersTest"

#include "backup_adapters_test.h"

#include <string>

#include "backup_adapters.h"
#include "backup_const.h"
#include "medialibrary_db_const.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {

void BackupAdaptersTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void BackupAdaptersTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void BackupAdaptersTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void BackupAdaptersTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_IsLakeFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_001 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    
    bool result = FileAdapter::IsLakeFile(fileInfo);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_001 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_IsLakeFile_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_002 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    
    bool result = FileAdapter::IsLakeFile(fileInfo);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_002 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_IsLakeFile_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_003 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "";
    
    bool result = FileAdapter::IsLakeFile(fileInfo);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_003 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_IsLakeFile_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_004 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    fileInfo.hidden = 1;
    
    bool result = FileAdapter::IsLakeFile(fileInfo);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("FileAdapter_IsLakeFile_Test_004 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_001 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_EQ(result, fileInfo.cloudPath);
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_001 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_002 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_EQ(result, fileInfo.storagePath);
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_002 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_003 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_EQ(result, fileInfo.cloudPath);
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_003 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_004 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA;
    fileInfo.storagePath = "";
    fileInfo.cloudPath = "";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_004 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_005 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = FileSourceType::MEDIA_HO_LAKE;
    fileInfo.storagePath = "";
    fileInfo.cloudPath = "";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_005 end");
}

HWTEST_F(BackupAdaptersTest, FileAdapter_GetOriginalFilePath_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_006 start");
    FileInfo fileInfo;
    fileInfo.fileSourceType = -1;
    fileInfo.storagePath = "/storage/emulated/0/Pictures/test.jpg";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    
    std::string result = FileAdapter::GetOriginalFilePath(fileInfo);
    EXPECT_EQ(result, fileInfo.cloudPath);
    MEDIA_INFO_LOG("FileAdapter_GetOriginalFilePath_Test_006 end");
}
}  // namespace OHOS::Media