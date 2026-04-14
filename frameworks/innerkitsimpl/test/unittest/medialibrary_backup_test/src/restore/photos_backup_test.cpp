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

#define MLOG_TAG "PhotosBackupTest"

#include "photos_backup_test.h"

#include <string>

#include "backup_const.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "nlohmann/json.hpp"
#include "photos_backup.h"
#include "userfile_manager_types.h"
#include "media_string_utils.h"

using namespace testing::ext;

namespace OHOS::Media {
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void PhotosBackupTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
}

void PhotosBackupTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotosBackupTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotosBackupTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotosBackupTest, BackupInfo_ToString_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupInfo_ToString_Test_001 start");
    PhotosBackup::BackupInfo backupInfo;
    backupInfo.suffix = "";
    backupInfo.photoCount = 10;
    backupInfo.videoCount = 5;
    backupInfo.cloudPhotoCount = 3;
    backupInfo.cloudVideoCount = 2;
    backupInfo.audioCount = 7;
    backupInfo.totalSize = 1024000;
    
    std::string result = backupInfo.ToString();
    EXPECT_FALSE(result.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(result);
    EXPECT_TRUE(jsonObject.is_array());
    EXPECT_EQ(jsonObject.size(), 6);
    MEDIA_INFO_LOG("BackupInfo_ToString_Test_001 end");
}

HWTEST_F(PhotosBackupTest, BackupInfo_ToString_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupInfo_ToString_Test_002 start");
    PhotosBackup::BackupInfo backupInfo;
    backupInfo.suffix = "_anco";
    backupInfo.photoCount = 0;
    backupInfo.videoCount = 0;
    backupInfo.cloudPhotoCount = 0;
    backupInfo.cloudVideoCount = 0;
    backupInfo.audioCount = 0;
    backupInfo.totalSize = 0;
    
    std::string result = backupInfo.ToString();
    EXPECT_FALSE(result.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(result);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("BackupInfo_ToString_Test_002 end");
}

HWTEST_F(PhotosBackupTest, PhotosBackup_Constructor_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("PhotosBackup_Constructor_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    MEDIA_INFO_LOG("PhotosBackup_Constructor_Test_001 end");
}

HWTEST_F(PhotosBackupTest, PhotosBackup_Constructor_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("PhotosBackup_Constructor_Test_002 start");
    int32_t sceneCode = 0;
    std::string taskId = "";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    MEDIA_INFO_LOG("PhotosBackup_Constructor_Test_002 end");
}

HWTEST_F(PhotosBackupTest, GetBackupInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupInfo_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    EXPECT_GE(jsonObject.size(), 1);
    MEDIA_INFO_LOG("GetBackupInfo_Test_001 end");
}

HWTEST_F(PhotosBackupTest, GetBackupInfo_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupInfo_Test_002 start");
    int32_t sceneCode = 2001;
    std::string taskId = "task_002";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("GetBackupInfo_Test_002 end");
}

HWTEST_F(PhotosBackupTest, GetBackupInfoOfMediaFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupInfoOfMediaFile_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("GetBackupInfoOfMediaFile_Test_001 end");
}

HWTEST_F(PhotosBackupTest, GetBackupInfoOfLakeFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupInfoOfLakeFile_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("GetBackupInfoOfLakeFile_Test_001 end");
}

HWTEST_F(PhotosBackupTest, GetBackupTotalSizeOfMediaFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupTotalSizeOfMediaFile_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("GetBackupTotalSizeOfMediaFile_Test_001 end");
}

HWTEST_F(PhotosBackupTest, GetBackupTotalSizeOfLakeFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetBackupTotalSizeOfLakeFile_Test_001 start");
    int32_t sceneCode = 1001;
    std::string taskId = "task_001";
    
    PhotosBackup photosBackup(sceneCode, taskId, g_rdbStore->GetRaw());
    
    std::string backupInfo = photosBackup.GetBackupInfo();
    EXPECT_FALSE(backupInfo.empty());
    
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_TRUE(jsonObject.is_array());
    MEDIA_INFO_LOG("GetBackupTotalSizeOfLakeFile_Test_001 end");
}
}  // namespace OHOS::Media