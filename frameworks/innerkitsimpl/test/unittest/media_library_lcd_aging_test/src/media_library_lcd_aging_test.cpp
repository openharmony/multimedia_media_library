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

#include "media_library_lcd_aging_test.h"

#include "lcd_aging_manager.h"
#include "lcd_aging_utils.h"
#include "lcd_aging_worker.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "exif_rotate_utils.h"
#include "userfile_manager_types.h"

#include "ithumbnail_helper.h"
#include "media_file_utils.h"
#include "media_upgrade.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "thumbnail_source_loading.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS;
using namespace::testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static int64_t g_id;
const int64_t DATE_TAKEN_TEST_VALUE = 1756111539577;
const string TEST_IMAGE_PATH = "/storage/cloud/files/Photo/1/CreateImageThumbnailTest_001.jpg";
const int64_t THUMB_DENTRY_SIZE = 2 * 1024 * 1024;
const std::string FILE_NAME_LCD = "LCD.jpg";

class TddRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return E_OK;
    }
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

static void InitRdbStore()
{
    const string dbPath = "/data/test/medialibrary_thumbnail_rdb_utils_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    TddRdbOpenCallback openCallback;

    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, openCallback);
    ASSERT_EQ(ret, E_OK);
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);

    ret = g_rdbStore->ExecuteSql(PhotoUpgrade::CREATE_PHOTO_TABLE);
    ASSERT_EQ(ret, NativeRdb::E_OK);

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, 0);
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, DATE_TAKEN_TEST_VALUE);
    ret = g_rdbStore->Insert(g_id, PhotoColumn::PHOTOS_TABLE, values);
    ASSERT_EQ(ret, NativeRdb::E_OK);
}

static void DeleteRdbStore()
{
    string dropSql = "DROP TABLE IF EXISTS " + PhotoColumn::PHOTOS_TABLE + ";";
    int32_t ret = g_rdbStore->ExecuteSql(dropSql);
    MEDIA_INFO_LOG("Drop photos table ret: %{public}d", ret == NativeRdb::E_OK);
    MediaLibraryUnitTestUtils::StopUnistore();
}

void MediaLibraryLcdAgingTest::SetUpTestCase(void)
{
    InitRdbStore();
}

void MediaLibraryLcdAgingTest::TearDownTestCase(void)
{
    DeleteRdbStore();
}

void MediaLibraryLcdAgingTest::SetUp()
{
    LcdAgingUtils::maxLcdNumber_ = -1;
    LcdAgingUtils::scaleLcdNumber_ = -1;
}

void MediaLibraryLcdAgingTest::TearDown(void) {}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetMaxThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_GetMaxThresholdOfLcd_test_001: test get max threshold");
    ThumbRdbOpt opts;
    ThumbnailData data;
    opts.store = g_rdbStore;
    opts.table = PhotoColumn::PHOTOS_TABLE;
    data.id = std::to_string(g_id);
    data.path = TEST_IMAGE_PATH;
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    bool result = IThumbnailHelper::DoCreateLcdAndThumbnail(opts, data);
    EXPECT_EQ(result, true);

    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetMaxThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 20000);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetMaxThresholdOfLcd_Cached_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_GetMaxThresholdOfLcd_Cached_test_002: test return cached maxLcdNumber");
    LcdAgingUtils::maxLcdNumber_ = 50000;
    
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetMaxThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(lcdNumber, 50000);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetScaleThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_GetScaleThresholdOfLcd_test_001: test get scale threshold of lcd");
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 15999);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetScaleThresholdOfLcd_Cached_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_GetScaleThresholdOfLcd_Cached_test_002: test return cached scaleLcdNumber");
    LcdAgingUtils::scaleLcdNumber_ = 40000;
    
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(lcdNumber, 40000);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetScaleThresholdOfLcd_Calculate_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_GetScaleThresholdOfLcd_Calculate_test_003: test scale threshold calculation");
    LcdAgingUtils::maxLcdNumber_ = 50000;
    LcdAgingUtils::scaleLcdNumber_ = -1;
    
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(lcdNumber, static_cast<int64_t>(50000 * 0.8));
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_ConvertAgingFileToDentryFile_Single_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_ConvertAgingFileToDentryFile_Single_test_002: test convert single aging file");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.fileId = 1;
    agingFileInfo.cloudId = "test_cloud_id_001";
    agingFileInfo.path = "/storage/cloud/files/Photo/test.jpg";
    agingFileInfo.localLcdPath = "/storage/cloud/files/.thumbs/Photo/LCD/test.jpg";
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 0;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::TOP_LEFT);
    agingFileInfo.dateModified = 1234567890;
    agingFileInfo.lcdFileSize = 102400;
    agingFileInfo.hasExThumbnail = false;
    
    vector<LcdAgingFileInfo> agingFileInfos = {agingFileInfo};
    
    auto dentryFileInfos = LcdAgingUtils().ConvertAgingFileToDentryFile(agingFileInfos);
    EXPECT_EQ(dentryFileInfos.size(), 1);
    EXPECT_EQ(dentryFileInfos[0].cloudId, "test_cloud_id_001");
    EXPECT_EQ(dentryFileInfos[0].path, "/storage/cloud/files/Photo/test.jpg");
    EXPECT_EQ(dentryFileInfos[0].size, THUMB_DENTRY_SIZE);
    EXPECT_EQ(dentryFileInfos[0].modifiedTime, 1234567890);
    EXPECT_EQ(dentryFileInfos[0].fileName, FILE_NAME_LCD);
    EXPECT_EQ(dentryFileInfos[0].fileType, "LCD");
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_ConvertAgingFileToDentryFile_ExThumbnail_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_ConvertAgingFileToDentryFile_ExThumbnail_test_003: test convert single aging ex file");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.fileId = 2;
    agingFileInfo.cloudId = "test_cloud_id_002";
    agingFileInfo.path = "/storage/cloud/files/Photo/test2.jpg";
    agingFileInfo.localLcdPath = "/storage/cloud/files/.thumbs/Photo/LCD/test2.jpg";
    agingFileInfo.localLcdExPath = "/storage/cloud/files/.thumbs/Photo/LCD_EX/test2.jpg";
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 90;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::RIGHT_TOP);
    agingFileInfo.dateModified = 1234567891;
    agingFileInfo.lcdFileSize = 204800;
    agingFileInfo.hasExThumbnail = true;
    
    vector<LcdAgingFileInfo> agingFileInfos = {agingFileInfo};
    
    auto dentryFileInfos = LcdAgingUtils().ConvertAgingFileToDentryFile(agingFileInfos);
    EXPECT_EQ(dentryFileInfos.size(), 1);
    EXPECT_EQ(dentryFileInfos[0].cloudId, "test_cloud_id_002");
    EXPECT_EQ(dentryFileInfos[0].path, "/storage/cloud/files/Photo/test2.jpg");
    EXPECT_EQ(dentryFileInfos[0].size, THUMB_DENTRY_SIZE);
    EXPECT_EQ(dentryFileInfos[0].modifiedTime, 1234567891);
    EXPECT_EQ(dentryFileInfos[0].fileName, FILE_NAME_LCD);
    EXPECT_EQ(dentryFileInfos[0].fileType, "THM_EX/LCD");
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_HasExThumbnail_ImageWithOrientation_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_HasExThumbnail_ImageWithOrientation_test_001: test has ex thumbnail");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 90;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::TOP_LEFT);
    
    bool result = LcdAgingUtils().HasExThumbnail(agingFileInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_HasExThumbnail_ImageWithExifRotate_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_HasExThumbnail_ImageWithExifRotate_test_002: test has ex thumbnail");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 0;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::RIGHT_TOP);
    
    bool result = LcdAgingUtils().HasExThumbnail(agingFileInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_HasExThumbnail_ImageNoRotate_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_HasExThumbnail_ImageNoRotate_test_003: test no ex thumbnail for image without rotation");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 0;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::TOP_LEFT);
    
    bool result = LcdAgingUtils().HasExThumbnail(agingFileInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_HasExThumbnail_Video_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_HasExThumbnail_Video_test_004: test no ex thumbnail for video type");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO);
    agingFileInfo.orientation = 90;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::RIGHT_TOP);
    
    bool result = LcdAgingUtils().HasExThumbnail(agingFileInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_ConvertAgingFileToDentryFile_AllFields_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_ConvertAgingFileToDentryFile_AllFields_test_005: test convert with all fields populated");
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.fileId = 999;
    agingFileInfo.cloudId = "test_cloud_id_full";
    agingFileInfo.path = "/storage/cloud/files/Photo/full_test.jpg";
    agingFileInfo.localLcdPath = "/storage/cloud/files/.thumbs/Photo/LCD/full_test.jpg";
    agingFileInfo.localLcdExPath = "/storage/cloud/files/.thumbs/Photo/LCD_EX/full_test.jpg";
    agingFileInfo.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    agingFileInfo.orientation = 90;
    agingFileInfo.exifRotate = static_cast<int32_t>(ExifRotateType::RIGHT_TOP);
    agingFileInfo.thumbnailReady = 1;
    agingFileInfo.dateModified = 9999999999;
    agingFileInfo.lcdFileSize = 999999;
    agingFileInfo.needFixLcdFileSize = true;
    agingFileInfo.hasExThumbnail = true;
    
    vector<LcdAgingFileInfo> agingFileInfos = {agingFileInfo};
    
    auto dentryFileInfos = LcdAgingUtils().ConvertAgingFileToDentryFile(agingFileInfos);
    EXPECT_EQ(dentryFileInfos.size(), 1);
    EXPECT_EQ(dentryFileInfos[0].cloudId, "test_cloud_id_full");
    EXPECT_EQ(dentryFileInfos[0].path, "/storage/cloud/files/Photo/full_test.jpg");
    EXPECT_EQ(dentryFileInfos[0].size, THUMB_DENTRY_SIZE);
    EXPECT_EQ(dentryFileInfos[0].modifiedTime, 9999999999);
    EXPECT_EQ(dentryFileInfos[0].fileName, FILE_NAME_LCD);
    EXPECT_EQ(dentryFileInfos[0].fileType, "THM_EX/LCD");
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_ClearNotAgingFileIds_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_ClearNotAgingFileIds_test_001: test clear not aging file ids");
    auto& manager = LcdAgingManager::GetInstance();
    manager.notAgingFileIds_.push_back("1");
    manager.notAgingFileIds_.push_back("2");
    manager.notAgingFileIds_.push_back("3");
    manager.ClearNotAgingFileIds();
    EXPECT_TRUE(manager.notAgingFileIds_.empty());
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_GetFileIdFromAgingFiles_Single_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_GetFileIdFromAgingFiles_Single_test_002: test get file ids");
    auto& manager = LcdAgingManager::GetInstance();
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.fileId = 100;
    
    vector<LcdAgingFileInfo> agingFileInfos = {agingFileInfo};
    auto fileIds = manager.GetFileIdFromAgingFiles(agingFileInfos);
    
    EXPECT_EQ(fileIds.size(), 1);
    EXPECT_EQ(fileIds[0], "100");
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_DeleteLocalFile_EmptyPath_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_DeleteLocalFile_EmptyPath_test_001: test delete file with empty path");
    auto& manager = LcdAgingManager::GetInstance();
    int32_t ret = manager.DeleteLocalFile("");
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_DeleteLocalFile_NonExistent_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_DeleteLocalFile_NonExistent_test_002: test delete non-existent file");
    auto& manager = LcdAgingManager::GetInstance();
    int32_t ret = manager.DeleteLocalFile("/data/test/non_existent_file.jpg");
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_FinishAgingTask_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_FinishAgingTask_test_001: test finish aging task clears all state");
    auto& manager = LcdAgingManager::GetInstance();
    manager.isInAgingPeriod_.store(true);
    manager.hasAgingLcdNumber_ = 1000;
    manager.notAgingFileIds_.push_back("1");
    manager.notAgingFileIds_.push_back("2");
    
    int32_t ret = manager.FinishAgingTask();
    
    EXPECT_EQ(ret, 1);
    EXPECT_FALSE(manager.isInAgingPeriod_.load());
    EXPECT_EQ(manager.hasAgingLcdNumber_, 0);
    EXPECT_TRUE(manager.notAgingFileIds_.empty());
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_UpdateLastLcdAgingEndTime_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_UpdateLastLcdAgingEndTime_test_001: test update last lcd aging end time");
    auto& manager = LcdAgingManager::GetInstance();
    int64_t newTime = 1234567890;
    manager.UpdateLastLcdAgingEndTime(newTime);
    
    int64_t endTime = manager.GetLastLcdAgingEndTime();
    EXPECT_EQ(endTime, newTime);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_DelayLcdAgingTime_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_DelayLcdAgingTime_test_001: test delay lcd aging time");
    auto& manager = LcdAgingManager::GetInstance();
    int64_t oldTime = manager.GetLastLcdAgingEndTime();
    
    manager.DelayLcdAgingTime();
    
    int64_t newTime = manager.GetLastLcdAgingEndTime();
    EXPECT_GE(newTime, oldTime);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_ReadyAgingLcd_AlreadyInPeriod_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_ReadyAgingLcd_AlreadyInPeriod_test_001: test ready aging lcd when already");
    auto& manager = LcdAgingManager::GetInstance();
    manager.isInAgingPeriod_.store(true);
    
    int32_t ret = manager.ReadyAgingLcd();
    EXPECT_EQ(ret, E_OK);
    
    manager.isInAgingPeriod_.store(false);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_BatchAgingLcdFileTask_StatusOff_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_BatchAgingLcdFileTask_StatusOff_test_001: test batch aging lcd file task");
    auto& manager = LcdAgingManager::GetInstance();
    LcdAgingWorker::GetInstance().isThreadRunning_.store(false);
    
    int32_t ret = manager.BatchAgingLcdFileTask();
    EXPECT_EQ(ret, 2);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_CheckLocalLcd_EmptyPath_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_CheckLocalLcd_EmptyPath_test_001: test check local lcd with empty path");
    auto& manager = LcdAgingManager::GetInstance();
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.localLcdPath = "";
    agingFileInfo.hasExThumbnail = false;
    
    bool result = manager.CheckLocalLcd(agingFileInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_CheckLocalLcd_NonExistent_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_CheckLocalLcd_NonExistent_test_002: test check local lcd with non-existent file");
    auto& manager = LcdAgingManager::GetInstance();
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.localLcdPath = "/data/test/non_existent_lcd.jpg";
    agingFileInfo.hasExThumbnail = false;
    
    bool result = manager.CheckLocalLcd(agingFileInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_GetLcdAgingFileInfo_EmptyInput_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_GetLcdAgingFileInfo_EmptyInput_test_001: test get lcd aging file info ");
    auto& manager = LcdAgingManager::GetInstance();
    vector<PhotosPo> photos;
    
    auto agingFileInfos = manager.GetLcdAgingFileInfo(photos);
    EXPECT_TRUE(agingFileInfos.empty());
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_DeleteLocalLcdFiles_WithFailCloudIds_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_DeleteLocalLcdFiles_WithFailCloudIds_test_002: test delete local lcd files");
    auto& manager = LcdAgingManager::GetInstance();
    vector<LcdAgingFileInfo> agingFileInfos;
    
    LcdAgingFileInfo info;
    info.fileId = 1;
    info.cloudId = "failed_cloud_id";
    info.localLcdPath = "/data/test/lcd.jpg";
    info.localLcdExPath = "/data/test/lcd_ex.jpg";
    info.hasExThumbnail = false;
    agingFileInfos.push_back(info);
    
    vector<string> failCloudIds = {"failed_cloud_id"};
    vector<string> failFileIds;
    
    manager.DeleteLocalLcdFiles(agingFileInfos, failCloudIds, failFileIds);
    
    EXPECT_EQ(failFileIds.size(), 1);
    EXPECT_EQ(failFileIds[0], "1");
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_RegenerateAstcWithLocal_NotNeeded_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_RegenerateAstcWithLocal_NotNeeded_test_001: test regenerate astc not needed");
    auto& manager = LcdAgingManager::GetInstance();
    LcdAgingFileInfo agingFileInfo;
    agingFileInfo.fileId = 1;
    agingFileInfo.path = "/storage/cloud/files/Photo/test.jpg";
    agingFileInfo.thumbnailReady = 0;
    
    int32_t ret = manager.RegenerateAstcWithLocal(agingFileInfo);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_DoBatchAgingLcdFile_EmptyInput_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_DoBatchAgingLcdFile_EmptyInput_test_001: test do batch aging lcd file");
    auto& manager = LcdAgingManager::GetInstance();
    vector<PhotosPo> lcdAgingPoList;
    int64_t agingSuccessSize = 0;
    
    int32_t ret = manager.DoBatchAgingLcdFile(lcdAgingPoList, agingSuccessSize);
    EXPECT_EQ(ret, E_ERR);
    EXPECT_EQ(agingSuccessSize, 0);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_manager_StateReset_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_manager_StateReset_test_001: test reset manager state after operations");
    auto& manager = LcdAgingManager::GetInstance();
    
    manager.isInAgingPeriod_.store(true);
    manager.hasAgingLcdNumber_ = 500;
    manager.notAgingFileIds_.push_back("100");
    manager.notAgingFileIds_.push_back("200");
    
    manager.FinishAgingTask();
    
    EXPECT_FALSE(manager.isInAgingPeriod_.load());
    EXPECT_EQ(manager.hasAgingLcdNumber_, 0);
    EXPECT_TRUE(manager.notAgingFileIds_.empty());
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_worker_IsRunning_InitiallyFalse_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_worker_IsRunning_InitiallyFalse_test_001: test is running returns false initially");
    auto& worker = LcdAgingWorker::GetInstance();
    worker.isThreadRunning_.store(false);
    
    bool running = worker.IsRunning();
    EXPECT_FALSE(running);
}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_worker_HandleLcdAgingTask_StatusOff_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("lcd_aging_worker_HandleLcdAgingTask_StatusOff_test_001: test handle task when status is off");
    auto& worker = LcdAgingWorker::GetInstance();
    worker.isThreadRunning_.store(true);
    
    worker.HandleLcdAgingTask();
    
    EXPECT_FALSE(worker.isThreadRunning_.load());
}

} // namespace Media
} // namespace OHOS