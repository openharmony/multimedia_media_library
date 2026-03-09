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

#define MLOG_TAG "MediaCloudSync"

#include "media_background_task_factory_test.h"

#include "media_location_synchronize_task.h"
#include "power_efficiency_manager.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "cloud_sync_utils.h"
#include "cloud_media_photos_dao.h"
#include "result_set_reader.h"
#include "photos_po_writer.h"
#include "photos_po.h"
#include "cloud_media_scan_service.h"
#include "cloud_media_dao_utils.h"
#include "medialibrary_related_system_state_manager.h"

using namespace testing::ext;

namespace OHOS::Media::Background {
MediaBackgroundTaskFactory backgroundTaskFactory_;
void MediaBackgroundTaskFactoryTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
}

void MediaBackgroundTaskFactoryTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
}

void MediaBackgroundTaskFactoryTest::SetUp()
{}

void MediaBackgroundTaskFactoryTest::TearDown()
{}

HWTEST_F(MediaBackgroundTaskFactoryTest, MediaCloudSyncBackgroundTask_Test_001, TestSize.Level1)
{
    PowerEfficiencyManager::SetSubscriberStatus(true, true);
    backgroundTaskFactory_.Execute();
    EXPECT_EQ(true, backgroundTaskFactory_.Accept());
}

HWTEST_F(MediaBackgroundTaskFactoryTest, RepairPhotoLocation_EmptyPath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RepairPhotoLocation 方法，path 为空
    MediaLocationSynchronizeTask task;
    PhotosPo photoInfo;
    photoInfo.fileId = 100;
    photoInfo.path = "";
    int32_t repairRecord = 999;
    bool terminate = false;
    std::vector<PhotosPo> photosPoVec = {photoInfo};
    
    task.RepairPhotoLocation(repairRecord, terminate, photosPoVec);
    EXPECT_EQ(repairRecord, 100);
}

HWTEST_F(MediaBackgroundTaskFactoryTest, RepairPhotoLocation_ZeroPosition_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RepairPhotoLocation 方法，position <= 0
    MediaLocationSynchronizeTask task;
    PhotosPo photoInfo;
    photoInfo.fileId = 100;
    photoInfo.path = "/storage/test.jpg";
    photoInfo.position = 0;
    int32_t repairRecord = 999;
    bool terminate = false;
    std::vector<PhotosPo> photosPoVec = {photoInfo};
    
    task;RepairPhotoLocation(repairRecord, terminate, photosPoVec);
    EXPECT_EQ(repairRecord, 100);
}

HWTEST_F(MediaBackgroundTaskFactoryTest, RepairPhotoLocation_CloudPosition_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RepairPhotoLocation 方法，云位置且 WiFi 未连接
    MediaLocationSynchronizeTask task;
    PhotosPo photoInfo;
    photoInfo.fileId = 100;
    photoInfo.path = "/storage/test.jpg";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    int32_t repairRecord = 999;
    bool terminate = false;
    std::vector<PhotosPo> photosPoVec = {photoInfo};
    
    task.RepairPhotoLocation(repairRecord, terminate, photosPoVec);
    EXPECT_TRUE(terminate);
}

HWTEST_F(MediaBackgroundTaskFactoryTest, RepairPhotoLocation_StatusOff_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RepairPhotoLocation 方法，状态为 OFF
    MediaLocationSynchronizeTask task;
    PhotosPo photoInfo;
    photoInfo.fileId = 100;
    photoInfo.path = "/storage/test.jpg";
    photoInfo.position = 1;
    int32_t repairRecord = 999;
    bool terminate = false;
    std::vector<PhotosPo> photosPoVec = {photoInfo};
    
    task.RepairPhotoLocation(repairRecord, terminate, photosPoVec);
    EXPECT_TRUE(terminate);
}

HWTEST_F(MediaBackgroundTaskFactoryTest, RepairPhotoLocation_Success_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RepairPhotoLocation 方法，正常情况
    MediaLocationSynchronizeTask task;
    PhotosPo photoInfo;
    photoInfo.fileId = 100;
    photoInfo.path = "/storage/test.jpg";
    photoInfo.position = 1;
    int32_t repairRecord = 999;
    bool terminate = false;
    std::vector<PhotosPo> photosPoVec = {photoInfo};
    
    task.RepairPhotoLocation(repairRecord, terminate, photosPoVec);
    EXPECT_EQ(repairRecord, 100);
    EXPECT_FALSE(terminate);
}
}  // namespace OHOS::Media::CloudSync