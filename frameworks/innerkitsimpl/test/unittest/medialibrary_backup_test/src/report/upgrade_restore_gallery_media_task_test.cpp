/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "UpgradeRestoreGalleryMediaTaskTest"

#include <string>
#include <thread>
#define private public
#define protected public
#include "upgrade_restore_gallery_media_task.h"
#undef private
#undef protected

#include "upgrade_restore_gallery_media_task_test.h"
#include "media_log.h"

using namespace testing::ext;
using namespace std;
namespace OHOS::Media {

void UpgradeRestoreGalleryMediaTaskTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void UpgradeRestoreGalleryMediaTaskTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void UpgradeRestoreGalleryMediaTaskTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void UpgradeRestoreGalleryMediaTaskTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(UpgradeRestoreGalleryMediaTaskTest, CallbackResultData_Check, TestSize.Level0)
{
    UpgradeRestoreGalleryMediaTask task;
    CallbackResultData resultData = task.ParseFromJsonStr(this->SQL_JSON_TASK_INFO);
    CallbackResultInfo &resultInfo = resultData.resultInfo;
    // ASSERT CallbackResultInfo
    EXPECT_EQ(resultInfo.errorCode, "13500099");
    EXPECT_EQ(resultInfo.errorInfo, "Move failed");
    EXPECT_EQ(resultInfo.type, "ErrorInfo");
    // ASSERT CallbackBackupInfo
    EXPECT_EQ(resultData.infos.size(), 3);
    // ASSERT CallbackBackupInfo - Photo
    CallbackBackupInfo photoInfo = resultData.infos[0];
    EXPECT_EQ(photoInfo.backupInfo, "photo");
    EXPECT_EQ(photoInfo.duplicateCount, 0);
    EXPECT_EQ(photoInfo.failedCount, 0);
    EXPECT_EQ(photoInfo.successCount, 318);
    // ASSERT CallbackBackupInfo - Video
    CallbackBackupInfo videoInfo = resultData.infos[1];
    EXPECT_EQ(videoInfo.backupInfo, "video");
    EXPECT_EQ(videoInfo.duplicateCount, 0);
    EXPECT_EQ(videoInfo.failedCount, 0);
    EXPECT_EQ(videoInfo.successCount, 29);
    // ASSERT CallbackBackupInfo - Audio
    CallbackBackupInfo audioInfo = resultData.infos[2];
    EXPECT_EQ(audioInfo.backupInfo, "audio");
    EXPECT_EQ(audioInfo.duplicateCount, 0);
    EXPECT_EQ(audioInfo.failedCount, 0);
    EXPECT_EQ(audioInfo.successCount, 0);
}

HWTEST_F(UpgradeRestoreGalleryMediaTaskTest, MediaRestoreResultInfo_Check, TestSize.Level0)
{
    UpgradeRestoreGalleryMediaTask task;
    CallbackResultData resultData = task.SetSceneCode(0).SetTaskId("abc").ParseFromJsonStr(this->SQL_JSON_TASK_INFO);
    std::vector<MediaRestoreResultInfo> resultInfo = task.Parse(resultData);
    // ASSERT MediaRestoreResultInfo
    EXPECT_EQ(resultInfo.size(), 3);
    // ASSERT MediaRestoreResultInfo - Photo
    MediaRestoreResultInfo photoInfo = resultInfo[0];
    EXPECT_EQ(photoInfo.sceneCode, 0);
    EXPECT_EQ(photoInfo.taskId, "abc");
    EXPECT_EQ(photoInfo.errorCode, "13500099");
    EXPECT_EQ(photoInfo.errorInfo, "Move failed");
    EXPECT_EQ(photoInfo.type, "ErrorInfo");
    EXPECT_EQ(photoInfo.backupInfo, "photo");
    EXPECT_EQ(photoInfo.duplicateCount, 0);
    EXPECT_EQ(photoInfo.failedCount, 0);
    EXPECT_EQ(photoInfo.successCount, 318);
    // ASSERT MediaRestoreResultInfo - Video
    MediaRestoreResultInfo videoInfo = resultInfo[1];
    EXPECT_EQ(videoInfo.sceneCode, 0);
    EXPECT_EQ(videoInfo.taskId, "abc");
    EXPECT_EQ(videoInfo.errorCode, "13500099");
    EXPECT_EQ(videoInfo.errorInfo, "Move failed");
    EXPECT_EQ(videoInfo.type, "ErrorInfo");
    EXPECT_EQ(videoInfo.backupInfo, "video");
    EXPECT_EQ(videoInfo.duplicateCount, 0);
    EXPECT_EQ(videoInfo.failedCount, 0);
    EXPECT_EQ(videoInfo.successCount, 29);
    // ASSERT MediaRestoreResultInfo - Audio
    MediaRestoreResultInfo audioInfo = resultInfo[2];
    EXPECT_EQ(audioInfo.sceneCode, 0);
    EXPECT_EQ(audioInfo.taskId, "abc");
    EXPECT_EQ(audioInfo.errorCode, "13500099");
    EXPECT_EQ(audioInfo.errorInfo, "Move failed");
    EXPECT_EQ(audioInfo.type, "ErrorInfo");
    EXPECT_EQ(audioInfo.backupInfo, "audio");
    EXPECT_EQ(audioInfo.duplicateCount, 0);
    EXPECT_EQ(audioInfo.failedCount, 0);
    EXPECT_EQ(audioInfo.successCount, 0);
}
}  // namespace OHOS::Media