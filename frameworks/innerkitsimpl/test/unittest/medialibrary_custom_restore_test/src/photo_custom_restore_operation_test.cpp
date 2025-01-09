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

#define private public
#define MLOG_TAG "CustomRestoreCallbackUnitTest"

#include <gtest/gtest.h>

#include "media_log.h"
#include "photo_custom_restore_operation.h"
#include "medialibrary_errno.h"

using namespace testing;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class PhotoCustomRestoreOperationTest : public testing::Test {
std::string testPath = "/data/test/PhotoCustomRestoreOperationTest";
public:
    // input testsuit setup step，setup invoked before all testcases
    static void SetUpTestCase(void);
    // input testsuit teardown step，teardown invoked after all testcases
    static void TearDownTestCase(void);
    // input testcase setup step，setup invoked before each testcases
    void SetUp();
    // input testcase teardown step，teardown invoked after each testcases
    void TearDown();
};

void PhotoCustomRestoreOperationTest::SetUpTestCase(void) {}

void PhotoCustomRestoreOperationTest::TearDownTestCase(void) {}

void PhotoCustomRestoreOperationTest::SetUp(void) {}

void PhotoCustomRestoreOperationTest::TearDown(void) {}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_001 Start");
    PhotoCustomRestoreOperation::GetInstance();
    PhotoCustomRestoreOperation::GetInstance();
    EXPECT_EQ(PhotoCustomRestoreOperation::instance_ != nullptr, true);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_001 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_002 Start");
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.isRunning_.store(false);
    operatorObj.Start();
    EXPECT_EQ(operatorObj.isRunning_, false);
    operatorObj.isRunning_.store(true);
    operatorObj.Start();
    EXPECT_EQ(operatorObj.isRunning_, true);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_002 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_003 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    RestoreTaskInfo restoreTaskInfo2;
    restoreTaskInfo2.keyPath = "restoreTaskInfo2";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.AddTask(restoreTaskInfo);
    operatorObj.AddTask(restoreTaskInfo2);
    operatorObj.cancelKeySet.insert("restoreTaskInfo2");
    operatorObj.Start();
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_003 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_004 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    RestoreTaskInfo restoreTaskInfo2;
    restoreTaskInfo2.keyPath = "restoreTaskInfo2";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.isRunning_.store(true);
    operatorObj.AddTask(restoreTaskInfo);
    operatorObj.AddTask(restoreTaskInfo2);
    operatorObj.cancelKeySet.insert("restoreTaskInfo2");
    operatorObj.Start();
    EXPECT_EQ(operatorObj.isRunning_, true);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_004 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_005 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.CancelTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), true);
    operatorObj.CancelTaskFinish(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_005 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_006 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.ApplyEfficiencyQuota(1);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_006 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_007 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.AddTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_007 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_008 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.AddTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_008 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_008 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.DoCustomRestore(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_008 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_010 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.ReleaseCustomRestoreTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_010 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_011 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.ReportCustomRestoreTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_011 End");
}

HWTEST_F(PhotoCustomRestoreOperationTest, Photo_Custom_Restore_Operation_Test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_012 Start");
    RestoreTaskInfo restoreTaskInfo;
    restoreTaskInfo.keyPath = "restoreTaskInfo";
    PhotoCustomRestoreOperation &operatorObj = PhotoCustomRestoreOperation ::GetInstance();
    operatorObj.ReportCustomRestoreTask(restoreTaskInfo);
    EXPECT_EQ(operatorObj.IsCancelTask(restoreTaskInfo), false);
    MEDIA_INFO_LOG("Photo_Custom_Restore_Operation_Test_012 End");
}
}
}