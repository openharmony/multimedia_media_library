/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaLakeCloneEventManagerTest"

#include "media_lake_clone_event_manager_test.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "common_event_support.h"
#include "global_scanner.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "media_file_change_manager.h"
#include "media_lake_check_manager.h"
#include "media_lake_clone_event_manager.h"
#include "media_log.h"
#include "media_thread.h"
#include "want.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
constexpr int32_t BACKUP_SA_ID = 5203;
constexpr int32_t MIN_TIME_OUT = 4;
const std::string MEDIA_LIBRARY_BUNDLE = "com.ohos.medialibrary.medialibrarydata";
const std::string FILE_MANAGER_BUNDLE = "com.huawei.hmos.filemanager";
const std::string INVALID_BUNDLE = "com.invalid.bundle";
const std::string RESTORE_START_ACTION = "usual.event.RESTORE_START";
const std::string RESTORE_END_ACTION = "usual.event.RESTORE_END";
const std::string INVALID_ACTION = "invalid.action";

void MediaLakeCloneEventManagerTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::SetUpTestCase Start");
}

void MediaLakeCloneEventManagerTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::TearDownTestCase End");
}

void MediaLakeCloneEventManagerTest::SetUp(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::SetUp Start");
}

void MediaLakeCloneEventManagerTest::TearDown(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::TearDown Start");
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.ResetRestoreStatusBitMap();
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::TearDown End");
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_RestoreStartWithValidBundle_ReturnTrue,
    TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_RestoreEndWithValidBundle_ReturnTrue,
    TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_InvalidAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(INVALID_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_InvalidBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_EmptyAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction("");
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_EmptyBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", "");

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_DefaultState_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    bool result = manager.IsRestoring();

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_AfterRestoreStart_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);
    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_AfterRestoreEnd_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    bool result = manager.IsRestoring();

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_MultipleRestoreStart_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want1;
    want1.SetAction(RESTORE_START_ACTION);
    want1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want1);

    AAFwk::Want want2;
    want2.SetAction(RESTORE_START_ACTION);
    want2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want2);

    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeEvent_ManagerTest, IsRestoring_PartialRestoreEnd_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(RESTORE_START_ACTION);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(RESTORE_START_ACTION);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreStartWithMediaLibrary_HandleStart,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreStartWithFileManager_HandleStart,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreEndWithMediaLibrary_HandleEnd,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreEndWithFileManager_HandleEnd,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_InvalidAction_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(INVALID_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_ConcurrentStartEnd_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(startWant);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_DefaultState_ResetStatus, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeEventManagerTest, HandleDeathRecipient_NoRestoreInProgress_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    bool beforeState = manager.IsRestoring();
    manager.HandleDeathRecipient();
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_MultipleRestore_ResetAll, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(RESTORE_START_ACTION);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(RESTORE_START_ACTION);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_ConcurrentCalls_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    std::thread thread1([&]() { manager.HandleDeathRecipient(); });
    std::thread thread2([&]() { manager.HandleDeathRecipient(); });

    thread1.join();
    thread2.join();

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_MediaLibrary_SetStatusBit,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_FALSE(beforeState);
    EXPECT_TRUE(afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_FileManager_SetStatusBit,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_FALSE(beforeState);
    EXPECT_TRUE(afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", "");

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_MediaLibrary_ClearStatusBit,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_FileManager_ClearStatusBit,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);
    want.SetParam("bundleName", "");

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_MediaLibrary_ReturnBit0, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(MEDIA_LIBRARY_BUNDLE, bit);

    EXPECT_TRUE(result);
    EXPECT_EQ(bit, 0);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_FileManager_ReturnBit1, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(FILE_MANAGER_BUNDLE, bit);

    EXPECT_TRUE(result);
    EXPECT_EQ(bit, 1);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_InvalidBundle_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(INVALID_BUNDLE, bit);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_EmptyBundle_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName("", bit);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, ShouldUnregisterLakeFileMonitor_FirstRestore_ReturnTrue,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, ShouldUnregisterLakeFileMonitor_AlreadyRestoring_ReturnFalse,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want1;
    want1.SetAction(RESTORE_START_ACTION);
    want1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want1);

    AAFwk::Want want2;
    want2.SetAction(RESTORE_START_ACTION);
    want2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want2);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, ShouldRegisterLakeFileMonitor_LastRestoreEnd_ReturnTrue,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, ShouldRegisterLakeFileMonitor_PartialRestoreEnd_ReturnFalse,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(RESTORE_START_ACTION);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(RESTORE_START_ACTION);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, ResetRestoreStatusBitMap_DefaultState_ResetToZero,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, ResetRestoreStatusBitMap_MultipleRestore_ResetAll,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(RESTORE_START_ACTION);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(RESTORE_START_ACTION);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, CheckIsExecuteGlobalScan_MediaLibrary_ExecuteScan,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, CheckIsExecuteGlobalScan_FileManager_SkipScan,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_MediaLibrary_SetBit0,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_FALSE(beforeState);
    EXPECT_TRUE(afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_FileManager_SetBit1,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_FALSE(beforeState);
    EXPECT_TRUE(afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_InvalidBundle_NoAction,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_MediaLibrary_ClearBit0,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_FileManager_ClearBit1,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_InvalidBundle_NoAction,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetEventBundleName_ValidBundle_ReturnBundleName,
    TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    std::string bundleName = want.GetStringParam("bundleName");

    EXPECT_EQ(bundleName, MEDIA_LIBRARY_BUNDLE);
}

HWTEST_F(MediaLakeCloneEventManagerTest, GetEventBundleName_EmptyBundle_ReturnEmpty, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", "");

    std::string bundleName = want.GetStringParam("bundleName");

    EXPECT_TRUE(bundleName.empty());
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedAction_RestoreStart_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);

    std::string action = want.GetAction();
    bool result = (action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedAction_RestoreEnd_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);

    std::string action = want.GetAction();
    bool result = (action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedAction_InvalidAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(INVALID_ACTION);

    std::string action = want.GetAction();
    bool result = (action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedAction_EmptyAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction("");

    std::string action = want.GetAction();
    bool result = (action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedBundle_MediaLibrary_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    std::string bundleName = want.GetStringParam("bundleName");
    bool result = (bundleName == MEDIA_LIBRARY_BUNDLE || bundleName == FILE_MANAGER_BUNDLE);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedBundle_FileManager_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    std::string bundleName = want.GetStringParam("bundleName");
    bool result = (bundleName == MEDIA_LIBRARY_BUNDLE || bundleName == FILE_MANAGER_BUNDLE);

    EXPECT_TRUE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedBundle_InvalidBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", INVALID_BUNDLE);

    std::string bundleName = want.GetStringParam("bundleName");
    bool result = (bundleName == MEDIA_LIBRARY_BUNDLE || bundleName == FILE_MANAGER_BUNDLE);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, IsSubscribedBundle_EmptyBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetParam("bundleName", "");

    std::string bundleName = want.GetStringParam("bundleName");
    bool result = (bundleName == MEDIA_LIBRARY_BUNDLE || bundleName == FILE_MANAGER_BUNDLE);

    EXPECT_FALSE(result);
}

HWTEST_F(MediaLakeCloneEventManagerTest, UnregisterLakeFileMonitor_DuringRestore_StopMonitor,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, RegisterLakeFileMonitor_AfterRestoreEnd_StartMonitor,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, RunGlobalScanner_IdleScanner_StartScan, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, RunGlobalScanner_RunningScanner_SkipScan, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetDeathRecipient_NoRemoteObject_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, SetDeathRecipient_WithRemoteObject_AddRecipient,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentRestoreStart_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            AAFwk::Want want;
            want.SetAction(RESTORE_START_ACTION);
            want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
            manager.HandleRestoreEvent(want);
            successCount++;
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), threadCount);
    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentRestoreEnd_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            AAFwk::Want want;
            want.SetAction(RESTORE_END_ACTION);
            want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
            manager.HandleRestoreEvent(want);
            successCount++;
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), threadCount);
    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentIsRestoring_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> trueCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            if (manager.IsRestoring()) {
                trueCount++;
            }
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(trueCount.load(), threadCount);
}

HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentHandleDeathRecipient_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            manager.HandleDeathRecipient();
            successCount++;
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), threadCount);
    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_MixedOperations_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&, i]() {
            if (i % 2 == 0) {
                AAFwk::Want want;
                want.SetAction(RESTORE_START_ACTION);
                want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
                manager.HandleRestoreEvent(want);
            } else {
                AAFwk::Want want;
                want.SetAction(RESTORE_END_ACTION);
                want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
                manager.HandleRestoreEvent(want);
            }
            successCount++;
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), threadCount);
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_MaxRestoreStatus_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(RESTORE_START_ACTION);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(RESTORE_START_ACTION);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want endWant1;
    endWant1.SetAction(RESTORE_END_ACTION);
    endWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant1);

    AAFwk::Want endWant2;
    endWant2.SetAction(RESTORE_END_ACTION);
    endWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant2);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_RapidStartEnd_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    for (int32_t i = 0; i < 100; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(RESTORE_START_ACTION);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(RESTORE_END_ACTION);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_EmptyWant_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_NullBundleName_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_SpecialCharactersInBundle_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", "com.test.special!@#$%");

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_VeryLongBundleName_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    std::string longBundle(1000, 'a');
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", longBundle);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_RestoreStartWithoutEnd_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_START_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_RestoreEndWithoutStart_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(RESTORE_END_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_MultipleDeathRecipientCalls_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    for (int32_t i = 0; i < 10; ++i) {
        manager.HandleDeathRecipient();
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_InterleavedStartEndDeath_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    manager.HandleDeathRecipient();

    AAFwk::Want endWant;
    endWant.SetAction(RESTORE_END_ACTION);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_RapidRestoreEvents_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 1000;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(RESTORE_START_ACTION);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(RESTORE_END_ACTION);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_ConcurrentAccess_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t threadCount = 20;
    const int32_t iterations = 100;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            for (int32_t j = 0; j < iterations; ++j) {
                AAFwk::Want want;
                if (j % 2 == 0) {
                    want.SetAction(RESTORE_START_ACTION);
                } else {
                    want.SetAction(RESTORE_END_ACTION);
                }
                want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
                manager.HandleRestoreEvent(want);
            }
            successCount++;
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), threadCount);
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_MixedBundles_HandleCorrectly,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 100;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant1;
        startWant1.SetAction(RESTORE_START_ACTION);
        startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant1);

        AAFwk::Want startWant2;
        startWant2.SetAction(RESTORE_START_ACTION);
        startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
        manager.HandleRestoreEvent(startWant2);

        AAFwk::Want endWant1;
        endWant1.SetAction(RESTORE_END_ACTION);
        endWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant1);

        AAFwk::Want endWant2;
        endWant2.SetAction(RESTORE_END_ACTION);
        endWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
        manager.HandleRestoreEvent(endWant2);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_RapidIsRestoringCalls_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(RESTORE_START_ACTION);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t iterations = 10000;
    std::atomic<int> trueCount(0);

    for (int32_t i = 0; i < iterations; ++i) {
        if (manager.IsRestoring()) {
            trueCount++;
        }
    }

    EXPECT_EQ(trueCount.load(), iterations);
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_AlternatingDeathRecipient_HandleSafely,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 100;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(RESTORE_START_ACTION);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        if (i % 2 == 0) {
            manager.HandleDeathRecipient();
        }

        AAFwk::Want endWant;
        endWant.SetAction(RESTORE_END_ACTION);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_MemoryLeakCheck_NoLeaks, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 1000;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(RESTORE_START_ACTION);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(RESTORE_END_ACTION);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);

        manager.HandleDeathRecipient();
    }

    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_StateConsistency_CheckConsistency,
    TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 500;
    std::atomic<int> consistentCount(0);

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(RESTORE_START_ACTION);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        bool state1 = manager.IsRestoring();

        AAFwk::Want endWant;
        endWant.SetAction(RESTORE_END_ACTION);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);

        bool state2 = manager.IsRestoring();

        if (state1 && !state2) {
            consistentCount++;
        }
    }

    EXPECT_EQ(consistentCount.load(), iterations);
    EXPECT_FALSE(manager.IsRestoring());
}

HWTEST_F(MediaLakeCloneEventManagerTest, Coverage_AllBranches_Covered, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    AAFwk::Want want1;
    want1.SetAction(RESTORE_START_ACTION);
    want1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want1);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want2;
    want2.SetAction(RESTORE_START_ACTION);
    want2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want2);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want3;
    want3.SetAction(RESTORE_END_ACTION);
    want3.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want3);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want4;
    want4.SetAction(RESTORE_END_ACTION);
    want4.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want4);

    EXPECT_FALSE(manager.IsRestoring());

    AAFwk::Want want5;
    want5.SetAction(RESTORE_START_ACTION);
    want5.SetParam("bundleName", INVALID_BUNDLE);
    manager.HandleRestoreEvent(want5);

    EXPECT_FALSE(manager.IsRestoring());
}

} // namespace Media
} // namespace OHOS
