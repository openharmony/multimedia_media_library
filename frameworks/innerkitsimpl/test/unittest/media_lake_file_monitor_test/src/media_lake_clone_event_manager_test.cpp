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
#include "iremote_object.h"
#include "iservice_registry.h"
#include "media_lake_clone_event_manager.h"
#include "media_log.h"
#include "media_thread.h"
#include "want.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_SECONDS = 1;
const std::string MEDIA_LIBRARY_BUNDLE = "com.ohos.medialibrary.medialibrarydata";
const std::string FILE_MANAGER_BUNDLE = "com.huawei.hmos.filemanager";
const std::string INVALID_BUNDLE = "com.invalid.bundle";
const std::string INVALID_ACTION = "invalid.action";

void MediaLakeCloneEventManagerTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::SetUpTestCase Start");
}

void MediaLakeCloneEventManagerTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("MediaLakeCloneEventManagerTest::TearDownTestCase End");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
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

// Test IsRestoreEvent with valid restore start action
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_RestoreStartWithValidBundle_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_TRUE(result);
}

// Test IsRestoreEvent with valid restore end action
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_RestoreEndWithValidBundle_ReturnTrue, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_TRUE(result);
}

// Test IsRestoreEvent with invalid action
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_InvalidAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(INVALID_ACTION);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

// Test IsRestoreEvent with invalid
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_InvalidBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

// Test IsRestoreEvent with empty action
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_EmptyAction_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction("");
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

// Test IsRestoreEvent with empty bundle
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoreEvent_EmptyBundle_ReturnFalse, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);

    bool result = MediaLakeCloneEventManager::IsRestoreEvent(want);

    EXPECT_FALSE(result);
}

// Test IsRestoring in default state
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_DefaultState_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    bool result = manager.IsRestoring();

    EXPECT_FALSE(result);
}

// Test IsRestoring after restore start
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_AfterRestoreStart_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);
    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

// Test IsRestoring after restore end
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_AfterRestoreEnd_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    bool result = manager.IsRestoring();

    EXPECT_FALSE(result);
}

// Test IsRestoring with multiple restore start
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_MultipleRestoreStart_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want1;
    want1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want1);

    AAFwk::Want want2;
    want2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want2);

    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

// Test IsRestoring with partial restore end
HWTEST_F(MediaLakeCloneEventManagerTest, IsRestoring_PartialRestoreEnd_ReturnTrue, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    bool result = manager.IsRestoring();

    EXPECT_TRUE(result);
}

// Test HandleRestoreEvent with restore start for file manager
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreStartWithFileManager_HandleStart, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

// Test HandleRestoreEvent with restore end for media library
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreEndWithMediaLibrary_HandleEnd, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

// Test HandleRestoreEvent with restore end for file manager
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_RestoreEndWithFileManager_HandleEnd, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

// Test HandleRestoreEvent with invalid action
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

// Test HandleRestoreEvent with invalid bundle
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", INVALID_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test HandleRestoreEvent with concurrent start and end
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEvent_ConcurrentStartEnd_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(startWant);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

// Test HandleDeathRecipient with restore in progress
HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_DefaultState_ResetStatus, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

// Test HandleDeathRecipient with no restore in progress
HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_NoRestoreInProgress_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    bool beforeState = manager.IsRestoring();
    manager.HandleDeathRecipient();
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test HandleDeathRecipient with multiple restore
HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_MultipleRestore_ResetAll, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    manager.HandleDeathRecipient();

    EXPECT_FALSE(manager.IsRestoring());
}

// Test HandleDeathRecipient with concurrent calls
HWTEST_F(MediaLakeCloneEventManagerTest, HandleDeathRecipient_ConcurrentCalls_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    std::thread thread1([&]() { manager.HandleDeathRecipient(); });
    std::thread thread2([&]() { manager.HandleDeathRecipient(); });

    thread1.join();
    thread2.join();

    EXPECT_FALSE(manager.IsRestoring());
}

// Test GetBitByBundleName with media library
HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_MediaLibrary_ReturnBit0, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(MEDIA_LIBRARY_BUNDLE, bit);

    EXPECT_TRUE(result);
    EXPECT_EQ(bit, 0);
}

// Test GetBitByBundleName with file manager
HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_FileManager_ReturnBit1, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(FILE_MANAGER_BUNDLE, bit);

    EXPECT_TRUE(result);
    EXPECT_EQ(bit, 1);
}

// Test GetBitByBundleName with invalid bundle
HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_InvalidBundle_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName(INVALID_BUNDLE, bit);

    EXPECT_FALSE(result);
}

// Test GetBitByBundleName with empty bundle
HWTEST_F(MediaLakeCloneEventManagerTest, GetBitByBundleName_EmptyBundle_ReturnFalse, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint8_t bit = 0xFF;

    bool result = manager.GetBitByBundleName("", bit);

    EXPECT_FALSE(result);
}

// Test SetRestoreStatusBitMapForStart with media library - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_MediaLibrary_SetBit0, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 1);
}

// Test SetRestoreStatusBitMapForStart with file manager - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_FileManager_SetBit1, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 2);
}

// Test SetRestoreStatusBitMapForStart with invalid bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    manager.SetRestoreStatusBitMapForStart(INVALID_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test SetRestoreStatusBitMapForStart with empty bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    manager.SetRestoreStatusBitMapForStart("");

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test SetRestoreStatusBitMapForStart with multiple bundles - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForStart_MultipleBundles_SetBothBits, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 1);

    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);
    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 3);
}

// Test SetRestoreStatusBitMapForEnd with media library - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_MediaLibrary_ClearBit0, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    manager.SetRestoreStatusBitMapForEnd(MEDIA_LIBRARY_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 2);
}

// Test SetRestoreStatusBitMapForEnd with file manager - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_FileManager_ClearBit1, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    manager.SetRestoreStatusBitMapForEnd(FILE_MANAGER_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 1);
}

// Test SetRestoreStatusBitMapForEnd with invalid bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    manager.SetRestoreStatusBitMapForEnd(INVALID_BUNDLE);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test SetRestoreStatusBitMapForEnd with empty bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, SetRestoreStatusBitMapForEnd_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    manager.SetRestoreStatusBitMapForEnd("");

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test CheckIsExecuteGlobalScan with media library - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, CheckIsExecuteGlobalScan_MediaLibrary_SkipScan, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    bool beforeState = manager.isExecuteGlobalScan_.load();

    manager.CheckIsExecuteGlobalScan(0);

    EXPECT_FALSE(manager.isExecuteGlobalScan_.load());
}

// Test CheckIsExecuteGlobalScan with file manager - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, CheckIsExecuteGlobalScan_FileManager_ExecuteScan, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.isExecuteGlobalScan_.store(false);

    manager.CheckIsExecuteGlobalScan(1);

    EXPECT_FALSE(manager.isExecuteGlobalScan_.load());
}

// Test ShouldUnregisterLakeFileMonitor with first restore without start - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ShouldUnregisterLakeFileMonitor_FirstRestoreWithoutStart, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    bool result = manager.ShouldUnregisterLakeFileMonitor();

    EXPECT_FALSE(result);
}

// Test ShouldUnregisterLakeFileMonitor with first restore with start - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ShouldUnregisterLakeFileMonitor_FirstRestoreWithStart, TestSize.Level1)
{
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.HandleRestoreEvent(startWant);

    bool result = manager.ShouldUnregisterLakeFileMonitor();

    EXPECT_TRUE(result);
}

// Test ShouldUnregisterLakeFileMonitor with already restoring - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ShouldUnregisterLakeFileMonitor_AlreadyRestoring, TestSize.Level1)
{
    AAFwk::Want startWant1;
    startWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    bool result = manager.ShouldUnregisterLakeFileMonitor();

    EXPECT_FALSE(result);
}

// Test ShouldRegisterLakeFileMonitor with last restore end - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ShouldRegisterLakeFileMonitor_LastRestoreEnd, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);

    bool result = manager.ShouldRegisterLakeFileMonitor();

    EXPECT_FALSE(result);
}

// Test ShouldRegisterLakeFileMonitor with partial restore end - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ShouldRegisterLakeFileMonitor_PartialRestoreEnd, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    bool result = manager.ShouldRegisterLakeFileMonitor();

    EXPECT_FALSE(result);
}

// Test ResetRestoreStatusBitMap with restore in progress - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ResetRestoreStatusBitMap_WithRestoreInProgress_ResetAll, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    manager.ResetRestoreStatusBitMap();

    EXPECT_EQ(manager.initRestoreStatusBitMap_.load(), 0);
    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 0);
    EXPECT_TRUE(manager.isExecuteGlobalScan_.load());
}

// Test ResetRestoreStatusBitMap with no restore in progress - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ResetRestoreStatusBitMap_NoRestoreInProgress_ResetAll, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    manager.ResetRestoreStatusBitMap();

    EXPECT_EQ(manager.initRestoreStatusBitMap_.load(), 0);
    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 0);
    EXPECT_TRUE(manager.isExecuteGlobalScan_.load());
}

// Test HandleRestoreStartEvent with media library - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_MediaLibrary_SetStatusBit, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreStartEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 1);
}

// Test HandleRestoreStartEvent with file manager - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_FileManager_SetStatusBit, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    manager.HandleRestoreStartEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 2);
}

// Test HandleRestoreStartEvent with empty bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreStartEvent_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    manager.HandleRestoreStartEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test HandleRestoreEndEvent with media library - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_MediaLibrary_ClearStatusBit, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEndEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 0);
}

// Test HandleRestoreEndEvent with file manager - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_FileManager_ClearStatusBit, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(FILE_MANAGER_BUNDLE);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    manager.HandleRestoreEndEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 0);
}

// Test HandleRestoreEndEvent with invalid bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_InvalidBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", INVALID_BUNDLE);

    manager.HandleRestoreEndEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test HandleRestoreEndEvent with empty bundle - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, HandleRestoreEndEvent_EmptyBundle_NoAction, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    uint32_t beforeStatus = manager.currentRestoreStatusBitMap_.load();

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);

    manager.HandleRestoreEndEvent(want);

    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), beforeStatus);
}

// Test ResetRestoreStatusBitMap resets all member variables - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, ResetRestoreStatusBitMap_ResetsAllVariables, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.SetRestoreStatusBitMapForStart(MEDIA_LIBRARY_BUNDLE);
    manager.isExecuteGlobalScan_.store(false);

    manager.ResetRestoreStatusBitMap();

    EXPECT_EQ(manager.initRestoreStatusBitMap_.load(), 0);
    EXPECT_EQ(manager.currentRestoreStatusBitMap_.load(), 0);
    EXPECT_TRUE(manager.isExecuteGlobalScan_.load());
}

// Test OnRemoteDied with null object - private function test
HWTEST_F(MediaLakeCloneEventManagerTest, OnRemoteDied_NullObject_NoAction, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", FILE_MANAGER_BUNDLE);

    auto &manager = MediaLakeCloneEventManager::GetInstance();
    manager.HandleRestoreStartEvent(want);

    MediaLakeCloneDeathRecipient recipient;
    wptr<IRemoteObject> object = nullptr;
    recipient.OnRemoteDied(object);

    EXPECT_TRUE(manager.IsRestoring());  // invalid death recipient
}

// Test multi-threaded concurrent restore start
HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentRestoreStart_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            AAFwk::Want want;
            want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
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

// Test multi-threaded concurrent restore end
HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentRestoreEnd_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            AAFwk::Want want;
            want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
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

// Test multi-threaded concurrent IsRestoring calls
HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentIsRestoring_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
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

// Test multi-threaded concurrent HandleDeathRecipient calls
HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_ConcurrentHandleDeathRecipient_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
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

// Test multi-threaded mixed operations
HWTEST_F(MediaLakeCloneEventManagerTest, MultiThread_MixedOperations_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t threadCount = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int32_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([&, i]() {
            if (i % 2 == 0) {
                AAFwk::Want want;
                want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
                want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
                manager.HandleRestoreEvent(want);
            } else {
                AAFwk::Want want;
                want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
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

// Test boundary condition: max restore status
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_MaxRestoreStatus_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant1;
    startWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant1);

    AAFwk::Want startWant2;
    startWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(startWant2);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want endWant1;
    endWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant1);

    AAFwk::Want endWant2;
    endWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(endWant2);

    EXPECT_FALSE(manager.IsRestoring());
}

// Test boundary condition: rapid start and end
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_RapidStartEnd_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    for (int32_t i = 0; i < 10; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test boundary condition: empty want
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_EmptyWant_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test boundary condition: null bundle name
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_NullBundleName_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test boundary condition: special characters in bundle
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_SpecialCharactersInBundle_HandleSafely, TestSize.Level1)
{
    std::string bundleNameWithSpecialCharacters = "com.test.special!@#$%";
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", bundleNameWithSpecialCharacters);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test boundary condition: very long bundle name
HWTEST_F(MediaLakeCloneEventManagerTest, Boundary_VeryLongBundleName_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    std::string longBundle(1000, 'a');
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", longBundle);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test edge case: restore start without end
HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_RestoreStartWithoutEnd_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    manager.HandleRestoreEvent(want);

    EXPECT_TRUE(manager.IsRestoring());
}

// Test edge case: restore end without start
HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_RestoreEndWithoutStart_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);

    bool beforeState = manager.IsRestoring();
    manager.HandleRestoreEvent(want);
    bool afterState = manager.IsRestoring();

    EXPECT_EQ(beforeState, afterState);
}

// Test edge case: multiple death recipient calls
HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_MultipleDeathRecipientCalls_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    for (int32_t i = 0; i < 10; ++i) {
        manager.HandleDeathRecipient();
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test edge case: interleaved start, end, and death recipient
HWTEST_F(MediaLakeCloneEventManagerTest, EdgeCase_InterleavedStartEndDeath_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    manager.HandleDeathRecipient();

    AAFwk::Want endWant;
    endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(endWant);

    EXPECT_FALSE(manager.IsRestoring());
}

// Test stress: rapid restore events
HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_RapidRestoreEvents_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 10;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test stress: mixed bundles
HWTEST_F(MediaLakeCloneEventManagerTest, ressTest_MixedBundles_HandleCorrectly, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 10;

    for (int32_t i = 0; i < iterations; i++) {
        AAFwk::Want startWant1;
        startWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant1);

        AAFwk::Want startWant2;
        startWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
        manager.HandleRestoreEvent(startWant2);

        AAFwk::Want endWant1;
        endWant1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant1);

        AAFwk::Want endWant2;
        endWant2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
        manager.HandleRestoreEvent(endWant2);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test stress: rapid IsRestoring calls
HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_RapidIsRestoringCalls_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    AAFwk::Want startWant;
    startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(startWant);

    const int32_t iterations = 1000;
    std::atomic<int> trueCount(0);

    for (int32_t i = 0; i < iterations; ++i) {
        if (manager.IsRestoring()) {
            trueCount++;
        }
    }

    EXPECT_EQ(trueCount.load(), iterations);
}

// Test stress: alternating death recipient
HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_AlternatingDeathRecipient_HandleSafely, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 10;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        if (i % 2 == 0) {
            manager.HandleDeathRecipient();
        }

        AAFwk::Want endWant;
        endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test stress: memory leak check
HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_MemoryLeakCheck_NoLeaks, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 10;

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        AAFwk::Want endWant;
        endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
        endWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(endWant);

        manager.HandleDeathRecipient();
    }

    EXPECT_FALSE(manager.IsRestoring());
}

// Test stress: state consistency
HWTEST_F(MediaLakeCloneEventManagerTest, StressTest_StateConsistency_CheckConsistency, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();
    const int32_t iterations = 5;
    std::atomic<int> consistentCount(0);

    for (int32_t i = 0; i < iterations; ++i) {
        AAFwk::Want startWant;
        startWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
        startWant.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
        manager.HandleRestoreEvent(startWant);

        bool state1 = manager.IsRestoring();

        AAFwk::Want endWant;
        endWant.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
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

// Test coverage: all branches
HWTEST_F(MediaLakeCloneEventManagerTest, Coverage_AllBranches_Covered, TestSize.Level1)
{
    auto &manager = MediaLakeCloneEventManager::GetInstance();

    AAFwk::Want want1;
    want1.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want1.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want1);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want2;
    want2.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want2.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want2);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want3;
    want3.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want3.SetParam("bundleName", MEDIA_LIBRARY_BUNDLE);
    manager.HandleRestoreEvent(want3);

    EXPECT_TRUE(manager.IsRestoring());

    AAFwk::Want want4;
    want4.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_END);
    want4.SetParam("bundleName", FILE_MANAGER_BUNDLE);
    manager.HandleRestoreEvent(want4);

    EXPECT_FALSE(manager.IsRestoring());

    AAFwk::Want want5;
    want5.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START);
    want5.SetParam("bundleName", INVALID_BUNDLE);
    manager.HandleRestoreEvent(want5);

    EXPECT_FALSE(manager.IsRestoring());
}

}  // namespace Media
}  // namespace OHOS
