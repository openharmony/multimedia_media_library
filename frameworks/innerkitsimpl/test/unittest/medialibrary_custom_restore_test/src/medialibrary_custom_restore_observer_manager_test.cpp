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
#include "medialibrary_custom_restore_observer_manager.h"

using namespace testing;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class MediaLibraryCustomRestoreObserverManagerTest : public testing::Test {
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

void MediaLibraryCustomRestoreObserverManagerTest::SetUpTestCase(void) {}

void MediaLibraryCustomRestoreObserverManagerTest::TearDownTestCase(void) {}

void MediaLibraryCustomRestoreObserverManagerTest::SetUp(void) {}

void MediaLibraryCustomRestoreObserverManagerTest::TearDown(void) {}

class SecondMockCustomRestoreCallback : public CustomRestoreCallback {
    int32_t OnRestoreResult(RestoreResult restoreResult) override
    {
        MEDIA_INFO_LOG("SecondMockCustomRestoreCallback OnRestoreResult stage: %{public}s, "
            "errCode: %{public}d, progress: %{public}d, "
            "uriType: %{public}d, uri: %{public}s", (restoreResult.stage).c_str(),
            restoreResult.errCode, restoreResult.progress,
            restoreResult.uriType, (restoreResult.uri).c_str());
        return E_OK;
    }
};

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_001 Start");
    auto result = CustomRestoreObserverManager::GetInstance().AttachObserver(nullptr, nullptr);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_001 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_002 Start");
    SecondMockCustomRestoreCallback customRestoreCallback;
    std::shared_ptr<SecondMockCustomRestoreCallback> callback =
        std::make_shared<SecondMockCustomRestoreCallback>(customRestoreCallback);
    auto result = CustomRestoreObserverManager::GetInstance().AttachObserver(callback, nullptr);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_002 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_003 Start");
    SecondMockCustomRestoreCallback customRestoreCallback;
    std::shared_ptr<SecondMockCustomRestoreCallback> callback =
        std::make_shared<SecondMockCustomRestoreCallback>(customRestoreCallback);
    std::shared_ptr<CustomRestoreNotifyObserver> notifyObserver =
            std::make_shared<CustomRestoreNotifyObserver>(callback);
    auto result = CustomRestoreObserverManager::GetInstance().AttachObserver(callback, notifyObserver);
    EXPECT_EQ(result, true);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_003 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_005 Start");
    CustomRestoreObserverManager::GetInstance().AttachObserver(nullptr, nullptr);
    auto result = CustomRestoreObserverManager::GetInstance().QueryObserver(nullptr);
    EXPECT_EQ(result == nullptr, true);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_005 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_006 Start");
    CustomRestoreObserverManager::GetInstance().callbackMap_.Clear();
    SecondMockCustomRestoreCallback customRestoreCallback;
    std::shared_ptr<SecondMockCustomRestoreCallback> callback =
        std::make_shared<SecondMockCustomRestoreCallback>(customRestoreCallback);
    auto result = CustomRestoreObserverManager::GetInstance().QueryObserver(callback);
    EXPECT_EQ(result == nullptr, true);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_006 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_007 Start");
    CustomRestoreObserverManager::GetInstance().callbackMap_.Clear();
    SecondMockCustomRestoreCallback customRestoreCallback;
    std::shared_ptr<SecondMockCustomRestoreCallback> callback =
        std::make_shared<SecondMockCustomRestoreCallback>(customRestoreCallback);
    std::shared_ptr<CustomRestoreNotifyObserver> notifyObserver =
            std::make_shared<CustomRestoreNotifyObserver>(callback);
    CustomRestoreObserverManager::GetInstance().AttachObserver(callback, notifyObserver);
    auto result = CustomRestoreObserverManager::GetInstance().QueryObserver(callback);
    EXPECT_EQ(result != nullptr, true);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_007 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_008 Start");
    CustomRestoreObserverManager::GetInstance().callbackMap_.Clear();
    auto result = CustomRestoreObserverManager::GetInstance().DetachObserver(nullptr);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_008 End");
}

HWTEST_F(MediaLibraryCustomRestoreObserverManagerTest, Custom_Restore_ObserverManager_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_009 Start");
    CustomRestoreObserverManager::GetInstance().callbackMap_.Clear();
    SecondMockCustomRestoreCallback customRestoreCallback;
    std::shared_ptr<SecondMockCustomRestoreCallback> callback =
        std::make_shared<SecondMockCustomRestoreCallback>(customRestoreCallback);
    auto result = CustomRestoreObserverManager::GetInstance().DetachObserver(callback);
    EXPECT_EQ(result, true);
    MEDIA_INFO_LOG("Custom_Restore_ObserverManager_Test_009 End");
}

}
}