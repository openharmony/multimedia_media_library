/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryTriggerManagerTest"

#include "medialibrary_trigger_manager_test.h"

#define private public
#include "medialibrary_trigger_manager.h"
#undef private

namespace OHOS {
namespace Media {

using namespace testing::ext;

static std::string key = PhotoColumn::PHOTOS_TABLE + "#INSERT";
static std::string unavailableKey = PhotoColumn::PHOTOS_TABLE + "#UPDATE";

HWTEST_F(MediaLibraryTriggerManagerTest, MediaLibraryTriggerManager_GetInstance_000, TestSize.Level2) {
    auto &triggerManager = MediaLibraryTriggerManager::GetInstance();
    int expectedGenTriggerFuncSize = 2;

    EXPECT_TRUE(triggerManager.getTriggersFuncs_.find(key) != triggerManager.getTriggersFuncs_.end());
    EXPECT_TRUE(triggerManager.getTriggersFuncs_[key].size() == expectedGenTriggerFuncSize);
    EXPECT_TRUE(!triggerManager.getTriggersFuncs_.count(unavailableKey));
}

HWTEST_F(MediaLibraryTriggerManagerTest, MediaLibraryTriggerManager_GetTrigger_000, TestSize.Level2) {
    auto &triggerManager = MediaLibraryTriggerManager::GetInstance();
    auto trigger = triggerManager.GetTrigger(PhotoColumn::PHOTOS_TABLE,
        MediaLibraryTriggerManager::TriggerType::INSERT);
    EXPECT_NE(trigger, nullptr);

    trigger = triggerManager.GetTrigger(PhotoColumn::PHOTOS_TABLE, MediaLibraryTriggerManager::TriggerType::UPDATE);
    EXPECT_NE(trigger, nullptr);
}

HWTEST_F(MediaLibraryTriggerManagerTest, MediaLibraryTriggerManager_GetTrigger_001, TestSize.Level2) {
    auto &triggerManager = MediaLibraryTriggerManager::GetInstance();
    triggerManager.getTriggersFuncs_[key].push_back([]() -> std::shared_ptr<MediaLibraryTriggerBase> {
        return nullptr;});
    auto trigger = triggerManager.GetTrigger(PhotoColumn::PHOTOS_TABLE,
        MediaLibraryTriggerManager::TriggerType::INSERT);
    EXPECT_EQ(trigger, nullptr);
}

} // namespace Media
} // namespace OHOS