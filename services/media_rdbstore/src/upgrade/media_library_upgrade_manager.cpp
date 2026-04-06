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

#define MLOG_TAG "Media_Upgrade"

#include "media_library_upgrade_manager.h"

#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "media_library_upgrade_task_registry.h"
#include "result_set_utils.h"
#include <chrono>

namespace OHOS {
namespace Media {

UpgradeManager& UpgradeManager::GetInstance()
{
    static UpgradeManager instance;
    return instance;
}

int32_t UpgradeManager::Initialize(const UpgradeManagerConfig& config)
{
    observer_ = std::make_shared<DefaultUpgradeObserver>();
    executor_.SetObserver(observer_);
    executor_.SetRdbConfigPath(config.rdbConfigPath);
    executor_.SetUpgradeEventPath(config.upgradeEventPath);
    currentVersion_ = config.currentVersion;
    targetVersion_ = config.targetVersion;
    isCloned_ = config.isCloned;
    MEDIA_INFO_LOG("UpgradeManager initialized");
    return NativeRdb::E_OK;
}

void UpgradeManager::SetObserver(std::shared_ptr<IUpgradeObserver> observer)
{
    observer_ = observer;
    executor_.SetObserver(observer);
}

int32_t UpgradeManager::DoUpgrade(NativeRdb::RdbStore& store, bool isSync)
{
    int64_t startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (currentVersion_ >= targetVersion_) {
        MEDIA_INFO_LOG("No upgrade needed, current version: %{public}d", currentVersion_);
        return NativeRdb::E_OK;
    }

    MEDIA_INFO_LOG("Start %{public}s upgrade from version %{public}d to %{public}d",
        isSync ? "sync" : "async", currentVersion_, targetVersion_);

    std::vector<std::shared_ptr<IUpgradeTask>> tasks =
        UpgradeTaskRegistry::GetInstance().GetTasksAfterVersion(currentVersion_, isSync);

    if (tasks.empty()) {
        MEDIA_INFO_LOG("No upgrade tasks to execute");
        return NativeRdb::E_OK;
    }

    // 执行升级任务
    int32_t ret = executor_.ExecuteTasks(tasks, store, currentVersion_, isSync);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("ExecuteTasks failed");
        RdbUpgradeUtils::ReportUpgradeDfxMessages(startTime, currentVersion_, targetVersion_, isSync);
        return ret;
    }

    MEDIA_INFO_LOG("Upgrade completed successfully");
    RdbUpgradeUtils::ReportUpgradeDfxMessages(startTime, currentVersion_, targetVersion_, isSync);
    return NativeRdb::E_OK;
}

int32_t UpgradeManager::UpgradeSync(NativeRdb::RdbStore& store)
{
    return DoUpgrade(store, true);
}

int32_t UpgradeManager::UpgradeAsync(NativeRdb::RdbStore& store)
{
    return DoUpgrade(store, false);
}

} // namespace Media
} // namespace OHOS