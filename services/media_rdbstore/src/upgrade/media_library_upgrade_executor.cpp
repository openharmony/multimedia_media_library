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

#include "media_library_upgrade_executor.h"
#include "media_log.h"

namespace OHOS {
namespace Media {

// 需要状态管理的起始版本号 VERSION_FIX_DB_UPGRADE_TO_API20
const int32_t STATUS_MANAGEMENT_START_VERSION = 350;

void UpgradeExecutor::SetObserver(std::shared_ptr<IUpgradeObserver> observer)
{
    observer_ = observer;
}

void UpgradeExecutor::SetUpgradeEventPath(const std::string& path)
{
    upgradeEventPath_ = path;
}

void UpgradeExecutor::SetRdbConfigPath(const std::string& path)
{
    rdbConfigPath_ = path;
}

void UpgradeExecutor::SetRdbConfigVersion(int32_t version)
{
    int32_t errCode = 0;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(rdbConfigPath_, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    const std::string RDB_OLD_VERSION = "rdb_old_version";
    prefs->PutInt(RDB_OLD_VERSION, version);
    prefs->FlushSync();
}

bool UpgradeExecutor::ShouldExecuteTask(const std::shared_ptr<IUpgradeTask>& task,
    int32_t currentVersion, bool isSync) const
{
    int32_t version = task->GetVersion();
    // 检查版本号是否需要升级
    if (currentVersion >= version) {
        MEDIA_INFO_LOG("Task %{public}s (version %{public}d) skipped: current version >= task version",
            task->GetName().c_str(), version);
        return false;
    }

    // 只有 VERSION_FIX_DB_UPGRADE_TO_API20 及之后的版本才需要检查升级状态
    if (version >= STATUS_MANAGEMENT_START_VERSION) {
        if (RdbUpgradeUtils::HasUpgraded(version, isSync, upgradeEventPath_)) {
            MEDIA_INFO_LOG("Task %{public}s (version %{public}d) skipped: already upgraded",
                task->GetName().c_str(), version);
            return false;
        }
    }

    return true;
}

int32_t UpgradeExecutor::ExecuteTask(const std::shared_ptr<IUpgradeTask>& task,
    NativeRdb::RdbStore& store, bool isSync)
{
    int32_t version = task->GetVersion();

    NotifyUpgradeStart(task);

    // 执行升级任务
    int32_t ret = task->Execute(store);

    NotifyUpgradeComplete(task, ret);

    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Task %{public}s (version %{public}d) failed with error: %{public}d",
            task->GetName().c_str(), version, ret);
        return ret;
    }

    // 只有 VERSION_FIX_DB_UPGRADE_TO_API20 及之后的版本才需要设置升级状态
    if (version >= STATUS_MANAGEMENT_START_VERSION) {
        RdbUpgradeUtils::SetUpgradeStatus(version, isSync, upgradeEventPath_);
        MEDIA_INFO_LOG("Task %{public}s (version %{public}d) status set",
            task->GetName().c_str(), version);
    }
    SetRdbConfigVersion(version);

    MEDIA_INFO_LOG("Task %{public}s (version %{public}d) completed successfully",
        task->GetName().c_str(), version);

    return NativeRdb::E_OK;
}

void UpgradeExecutor::NotifyUpgradeStart(const std::shared_ptr<IUpgradeTask>& task)
{
    if (observer_ != nullptr) {
        observer_->OnUpgradeStart(task);
    }
}

void UpgradeExecutor::NotifyUpgradeComplete(const std::shared_ptr<IUpgradeTask>& task, int32_t ret)
{
    if (observer_ != nullptr) {
        observer_->OnUpgradeComplete(task, ret);
    }
}

int32_t UpgradeExecutor::ExecuteTasks(const std::vector<std::shared_ptr<IUpgradeTask>>& tasks,
    NativeRdb::RdbStore& store, int32_t currentVersion, bool isSync)
{
    int32_t failedCount = 0;

    // 责任链模式：按顺序执行升级任务
    for (const auto& task : tasks) {
        if (!ShouldExecuteTask(task, currentVersion, isSync)) {
            continue;
        }

        int32_t ret = ExecuteTask(task, store, isSync);
        if (ret != NativeRdb::E_OK) {
            failedCount++;
        }
    }

    if (failedCount > 0) {
        MEDIA_ERR_LOG("ExecuteTasks completed with %{public}d failed tasks", failedCount);
        return NativeRdb::E_ERROR;
    }

    MEDIA_INFO_LOG("ExecuteTasks completed successfully");
    return NativeRdb::E_OK;
}

} // namespace Media
} // namespace OHOS