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

#include "media_library_upgrade_task_registry.h"

#include "media_log.h"

namespace OHOS {
namespace Media {

UpgradeTaskRegistry& UpgradeTaskRegistry::GetInstance()
{
    static UpgradeTaskRegistry instance;
    return instance;
}

void UpgradeTaskRegistry::RegisterTask(std::shared_ptr<IUpgradeTask> task)
{
    if (task == nullptr) {
        MEDIA_ERR_LOG("RegisterTask failed: task is nullptr");
        return;
    }

    int32_t version = task->GetVersion();
    std::string moduleName = task->GetModuleName();

    // 按版本号注册（支持同一版本号多个任务）
    tasksByVersion_[version].push_back(task);

    // 按模块名称注册
    tasksByModule_[moduleName].push_back(task);

    MEDIA_INFO_LOG("Registered upgrade task: %{public}s (version %{public}d, module %{public}s",
                   task->GetName().c_str(), version, moduleName.c_str());
}

std::vector<std::shared_ptr<IUpgradeTask>> UpgradeTaskRegistry::GetAllTasks() const
{
    std::vector<std::shared_ptr<IUpgradeTask>> tasks;
    for (const auto& pair : tasksByVersion_) {
        for (const auto& task : pair.second) {
            tasks.push_back(task);
        }
    }
    return tasks;
}

std::vector<std::shared_ptr<IUpgradeTask>> UpgradeTaskRegistry::GetTasksByModule(const std::string& moduleName) const
{
    auto it = tasksByModule_.find(moduleName);
    if (it != tasksByModule_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::shared_ptr<IUpgradeTask>> UpgradeTaskRegistry::GetTasksByVersion(int32_t version) const
{
    auto it = tasksByVersion_.find(version);
    if (it != tasksByVersion_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::shared_ptr<IUpgradeTask>> UpgradeTaskRegistry::GetTasksAfterVersion(int32_t currentVersion) const
{
    std::vector<std::shared_ptr<IUpgradeTask>> tasks;
    // map 遍历默认按版本号从小到大排序
    for (const auto& pair : tasksByVersion_) {
        if (pair.first <= currentVersion) continue;
        for (const auto& task : pair.second) {
            tasks.push_back(task);
        }
    }
    return tasks;
}

std::vector<std::shared_ptr<IUpgradeTask>> UpgradeTaskRegistry::GetTasksAfterVersion(int32_t currentVersion,
    bool isSync) const
{
    std::vector<std::shared_ptr<IUpgradeTask>> tasks;
    // map 遍历默认按版本号从小到大排序
    for (const auto& pair : tasksByVersion_) {
        if (pair.first <= currentVersion) continue;
        for (const auto& task : pair.second) {
            if (task->IsSync() == isSync) {
                tasks.push_back(task);
            }
        }
    }
    return tasks;
}

void UpgradeTaskRegistry::Clear()
{
    tasksByVersion_.clear();
    tasksByModule_.clear();
    MEDIA_INFO_LOG("UpgradeTaskRegistry cleared");
}

} // namespace Media
} // namespace OHOS