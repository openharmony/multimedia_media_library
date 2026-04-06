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

#ifndef MEDIA_LIBRARY_UPGRADE_TASK_REGISTRY_H
#define MEDIA_LIBRARY_UPGRADE_TASK_REGISTRY_H

#include "media_library_upgrade_task.h"
#include <vector>
#include <memory>
#include <string>
#include <map>

namespace OHOS {
namespace Media {

/**
 * @brief 升级任务注册表（注册表模式 + 单例模式）
 *
 * 负责管理和注册所有升级任务
 */
class UpgradeTaskRegistry {
public:
    /**
     * @brief 获取注册表单例
     * @return 注册表引用
     */
    static UpgradeTaskRegistry& GetInstance();

    // 禁止拷贝和赋值
    UpgradeTaskRegistry(const UpgradeTaskRegistry&) = delete;
    UpgradeTaskRegistry& operator=(const UpgradeTaskRegistry&) = delete;

    /**
     * @brief 注册升级任务
     * @param task 升级任务智能指针
     */
    void RegisterTask(std::shared_ptr<IUpgradeTask> task);

    /**
     * @brief 获取所有升级任务
     * @return 升级任务列表
     */
    std::vector<std::shared_ptr<IUpgradeTask>> GetAllTasks() const;

    /**
     * @brief 根据模块名称获取升级任务
     * @param moduleName 模块名称
     * @return 升级任务列表
     */
    std::vector<std::shared_ptr<IUpgradeTask>> GetTasksByModule(const std::string& moduleName) const;

    /**
     * @brief 根据版本号获取升级任务
     * @param version 版本号
     * @return 升级任务列表，不存在返回空列表
     */
    std::vector<std::shared_ptr<IUpgradeTask>> GetTasksByVersion(int32_t version) const;

    /**
     * @brief 获取指定版本之后的升级任务
     * @param currentVersion 当前版本
     * @return 需要执行的升级任务列表
     */
    std::vector<std::shared_ptr<IUpgradeTask>> GetTasksAfterVersion(int32_t currentVersion) const;

    /**
     * @brief 获取指定版本之后指定类型的升级任务
     * @param currentVersion 当前版本
     * @param isSync 任务类型（true=同步，false=异步）
     * @return 需要执行的升级任务列表
     */
    std::vector<std::shared_ptr<IUpgradeTask>> GetTasksAfterVersion(int32_t currentVersion, bool isSync) const;

    /**
     * @brief 清空所有任务
     */
    void Clear();

private:
    UpgradeTaskRegistry() = default;
    ~UpgradeTaskRegistry() = default;

    // 支持同一版本号注册多个任务（用于同步/异步升级场景）
    std::map<int32_t, std::vector<std::shared_ptr<IUpgradeTask>>> tasksByVersion_;
    std::map<std::string, std::vector<std::shared_ptr<IUpgradeTask>>> tasksByModule_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_TASK_REGISTRY_H