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

#ifndef MEDIA_LIBRARY_UPGRADE_EXECUTOR_H
#define MEDIA_LIBRARY_UPGRADE_EXECUTOR_H

#include "media_library_upgrade_task.h"
#include "media_library_upgrade_observer.h"
#include "medialibrary_upgrade_utils.h"
#include "upgrade_visibility.h"
#include <vector>
#include <memory>

namespace OHOS {
namespace Media {

/**
 * @brief 升级执行器
 *
 * 负责执行升级任务，处理升级状态管理和错误上报
 */
class UpgradeExecutor {
public:
    UpgradeExecutor() = default;
    ~UpgradeExecutor() = default;

    /**
     * @brief 设置观察者
     * @param observer 观察者指针
     */
    void SetObserver(std::shared_ptr<IUpgradeObserver> observer);

    /**
     * @brief 执行升级任务列表
     * @param tasks 升级任务列表
     * @param store 数据库存储对象
     * @param currentVersion 当前版本
     * @param isSync 是否同步升级
     * @return 错误码
     */
    int32_t ExecuteTasks(const std::vector<std::shared_ptr<IUpgradeTask>>& tasks,
                         NativeRdb::RdbStore& store,
                         int32_t currentVersion,
                         bool isSync);
    void SetUpgradeEventPath(const std::string& path);
    void SetRdbConfigPath(const std::string& path);

private:
    /**
     * @brief 检查任务是否需要执行
     * @param task 升级任务
     * @param currentVersion 当前版本
     * @param isSync 是否同步升级
     * @return true 表示需要执行
     */
    bool ShouldExecuteTask(const std::shared_ptr<IUpgradeTask>& task,
                           int32_t currentVersion,
                           bool isSync) const;

    /**
     * @brief 执行单个升级任务
     * @param task 升级任务
     * @param store 数据库存储对象
     * @param isSync 是否同步升级
     * @return 错误码
     */
    int32_t ExecuteTask(const std::shared_ptr<IUpgradeTask>& task,
                        NativeRdb::RdbStore& store,
                        bool isSync);

    /**
     * @brief 通知升级开始
     * @param task 升级任务
     */
    void NotifyUpgradeStart(const std::shared_ptr<IUpgradeTask>& task);

    /**
     * @brief 通知升级完成
     * @param task 升级任务
     * @param ret 返回码
     */
    void NotifyUpgradeComplete(const std::shared_ptr<IUpgradeTask>& task, int32_t ret);
    void SetRdbConfigVersion(int32_t version);

    std::shared_ptr<IUpgradeObserver> observer_;
    std::string upgradeEventPath_;
    std::string rdbConfigPath_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_EXECUTOR_H