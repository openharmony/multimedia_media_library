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

#ifndef MEDIA_LIBRARY_UPGRADE_OBSERVER_H
#define MEDIA_LIBRARY_UPGRADE_OBSERVER_H

#include "media_library_upgrade_task.h"
#include "upgrade_visibility.h"

namespace OHOS {
namespace Media {

/**
 * @brief 升级观察者接口（观察者模式）
 *
 * 用于观察升级任务的执行状态
 */
class IUpgradeObserver {
public:
    virtual ~IUpgradeObserver() = default;

    /**
     * @brief 升级任务开始时的回调
     * @param task 升级任务
     */
    virtual void OnUpgradeStart(const std::shared_ptr<IUpgradeTask>& task) = 0;

    /**
     * @brief 升级任务完成时的回调
     * @param task 升级任务
     * @param ret 返回码
     */
    virtual void OnUpgradeComplete(const std::shared_ptr<IUpgradeTask>& task, int32_t ret) = 0;

    /**
     * @brief 升级进度更新时的回调
     * @param currentVersion 当前版本
     * @param targetVersion 目标版本
     * @param completedCount 已完成任务数
     * @param totalCount 总任务数
     */
    virtual void OnUpgradeProgress(int32_t currentVersion,
                                   int32_t targetVersion,
                                   int32_t completedCount,
                                   int32_t totalCount) = 0;
};

/**
 * @brief 默认升级观察者
 *
 * 提供默认的日志输出实现
 */
class UPGRADE_EXPORT DefaultUpgradeObserver : public IUpgradeObserver {
public:
    void OnUpgradeStart(const std::shared_ptr<IUpgradeTask>& task) override;
    void OnUpgradeComplete(const std::shared_ptr<IUpgradeTask>& task, int32_t ret) override;
    void OnUpgradeProgress(int32_t currentVersion,
                           int32_t targetVersion,
                           int32_t completedCount,
                           int32_t totalCount) override;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_OBSERVER_H