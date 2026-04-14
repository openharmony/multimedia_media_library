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
#define MLOG_TAG "Lcd_Aging"

#include "lcd_aging_task_priority_manager.h"

#include <chrono>

#include "lcd_aging_worker.h"
#include "media_log.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
constexpr int32_t PAUSE_TIMEOUT_MINUTES = 3;

LcdAgingTaskPriorityManager& LcdAgingTaskPriorityManager::GetInstance()
{
    static LcdAgingTaskPriorityManager instance;
    return instance;
}

void LcdAgingTaskPriorityManager::RegisterHighPriorityTask(HighPriorityTaskType type)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    CHECK_AND_RETURN(LcdAgingWorker::GetInstance().IsRunning());

    taskCounters_[type]++;
    if (!hasHighPriorityTasks_.load()) {
        hasHighPriorityTasks_.store(true);
    }

    MEDIA_INFO_LOG("Register task type: %{public}d, count: %{public}d, total tasks: %{public}zu",
        static_cast<int32_t>(type), taskCounters_[type], taskCounters_.size());
}

void LcdAgingTaskPriorityManager::UnregisterHighPriorityTask(HighPriorityTaskType type)
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    CHECK_AND_RETURN(LcdAgingWorker::GetInstance().IsRunning());

    auto it = taskCounters_.find(type);
    if (it != taskCounters_.end()) {
        it->second--;
        if (it->second <= 0) {
            taskCounters_.erase(it);
        }
    }

    if (taskCounters_.empty() && hasHighPriorityTasks_.load()) {
        hasHighPriorityTasks_.store(false);
        agingResumeCV_.notify_all();
        MEDIA_INFO_LOG("Unregister task type: %{public}d, no more high priority tasks", static_cast<int32_t>(type));
        return;
    }
    MEDIA_INFO_LOG("Unregister task type: %{public}d, remaining tasks: %{public}zu",
        static_cast<int32_t>(type), taskCounters_.size());
}

bool LcdAgingTaskPriorityManager::HasHighPriorityTasks() const
{
    return hasHighPriorityTasks_.load();
}

void LcdAgingTaskPriorityManager::Reset()
{
    std::lock_guard<std::mutex> lock(taskMutex_);
    MEDIA_WARN_LOG("Reset task counters, current size: %{public}zu", taskCounters_.size());
    CHECK_AND_EXECUTE(taskCounters_.empty(), taskCounters_.clear());
    hasHighPriorityTasks_.store(false);
}

bool LcdAgingTaskPriorityManager::CheckForHighPriorityTasks()
{
    std::unique_lock<std::mutex> lock(taskMutex_);
    auto timeout = std::chrono::minutes(PAUSE_TIMEOUT_MINUTES);
    auto status = agingResumeCV_.wait_for(lock, timeout, [this]() {
        return !hasHighPriorityTasks_.load() &&
                MediaLibraryAstcStat::GetInstance().IsBackupGroundTaskEmpty();
    });
    CHECK_AND_PRINT_LOG(status, "LCD aging task woke up, status: %{public}d", status);
    return status;
}
}  // namespace OHOS::Media
