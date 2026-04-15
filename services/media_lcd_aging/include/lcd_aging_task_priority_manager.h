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

#ifndef OHOS_MEDIA_LCD_AGING_TASK_PRIORITY_MANAGER_H
#define OHOS_MEDIA_LCD_AGING_TASK_PRIORITY_MANAGER_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <unordered_map>

namespace OHOS::Media {
enum class HighPriorityTaskType {
    CLOUD_PULL,
    ANALYSIS_DOWNLOAD
};

class LcdAgingTaskPriorityManager {
public:
    static LcdAgingTaskPriorityManager& GetInstance();
    void RegisterHighPriorityTask(HighPriorityTaskType type);
    void UnregisterHighPriorityTask(HighPriorityTaskType type);
    void Reset();
    bool HasHighPriorityTasks() const;
    bool CheckForHighPriorityTasks();

private:
    LcdAgingTaskPriorityManager() = default;
    ~LcdAgingTaskPriorityManager() = default;
    LcdAgingTaskPriorityManager(const LcdAgingTaskPriorityManager&) = delete;
    LcdAgingTaskPriorityManager& operator=(const LcdAgingTaskPriorityManager&) = delete;

    std::mutex taskMutex_;
    std::unordered_map<HighPriorityTaskType, int32_t> taskCounters_;
    std::atomic<bool> hasHighPriorityTasks_ { false };
    std::condition_variable agingResumeCV_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_LCD_AGING_TASK_PRIORITY_MANAGER_H
