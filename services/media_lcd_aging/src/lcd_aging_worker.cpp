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

#include "lcd_aging_worker.h"

#include <chrono>
#include <thread>

#include "lcd_aging_manager.h"
#include "lcd_aging_task_priority_manager.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_subscriber.h"

namespace OHOS::Media {
constexpr int32_t CYCLE_NUMBER = 100;
constexpr int32_t E_PAUSE = 2;

LcdAgingWorker& LcdAgingWorker::GetInstance()
{
    static LcdAgingWorker instance;
    return instance;
}

void LcdAgingWorker::StartLcdAgingWorker()
{
    bool expected = false;
    if (!isThreadRunning_.compare_exchange_strong(expected, true)) {
        MEDIA_INFO_LOG("LCD aging worker is already running");
        return;
    }
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    workerThread_ = std::thread([this]() { this->HandleLcdAgingTask(); });
}

LcdAgingWorker::~LcdAgingWorker()
{
    isThreadRunning_.store(false);
    if (workerThread_.joinable()) {
        MEDIA_INFO_LOG("Waiting for LCD aging worker thread to finish");
        workerThread_.join();
        MEDIA_INFO_LOG("LCD aging worker thread finished");
    }
}

bool LcdAgingWorker::IsRunning()
{
    return isThreadRunning_.load();
}

void LcdAgingWorker::HandleLcdAgingTask()
{
    MEDIA_INFO_LOG("start HandleLcdAgingTask thread");
    std::string name("LcdAgingTaskThread");
    pthread_setname_np(pthread_self(), name.c_str());

    int32_t cycleNumber = 0;
    int32_t ret = E_ERR;
    while (MedialibrarySubscriber::IsCurrentStatusOn() && cycleNumber++ <= CYCLE_NUMBER) {
        // 如果等待超时，执行continue
        CHECK_AND_CONTINUE(LcdAgingTaskPriorityManager::GetInstance().CheckForHighPriorityTasks());
        MEDIA_DEBUG_LOG("begin BatchAgingLcdFileTask");
        ret = LcdAgingManager::GetInstance().BatchAgingLcdFileTask();
        MEDIA_DEBUG_LOG("end BatchAgingLcdFileTask");
        CHECK_AND_BREAK_ERR_LOG(ret == E_OK || ret == E_PAUSE, "break HandleLcdAgingTask, ret: %{public}d", ret);
    }
    isThreadRunning_.store(false);
    LcdAgingTaskPriorityManager::GetInstance().Reset();
    MEDIA_INFO_LOG("end HandleLcdAgingTask thread, ret: %{public}d, cycleNumber: %{public}d", ret, cycleNumber);
}
}  // namespace OHOS::Media