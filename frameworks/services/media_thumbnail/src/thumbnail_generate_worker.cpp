/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "thumbnail_generate_worker.h"

#include <pthread.h>

#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
static constexpr int32_t THREAD_NUM_FOREGROUND = 4;
static constexpr int32_t THREAD_NUM_BACKGROUND = 2;

ThumbnailGenerateWorker::~ThumbnailGenerateWorker()
{
    isThreadRunning_ = false;
    ignoreRequestId_ = 0;
    workerCv_.notify_all();
    for (auto &thread : threads_) {
        if (!thread.joinable()) {
            continue;
        }
        thread.join();
    }
    threads_.clear();
}

int32_t ThumbnailGenerateWorker::Init(const ThumbnailTaskType &taskType)
{
    int32_t threadNum;
    std::string threadName;
    if (taskType == ThumbnailTaskType::FOREGROUND) {
        threadNum = THREAD_NUM_FOREGROUND;
        threadName = THREAD_NAME_FOREGROUND;
    } else if (taskType == ThumbnailTaskType::BACKGROUND) {
        threadNum = THREAD_NUM_BACKGROUND;
        threadName = THREAD_NAME_BACKGROUND;
    } else {
        MEDIA_ERR_LOG("invalid task type");
        return E_ERR;
    }

    isThreadRunning_ = true;
    for (auto i = 0; i < threadNum; i++) {
        std::thread thread(&ThumbnailGenerateWorker::StartWorker, this);
        pthread_setname_np(thread.native_handle(), threadName.c_str());
        threads_.emplace_back(std::move(thread));
    }
    return E_OK;
}

int32_t ThumbnailGenerateWorker::ReleaseTaskQueue(const ThumbnailTaskPriority &taskPriority)
{
    if (taskPriority == ThumbnailTaskPriority::HIGH) {
        highPriorityTaskQueue_.Clear();
    } else if (taskPriority == ThumbnailTaskPriority::LOW) {
        lowPriorityTaskQueue_.Clear();
    } else {
        MEDIA_ERR_LOG("invalid task priority");
        return E_ERR;
    }
    return E_OK;
}

int32_t ThumbnailGenerateWorker::AddTask(
    const std::shared_ptr<ThumbnailGenerateTask> &task, const ThumbnailTaskPriority &taskPriority)
{
    if (taskPriority == ThumbnailTaskPriority::HIGH) {
        highPriorityTaskQueue_.Push(task);
    } else if (taskPriority == ThumbnailTaskPriority::LOW) {
        lowPriorityTaskQueue_.Push(task);
    } else {
        MEDIA_ERR_LOG("invalid task priority");
        return E_ERR;
    }
    workerCv_.notify_one();
    return E_OK;
}

void ThumbnailGenerateWorker::IgnoreTaskByRequestId(uint64_t requestId)
{
    if (highPriorityTaskQueue_.Empty() && lowPriorityTaskQueue_.Empty()) {
        MEDIA_INFO_LOG("task queue empty, no need to ignore task");
        return;
    }
    ignoreRequestId_.store(requestId);
}

void ThumbnailGenerateWorker::WaitForTask()
{
    std::unique_lock<std::mutex> lock(workerLock_);
    if (highPriorityTaskQueue_.Empty() && lowPriorityTaskQueue_.Empty() && isThreadRunning_) {
        ignoreRequestId_ = 0;
        workerCv_.wait(lock);
    }
}

void ThumbnailGenerateWorker::StartWorker()
{
    while (isThreadRunning_) {
        WaitForTask();
        std::shared_ptr<ThumbnailGenerateTask> task;
        if (!highPriorityTaskQueue_.Empty() && highPriorityTaskQueue_.Pop(task) &&
            task != nullptr && !NeedIgnoreTask(task->data_->requestId_)) {
            task->executor_(task->data_);
            continue;
        }

        if (!lowPriorityTaskQueue_.Empty() && lowPriorityTaskQueue_.Pop(task) &&
            task != nullptr && !NeedIgnoreTask(task->data_->requestId_)) {
            task->executor_(task->data_);
        }
    }
}

bool ThumbnailGenerateWorker::NeedIgnoreTask(uint64_t requestId)
{
    return ignoreRequestId_ != 0 && ignoreRequestId_ == requestId;
}
} // namespace Media
} // namespace OHOS