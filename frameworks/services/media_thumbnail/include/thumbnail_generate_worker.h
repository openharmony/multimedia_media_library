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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_WORKER_H
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_WORKER_H

#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <safe_queue.h>
#include <thread>

#include "thumbnail_utils.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
const std::string THREAD_NAME_FOREGROUND = "ThumbForeground";
const std::string THREAD_NAME_BACKGROUND = "ThumbBackground";

enum class ThumbnailTaskType {
    FOREGROUND,
    BACKGROUND,
};

enum class ThumbnailTaskPriority {
    HIGH,
    LOW,
};

class ThumbnailTaskData {
public:
    ThumbnailTaskData(ThumbRdbOpt &opts, ThumbnailData &data) : opts_(opts), thumbnailData_(data) {}

    ThumbnailTaskData(ThumbRdbOpt &opts, ThumbnailData &data,
        uint64_t requestId) : opts_(opts), thumbnailData_(data), requestId_(requestId) {}

    ~ThumbnailTaskData() = default;

    ThumbRdbOpt opts_;
    ThumbnailData thumbnailData_;
    uint64_t requestId_ = 0;
};

using ThumbnailGenerateExecute = void (*)(std::shared_ptr<ThumbnailTaskData> &data);
class ThumbnailGenerateTask {
public:
    ThumbnailGenerateTask(ThumbnailGenerateExecute executor,
        std::shared_ptr<ThumbnailTaskData> &data) : executor_(executor), data_(data) {}
    ~ThumbnailGenerateTask() = default;
    ThumbnailGenerateExecute executor_;
    std::shared_ptr<ThumbnailTaskData> data_;
};

class ThumbnailGenerateWorker {
public:
    EXPORT ThumbnailGenerateWorker() = default;
    EXPORT ~ThumbnailGenerateWorker();
    EXPORT int32_t Init(const ThumbnailTaskType &taskType);
    EXPORT int32_t ReleaseTaskQueue(const ThumbnailTaskPriority &taskPriority);
    EXPORT int32_t AddTask(
        const std::shared_ptr<ThumbnailGenerateTask> &task, const ThumbnailTaskPriority &taskPriority);
    EXPORT void IgnoreTaskByRequestId(uint64_t requestId);

private:
    void StartWorker();
    void WaitForTask();
    bool NeedIgnoreTask(uint64_t requestId);

    std::atomic<bool> isThreadRunning_ = false;
    std::list<std::thread> threads_;

    std::mutex workerLock_;
    std::condition_variable workerCv_;

    SafeQueue<std::shared_ptr<ThumbnailGenerateTask>> highPriorityTaskQueue_;
    SafeQueue<std::shared_ptr<ThumbnailGenerateTask>> lowPriorityTaskQueue_;

    std::atomic<uint64_t> ignoreRequestId_ = 0;
};
} // namespace Media
} // namespace OHOS

#endif //FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_WORKER_H