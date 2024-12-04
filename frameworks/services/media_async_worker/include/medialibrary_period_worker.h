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

#ifndef FRAMEWORKS_SERVICE_MEDIA_PERIOD_WORKER_INCLUDE_MEDIALIBRARY_ASYNC_WORKER_H_
#define FRAMEWORKS_SERVICE_MEDIA_PERIOD_WORKER_INCLUDE_MEDIALIBRARY_ASYNC_WORKER_H_

#include <atomic>
#include <condition_variable>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include "base_handler.h"

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))
#define COMPILE_HIDDEN __attribute__ ((visibility ("hidden")))

using MediaLibraryPeriodExecute = void (*)();
using AnalysisHandlerPeriodExecute = void (*)(std::shared_ptr<BaseHandler> &, std::function<void(bool)> &);

class MedialibraryPeriodTask {
public:
    MedialibraryPeriodTask(MediaLibraryPeriodExecute executor, int32_t period)
        : executor_(executor), period_(period) {}
    MedialibraryPeriodTask(AnalysisHandlerPeriodExecute executor, int32_t period)
        : analysisHandlerExecutor_(executor), period_(period) {}
    virtual ~MedialibraryPeriodTask() {}
    MediaLibraryPeriodExecute executor_{nullptr};
    AnalysisHandlerPeriodExecute analysisHandlerExecutor_{nullptr};
    std::thread thread_;
    std::atomic<bool> isThreadRunning_{false};
    std::atomic<bool> isTaskRunning_{false};
    int32_t period_{0};
};


class MediaLibraryPeriodWorker {
public:
    virtual ~MediaLibraryPeriodWorker();
    EXPORT static std::shared_ptr<MediaLibraryPeriodWorker> GetInstance();
    EXPORT void StartThreadById(int32_t threadId, int32_t period);
    EXPORT void StopThreadById(int32_t threadId);
    EXPORT void CloseThreadById(int32_t threadId);
    EXPORT bool IsThreadRunning(int32_t threadId);
    EXPORT int32_t AddTask(const std::shared_ptr<MedialibraryPeriodTask> &task);
    EXPORT int32_t AddTask(const std::shared_ptr<MedialibraryPeriodTask> &task,
        std::shared_ptr<BaseHandler> &handle, std::function<void(bool)> &refreshAlbumsFunc);

private:
    COMPILE_HIDDEN MediaLibraryPeriodWorker();
    COMPILE_HIDDEN void Init();
    COMPILE_HIDDEN int32_t GetValidId();
    COMPILE_HIDDEN void WaitForTask(const std::shared_ptr<MedialibraryPeriodTask> &task);
    COMPILE_HIDDEN void Worker(int32_t threadId);
    COMPILE_HIDDEN void Worker(int32_t threadId,
        std::shared_ptr<BaseHandler> &handle, std::function<void(bool)> &refreshAlbumsFunc);

    COMPILE_HIDDEN static std::shared_ptr<MediaLibraryPeriodWorker> periodWorkerInstance_;
    COMPILE_HIDDEN static std::mutex instanceMtx_;
    COMPILE_HIDDEN std::map<int32_t, std::shared_ptr<MedialibraryPeriodTask>> tasks_;
    COMPILE_HIDDEN std::vector<bool> validIds_;
    COMPILE_HIDDEN std::mutex mtx_;
    COMPILE_HIDDEN std::condition_variable cv_;
};

} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_NOTIFY_H