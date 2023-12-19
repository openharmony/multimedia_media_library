/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICE_MEDIA_ASYNC_WORKER_INCLUDE_MEDIALIBRARY_ASYNC_WORKER_H_
#define FRAMEWORKS_SERVICE_MEDIA_ASYNC_WORKER_INCLUDE_MEDIALIBRARY_ASYNC_WORKER_H_

#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <queue>
#include <thread>

#define ASYNC_WORKER_API_EXPORT __attribute__ ((visibility ("default")))
namespace OHOS {
namespace Media {
#define COMPILE_HIDDEN __attribute__ ((visibility ("hidden")))
class AsyncTaskData {
public:
    AsyncTaskData() {};
    virtual ~AsyncTaskData() {};
    std::string dataDisplay;
};

using MediaLibraryExecute = void (*)(AsyncTaskData *data);

class MediaLibraryAsyncTask {
public:
    MediaLibraryAsyncTask(MediaLibraryExecute executor, AsyncTaskData *data) : executor_(executor), data_(data) {}
    MediaLibraryAsyncTask() : MediaLibraryAsyncTask(nullptr, nullptr) {}
    virtual ~MediaLibraryAsyncTask()
    {
        delete data_;
        data_ = nullptr;
    }

    MediaLibraryExecute executor_;
    AsyncTaskData *data_;
};

class MediaLibraryAsyncWorker {
public:
    virtual ~MediaLibraryAsyncWorker();
    ASYNC_WORKER_API_EXPORT static std::shared_ptr<MediaLibraryAsyncWorker> GetInstance();
    ASYNC_WORKER_API_EXPORT void Interrupt();
    ASYNC_WORKER_API_EXPORT void Stop();
    ASYNC_WORKER_API_EXPORT int32_t AddTask(const std::shared_ptr<MediaLibraryAsyncTask> &task, bool isFg);

private:
    COMPILE_HIDDEN MediaLibraryAsyncWorker();
    COMPILE_HIDDEN void StartWorker(int num);
    COMPILE_HIDDEN void Init();
    COMPILE_HIDDEN std::shared_ptr<MediaLibraryAsyncTask> GetFgTask();
    COMPILE_HIDDEN std::shared_ptr<MediaLibraryAsyncTask> GetBgTask();
    COMPILE_HIDDEN void ReleaseFgTask();
    COMPILE_HIDDEN void ReleaseBgTask();
    COMPILE_HIDDEN void WaitForTask();
    COMPILE_HIDDEN bool IsFgQueueEmpty();
    COMPILE_HIDDEN bool IsBgQueueEmpty();
    COMPILE_HIDDEN void SleepFgWork();
    COMPILE_HIDDEN void SleepBgWork();

    COMPILE_HIDDEN static std::mutex instanceLock_;
    COMPILE_HIDDEN static std::shared_ptr<MediaLibraryAsyncWorker> asyncWorkerInstance_;
    COMPILE_HIDDEN std::atomic<bool> isThreadRunning_;
    COMPILE_HIDDEN std::mutex bgTaskLock_;
    COMPILE_HIDDEN std::queue<std::shared_ptr<MediaLibraryAsyncTask>> bgTaskQueue_;

    COMPILE_HIDDEN std::mutex fgTaskLock_;
    COMPILE_HIDDEN std::queue<std::shared_ptr<MediaLibraryAsyncTask>> fgTaskQueue_;

    COMPILE_HIDDEN std::mutex bgWorkLock_;
    COMPILE_HIDDEN std::condition_variable bgWorkCv_;
    COMPILE_HIDDEN std::atomic<uint32_t> doneTotal_;

    COMPILE_HIDDEN std::list<std::thread> threads_;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICE_MEDIA_ASYNC_WORKER_INCLUDE_MEDIALIBRARY_ASYNC_WORKER_H_