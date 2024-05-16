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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIBRARY_THREAD_POOL_H
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIBRARY_THREAD_POOL_H

#include <thread>
#include <future>
#include <queue>
#include <vector>
#include <string>

namespace OHOS {
namespace Media {

class MediaLibrarySemaphore {
public:
    MediaLibrarySemaphore() = default;
    virtual ~MediaLibrarySemaphore() = default;

    void Signal();
    void Wait();
    void NotifyAll();

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int32_t count_ = 0;
};

class ThreadPoolTaskQueue {
public:
    ThreadPoolTaskQueue() = default;
    bool IsEmpty();
    void PushTask(std::function<void()> func);
    std::function<void()> GetTask();

private:
    std::queue<std::function<void()>> taskQueue_;
    std::mutex mutex_;
};

class MediaLibraryThreadPool {
public:
    MediaLibraryThreadPool(int corePoolSize);
    ~MediaLibraryThreadPool();
    void ShutDownThreadPool();

    template <typename F, typename... Args>
    auto Submit(F &&f, Args &&...args) -> std::future<decltype(f(args...))>
    {
        std::function<decltype(f(args...))()> function = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
        auto task = std::make_shared<std::packaged_task<decltype(f(args...))()>>(function);
        std::function<void()> wapperedFunction = [task]() {
            (*task)();
        };
        workQueue_.PushTask(wapperedFunction);
        sem_.Signal();
        return task->get_future();
    }

private:
    void Worker();
    bool isShutDown_ = false;
    int corePoolSize_;
    std::mutex mutexPool_;
    MediaLibrarySemaphore sem_;
    std::vector<std::thread> workThreads_;
    ThreadPoolTaskQueue workQueue_;
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIBRARY_THREAD_POOL_H