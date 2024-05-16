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

#include "medialibrary_threadpool.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
void MediaLibrarySemaphore::Signal()
{
    {
        std::unique_lock<std::mutex> lck(mutex_);
        ++count_;
    }
    cv_.notify_one();
}

void MediaLibrarySemaphore::Wait()
{
    std::unique_lock<std::mutex> lck(mutex_);
    cv_.wait(lck);
    --count_;
}

void MediaLibrarySemaphore::NotifyAll()
{
    cv_.notify_all();
}

bool ThreadPoolTaskQueue::IsEmpty()
{
    std::lock_guard<std::mutex> guardTaskQueue(mutex_);
    return taskQueue_.empty();
}

void ThreadPoolTaskQueue::PushTask(std::function<void()> func)
{
    std::lock_guard<std::mutex> guardTaskQueue(mutex_);
    taskQueue_.push(func);
}

std::function<void()> ThreadPoolTaskQueue::GetTask()
{
    std::lock_guard<std::mutex> guardTaskQueue(mutex_);
    if (taskQueue_.size() <= 0) {
        MEDIA_INFO_LOG("task queue size is 0, take task return nullptr");
        return nullptr;
    }
    auto result = taskQueue_.front();
    taskQueue_.pop();
    return result;
}

MediaLibraryThreadPool::MediaLibraryThreadPool(int corePoolSize)
    : corePoolSize_(corePoolSize)
{
    MEDIA_INFO_LOG("start initialize medialibrary thread pool");
    for (int i = 0; i < corePoolSize_; i++) {
        auto worker = [this]() {
            MediaLibraryThreadPool::Worker();
        };
        workThreads_.push_back(std::thread(worker));
    }
}

MediaLibraryThreadPool::~MediaLibraryThreadPool()
{
    ShutDownThreadPool();
}

void MediaLibraryThreadPool::ShutDownThreadPool()
{
    MEDIA_INFO_LOG("shut down thread pool");
    isShutDown_  = true;
    for (int i = 0; i < workThreads_.size(); i++) {
        if (workThreads_.at(i).joinable()) {
            workThreads_.at(i).join();
        }
    }
    sem_.NotifyAll();
}

void MediaLibraryThreadPool::Worker()
{
    while (!isShutDown_) {
        if (workQueue_.IsEmpty()) {
            sem_.Wait();
        }
        auto task = workQueue_.GetTask();
        if (task != nullptr) {
            task();
        }
    }
}
} // namespace Media
} // namespace OHOS