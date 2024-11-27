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

#include "medialibrary_period_worker.h"
#include "media_log.h"
#include "power_efficiency_manager.h"

using namespace std;

namespace OHOS {
namespace Media {

shared_ptr<MediaLibraryPeriodWorker> MediaLibraryPeriodWorker::periodWorkerInstance_{nullptr};
mutex MediaLibraryPeriodWorker::instanceMtx_;
static constexpr int32_t THREAD_NUM = 2;

shared_ptr<MediaLibraryPeriodWorker> MediaLibraryPeriodWorker::GetInstance()
{
    if (periodWorkerInstance_ == nullptr) {
        lock_guard<mutex> lockGuard(instanceMtx_);
        periodWorkerInstance_ = shared_ptr<MediaLibraryPeriodWorker>(new MediaLibraryPeriodWorker());
        if (periodWorkerInstance_ != nullptr) {
            periodWorkerInstance_->Init();
        }
    }
    return periodWorkerInstance_;
}

MediaLibraryPeriodWorker::MediaLibraryPeriodWorker() {}

MediaLibraryPeriodWorker::~MediaLibraryPeriodWorker()
{
    for (auto &task : tasks_) {
        task.second->isThreadRunning_.store(false);
    }
    cv_.notify_all();
    for (auto &task : tasks_) {
        if (task.second->thread_.joinable()) {
            task.second->thread_.join();
        }
    }
    periodWorkerInstance_ = nullptr;
}

void MediaLibraryPeriodWorker::Init()
{
    validIds_ = vector<bool>(THREAD_NUM, false);
}

int32_t MediaLibraryPeriodWorker::AddTask(const shared_ptr<MedialibraryPeriodTask> &task)
{
    lock_guard<mutex> lockGuard(mtx_);
    int32_t threadId = GetValidId();
    if (threadId == -1) {
        MEDIA_ERR_LOG("task is over size");
        return threadId;
    }
    task->isThreadRunning_.store(true);
    task->isTaskRunning_.store(true);
    task->thread_ = thread([this, threadId]() { this->Worker(threadId); });
    tasks_[threadId] = task;
    return threadId;
}

int32_t MediaLibraryPeriodWorker::AddTask(const shared_ptr<MedialibraryPeriodTask> &task,
    shared_ptr<BaseHandler> &handle, function<void(bool)> &refreshAlbumsFunc)
{
    lock_guard<mutex> lockGuard(mtx_);
    int32_t threadId = GetValidId();
    if (threadId == -1) {
        MEDIA_ERR_LOG("task is over size");
        return threadId;
    }
    task->isThreadRunning_.store(true);
    task->isTaskRunning_.store(true);
    task->thread_ = thread([this, threadId, &handle, &refreshAlbumsFunc]() {
        this->Worker(threadId, handle, refreshAlbumsFunc);
    });
    tasks_[threadId] = task;
    return threadId;
}

int32_t MediaLibraryPeriodWorker::GetValidId()
{
    int32_t index = -1;
    for (int32_t i = 0; i < THREAD_NUM; i++) {
        if (!validIds_[i]) {
            index = i;
            validIds_[i] = true;
            break;
        }
    }
    return index;
}

void MediaLibraryPeriodWorker::StartThreadById(int32_t threadId, size_t period)
{
    lock_guard<mutex> lockGuard(mtx_);
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return;
    }
    task->second->isTaskRunning_.store(true);
    task->second->period_ = period;
    cv_.notify_all();
}

void MediaLibraryPeriodWorker::StopThreadById(int32_t threadId)
{
    lock_guard<mutex> lockGuard(mtx_);
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return;
    }
    task->second->isTaskRunning_.store(false);
}

void MediaLibraryPeriodWorker::CloseThreadById(int32_t threadId)
{
    lock_guard<mutex> lockGuard(mtx_);
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return;
    }
    task->second->isThreadRunning_.store(false);
    validIds_[threadId] = false;
    cv_.notify_all();
    if (task->second->thread_.joinable()) {
        task->second->thread_.detach();
    }
    tasks_.erase(threadId);
}

bool MediaLibraryPeriodWorker::IsThreadRunning(int32_t threadId)
{
    lock_guard<mutex> lockGuard(mtx_);
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return false;
    }
    return task->second->isThreadRunning_.load() && task->second->isTaskRunning_.load();
}

void MediaLibraryPeriodWorker::WaitForTask(const std::shared_ptr<MedialibraryPeriodTask> &task)
{
    unique_lock<mutex> lock(mtx_);
    cv_.wait(lock, [&task] { return task->isTaskRunning_.load() || !task->isThreadRunning_.load(); });
}

void MediaLibraryPeriodWorker::Worker(int32_t threadId)
{
    string name("NotifyWorker");
    pthread_setname_np(pthread_self(), name.c_str());
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return;
    }
    while (task->second->isThreadRunning_.load()) {
        WaitForTask(task->second);
        if (!task->second->isThreadRunning_.load()) {
            return;
        }
        task->second->executor_();
        this_thread::sleep_for(chrono::milliseconds(task->second->period_));
    }
}

void MediaLibraryPeriodWorker::Worker(int32_t threadId,
    shared_ptr<BaseHandler> &handle, function<void(bool)> &refreshAlbumsFunc)
{
    string name("AnalysisAlbumWorker");
    pthread_setname_np(pthread_self(), name.c_str());
    auto task = tasks_.find(threadId);
    if (task == tasks_.end()) {
        return;
    }
    while (task->second->isThreadRunning_.load()) {
        WaitForTask(task->second);
        if (!task->second->isThreadRunning_.load()) {
            return;
        }
        task->second->analysisHandlerExecutor_(handle, refreshAlbumsFunc);
        if (task->second->period_ != PowerEfficiencyManager::GetAlbumUpdateInterval()) {
            task->second->period_ = PowerEfficiencyManager::GetAlbumUpdateInterval();
        }
        this_thread::sleep_for(chrono::milliseconds(task->second->period_));
    }
}
} // namespace Media
} // namespace OHOS