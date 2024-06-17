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

#ifndef OHOS_MEDIA_DFX_WORKER_H
#define OHOS_MEDIA_DFX_WORKER_H

#include <chrono>
#include <thread>
#include <queue>
#include <condition_variable>

namespace OHOS {
namespace Media {
class DfxData {
public:
    DfxData() {};
    virtual ~DfxData() {};
};

using DfxExecute = void (*)(DfxData *data);

class DfxTask {
public:
    DfxTask(DfxExecute executor, DfxData *data) : executor_(executor), data_(data),
        executeTime_{std::chrono::system_clock::now()}, isDelayTask_(false) {}
    DfxTask() : DfxTask(nullptr, nullptr) {}
    virtual ~DfxTask()
    {
        delete data_;
        data_ = nullptr;
    }

    DfxExecute executor_;
    DfxData *data_;
    std::chrono::system_clock::time_point executeTime_;
    bool isDelayTask_;
};

class DfxWorker {
public:
    DfxWorker();
    ~DfxWorker();
    static std::shared_ptr<DfxWorker> GetInstance();
    void Init();
    void End();
    void AddTask(const std::shared_ptr<DfxTask> &task, int64_t delayTime = 0);
    std::chrono::system_clock::time_point GetWaitTime();

private:
    void InitDelayThread();
    void Prepare();
    bool IsThumbnailUpdate();
    bool IsDeleteStatisticUpdate();
    void StartLoopTaskDelay();
    bool IsTaskQueueEmpty();
    void WaitForTask();
    bool IsDelayTask();
    std::shared_ptr<DfxTask> GetTask();

private:
    int32_t thumbnailVersion_ {0};
    int32_t deleteStatisticVersion_ {0};
    static std::shared_ptr<DfxWorker> dfxWorkerInstance_;
    std::thread cycleThread_;
    std::thread delayThread_;
    bool isEnd_ = false;
    std::mutex taskLock_;
    std::mutex workLock_;
    std::condition_variable workCv_;
    std::vector<std::shared_ptr<DfxTask>> taskList_;
    bool isThreadRunning_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_WORKER_H