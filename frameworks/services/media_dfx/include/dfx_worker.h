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
    DfxTask(DfxExecute executor, DfxData *data) : executor_(executor), data_(data) {}
    DfxTask() : DfxTask(nullptr, nullptr) {}
    virtual ~DfxTask()
    {
        delete data_;
        data_ = nullptr;
    }

    DfxExecute executor_;
    DfxData *data_;
};
class DfxWorker {
public:
    DfxWorker();
    ~DfxWorker();
    static std::shared_ptr<DfxWorker> GetInstance();
    void Init();
    void End();
    void AddTask(const std::shared_ptr<DfxTask> &task);

private:
    void InitCycleThread();
    void InitDelayThread();
    void Prepare();
    bool IsThumbnailUpdate();
    bool IsDeleteStatisticUpdate();
    void InitLoop();
    bool IsTaskQueueEmpty();
    void WaitForTask();
    std::shared_ptr<DfxTask> GetTask();

private:
    int64_t lastReportTime_;
    int64_t lastMiddleReportTime_;
    int32_t thumbnailVersion_;
    int32_t deleteStatisticVersion_;
    static std::shared_ptr<DfxWorker> dfxWorkerInstance_;
    std::thread cycleThread_;
    std::thread delayThread_;
    bool isEnd_ = false;
    int32_t shortTime_;
    int32_t middleTime_;
    int32_t longTime_;
    std::mutex taskLock_;
    std::mutex workLock_;
    std::condition_variable workCv_;
    std::queue<std::shared_ptr<DfxTask>> taskQueue_;
    bool isThreadRunning_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_WORKER_H