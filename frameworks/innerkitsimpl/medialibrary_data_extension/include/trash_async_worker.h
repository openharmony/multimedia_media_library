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

#ifndef MEDIA_LIBRARY_TRACE_ASYNC_TASK_WORKER_H_
#define MEDIA_LIBRARY_TRACE_ASYNC_TASK_WORKER_H_

#include <condition_variable>
#include <mutex>
#include <thread>

#define EXPORT __attribute__ ((visibility ("default")))
namespace OHOS {
namespace Media {
class TrashAsyncTaskWorker {
public:
    EXPORT virtual ~TrashAsyncTaskWorker();
    EXPORT static std::shared_ptr<TrashAsyncTaskWorker> GetInstance();
    EXPORT void Interrupt();
    EXPORT void Init();
private:
    EXPORT TrashAsyncTaskWorker();
    EXPORT void StartWorker();
    static std::mutex instanceLock_;
    EXPORT static std::shared_ptr<TrashAsyncTaskWorker> asyncWorkerInstance_;
};
} // namespace Media
} // namespace OHOS

#endif  // MEDIA_LIBRARY_TRACE_ASYNC_TASK_WORKER_H_