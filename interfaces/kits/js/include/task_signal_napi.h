/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_TASK_SIGNAL_NAPI_H
#define OHOS_MEDIA_TASK_SIGNAL_NAPI_H

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <napi/native_api.h>
#include <napi/native_node_api.h>

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS::Media {
using TaskSignalCancelCallback = std::function<void()>;
class TaskSignalNapi {
public:
    EXPORT TaskSignalNapi() noexcept;
    EXPORT ~TaskSignalNapi();
    EXPORT static napi_value Init(napi_env env, napi_value exports);
    EXPORT static napi_value TaskSignalConstructor(napi_env env, napi_callback_info info);
    EXPORT static void TaskSignalDestructor(napi_env env, void *nativeObject, void *finalize_hint);
    EXPORT static napi_value Cancel(napi_env env, napi_callback_info info);
    EXPORT void SetRequestId(int32_t requestId);
    void RegisterCancelCallback(napi_env env, TaskSignalCancelCallback callback);
    EXPORT static void RegisterTaskCancelFlag(int32_t requestId, std::shared_ptr<std::atomic<bool>> cancelFlag);
    EXPORT static void UnregisterTaskCancelFlag(int32_t requestId);
public:
    bool cancelled_{false};
    int32_t requestId_;
    static thread_local napi_ref sTaskSignalConstructor_;
    std::atomic<bool> isCancelled_{false};
    std::mutex callbackMutex_;
    TaskSignalCancelCallback cancelCallback_;
};
} // namespace Media::Media

#endif // OHOS_MEDIA_TASK_SIGNAL_NAPI_H
