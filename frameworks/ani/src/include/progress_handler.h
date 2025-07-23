/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef PROGRESS_HANDLER_H
#define PROGRESS_HANDLER_H

#include <atomic>
#include <string>
#include "ani.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {

struct ProgressHandler;
using ThreadFunctionOnProgress = std::function<void(ProgressHandler*)>;

struct RetProgressValue {
    int32_t progress;
    int32_t type;
    std::string errorMsg;
    RetProgressValue() : progress(0), type(0), errorMsg("") {}
};

struct ProgressHandler {
    ani_vm *etsVm;
    ThreadFunctionOnProgress progressFunc;
    std::string requestId;
    ani_ref progressRef;
    RetProgressValue retProgressValue;
    ProgressHandler() : etsVm(nullptr), progressFunc(nullptr), requestId(""), progressRef(nullptr) {}
    ProgressHandler(ani_vm *etsVm, ThreadFunctionOnProgress func, const std::string &requestId,
        ani_ref progressRef) : etsVm(etsVm), progressFunc(func),
        requestId(requestId), progressRef(progressRef) {}
};

struct MovingPhotoProgressHandler {
    ani_vm *etsVm = nullptr;
    ani_ref progressHandlerRef;
    UniqueFd srcFd;
    UniqueFd destFd;
    int64_t size;
    int64_t offset;
    int32_t process;
    int32_t errCode;
    void *contextData;
    std::atomic_bool isComplete;
    ThreadFunctionOnProgress onProgressFunc;
    std::function<void(void*, int32_t)> callbackFunc;
    MovingPhotoProgressHandler() : etsVm(nullptr),  progressHandlerRef(nullptr),
        srcFd(-1), destFd(-1), size(0), offset(0), process(0), errCode(0), contextData(nullptr),
        isComplete(false), onProgressFunc(nullptr),  callbackFunc(nullptr) {}
};

} // namespace Media
} // namespace OHOS

#endif // PROGRESS_HANDLER_H
