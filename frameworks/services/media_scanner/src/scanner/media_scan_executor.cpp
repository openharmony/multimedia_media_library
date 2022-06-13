/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_scan_executor.h"
#include <thread>

namespace OHOS {
namespace Media {
using namespace std;

void MediaScanExecutor::SetCallbackFunction(callback_func cb_function)
{
    cb_function_ = cb_function;
}

void MediaScanExecutor::ExecuteScan(unique_ptr<ScanRequest> request)
{
    std::lock_guard<std::mutex> lock(mutex_);

    requestQueue_.push(move(request));

    if (activeThread_ < MAX_THREAD) {
        std::thread(&MediaScanExecutor::HandleScanExecution, this).detach();
        activeThread_++;
    }
}

void MediaScanExecutor::HandleScanExecution()
{
    unique_ptr<ScanRequest> request;
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (requestQueue_.empty()) {
                activeThread_--;
                break;
            }

            request = std::move(requestQueue_.front());
            requestQueue_.pop();
        }

        cb_function_(*request);
    }
}
} // namespace Media
} // namespace OHOS
