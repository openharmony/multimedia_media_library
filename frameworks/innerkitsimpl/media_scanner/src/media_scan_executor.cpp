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

namespace OHOS {
namespace Media {
using namespace std;

void MediaScanExecutor::SetCallbackFunction(callback_func cb_function)
{
    cb_function_ = cb_function;
}

void MediaScanExecutor::ExecuteScan(unique_ptr<ScanRequest> request)
{
    scanRequestQueue_.push(move(request));
    PrepareScanExecution();
}

void MediaScanExecutor::HandleScanExecution()
{
    while (!scanRequestQueue_.empty()) {
        unique_ptr<ScanRequest> sr = std::move(scanRequestQueue_.front());
        scanRequestQueue_.pop();
        cb_function_(*sr);
    }
    activeThread_--;
    return;
}

void MediaScanExecutor::PrepareScanExecution()
{
    size_t c = MAX_THREAD - activeThread_;
    for (size_t i = 0; i < c; i++) {
        if (!scanRequestQueue_.empty() && (activeThread_ < scanRequestQueue_.size())) {
            std::thread(&MediaScanExecutor::HandleScanExecution, this).detach();
            activeThread_++;
        }
    }
}
} // namespace Media
} // namespace OHOS
