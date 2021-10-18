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

MediaScanExecutor::MediaScanExecutor() : scanThreads_(MAX_THREAD)
{
    MEDIA_INFO_LOG("MediaScanExecutor:: entered %{public}s ", __func__);
    for (size_t i = 0; i < scanThreads_.size(); i++) {
        MEDIA_INFO_LOG("MediaScanExecutor:: creating thread %zu ", i);
        scanThreads_[i] = std::thread(&MediaScanExecutor::HandleScanExecution, this);
    }
}

void MediaScanExecutor::SetCallbackFunction(callback_func cb_function)
{
    MEDIA_INFO_LOG("MediaScanExecutor:: entered %{public}s ", __func__);
    cb_function_ = cb_function;
}

void MediaScanExecutor::ExecuteScan(unique_ptr<ScanRequest> request)
{
    MEDIA_INFO_LOG("MediaScanExecutor:: entered %{public}s ", __func__);
    std::unique_lock<std::mutex> lock(lock_);
    scanRequestQueue_.push(move(request));
    // unlock the queue before notify.
    lock.unlock();
    conditionVariable_.notify_one();
}

void MediaScanExecutor::HandleScanExecution()
{
    MEDIA_INFO_LOG("MediaScanExecutor:: entered %{public}s ", __func__);
    std::unique_lock<std::mutex> lock(lock_);
    do {
        MEDIA_INFO_LOG("MediaScanExecutor:: waiting for scan");
        // Wait until we have data or executor exit.
        conditionVariable_.wait(lock, [this] { return (scanRequestQueue_.size() || exit_); });

        if (scanRequestQueue_.size() && (!exit_)) {
            unique_ptr<ScanRequest> sr = std::move(scanRequestQueue_.front());
            scanRequestQueue_.pop();
            lock.unlock();
            cb_function_(*sr);
            lock.lock();
        }
    } while (!exit_);
}

MediaScanExecutor::~MediaScanExecutor()
{
    MEDIA_INFO_LOG("MediaScanExecutor:: entered %{public}s ", __func__);
    std::unique_lock<std::mutex> lock(lock_);
    exit_ = true;
    lock.unlock(); // unlock threads to exit.
    conditionVariable_.notify_all();

    // Wait for threads to finish before exit
    for (size_t i = 0; i < scanThreads_.size(); i++) {
        if (scanThreads_[i].joinable()) {
            MEDIA_INFO_LOG("MediaScanExecutor: Joining thread %zu until completion\n", i);
            scanThreads_[i].join();
        }
    }
}
} // namespace Media
} // namespace OHOS
