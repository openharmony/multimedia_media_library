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

#ifndef MEDIA_SCAN_EXECUTOR_H
#define MEDIA_SCAN_EXECUTOR_H

#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;

class ScanRequest {
public:
    ScanRequest() {}
    ScanRequest(string path) : path_(path) {}

    int32_t GetRequestId() const
    {
        return requestId_;
    };

    void SetRequestId(int32_t requestId)
    {
        requestId_ = requestId;
    }

    const string &GetPath() const
    {
        return path_;
    }

    void SetIsDirectory(bool isDir)
    {
        isDir_ = isDir;
    }

    bool GetIsDirectory() const
    {
        return isDir_;
    }

private:
    int32_t requestId_;
    string path_;
    bool isDir_;
};

class MediaScanExecutor {
typedef void (*callback_func)(ScanRequest);
public:
    MediaScanExecutor();
    ~MediaScanExecutor();

    void ExecuteScan(unique_ptr<ScanRequest> request);
    void SetCallbackFunction(callback_func cb_function);

private:
    const int32_t MAX_THREAD = 1;
    std::string name_;
    std::mutex lock_;
    std::vector<std::thread> scanThreads_;
    std::queue<unique_ptr<ScanRequest>> scanRequestQueue_;
    std::condition_variable conditionVariable_;
    bool exit_ = false;
    callback_func cb_function_ = nullptr;

    void HandleScanExecution();
};
} // namespace Media
} // namespace OHOS

#endif /* MEDIA_SCAN_EXECUTOR_H */