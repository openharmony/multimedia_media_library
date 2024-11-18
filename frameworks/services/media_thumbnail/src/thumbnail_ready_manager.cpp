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

#include <thread>

#include "cloud_sync_manager.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_ready_manager.h"

using namespace std;
using namespace OHOS::FileManagement::CloudSync;
namespace OHOS {
namespace Media {
ReadyTaskManager::ReadyTaskManager()
{
    auto readyTaskData = ReadyTaskData();
    readyTaskData_ = make_shared<ReadyTaskData>(readyTaskData);
}

ReadyTaskManager* ReadyTaskManager::GetInstance()
{
    static ReadyTaskManager instance;
    return &instance;
}

void ReadyTaskManager::InitReadyTaskData()
{
    readyTaskData_->isCloudTaskFinish = true;
    readyTaskData_->isLocalTaskFinish = true;
    readyTaskData_->requestId = 0;
    readyTaskData_->downloadId = 0;
    readyTaskData_->downloadThumbMap.clear();
    readyTaskData_->cloudPaths.clear();
    readyTaskData_->localInfos.clear();
}

shared_ptr<ReadyTaskData> ReadyTaskManager::GetReadyTaskData()
{
    return readyTaskData_;
}

void ReadyTaskManager::StartReadyTaskTimer(int32_t requestId)
{
    isDownloadTaskWaiting_ = true;
    DownloadThumbTimeoutWatcherThread_ = std::thread([this, requestId] {
        this->ThumbTimeoutWatcher(requestId);
    });
}

bool ReadyTaskManager::IsDownloadThumbTimeout(int32_t requestId)
{
    std::unique_lock<std::mutex> lock(downloadThumbLock_);
    return !downloadThumbTimeoutWatcherCv_.wait_for(lock,
        std::chrono::milliseconds(THUMB_BATCH_WAIT_TIME), [this]() {
            return !isDownloadTaskWaiting_;
    });
}

void ReadyTaskManager::ThumbTimeoutWatcher(int32_t requestId)
{
    if (IsDownloadThumbTimeout(requestId)) {
        HandleDownloadThumbTimeout(requestId);
    } else {
        readyTaskData_->timeoutCount = 0;
    }
}

void ReadyTaskManager::EndDownloadThumbTimeoutWatcherThread()
{
    {
        std::unique_lock<std::mutex> lock(downloadThumbLock_);
        isDownloadTaskWaiting_ = false;
    }
    downloadThumbTimeoutWatcherCv_.notify_all();
    if (!DownloadThumbTimeoutWatcherThread_.joinable()) {
        return;
    }
    DownloadThumbTimeoutWatcherThread_.join();
    MEDIA_INFO_LOG("End Download Thumb Timeout Watcher Thread");
}

void ReadyTaskManager::HandleDownloadThumbTimeout(int32_t requestId)
{
    if (requestId <= 0 || readyTaskData_->downloadId < 0) {
        return;
    }
    readyTaskData_->timeoutCount++;
    MEDIA_INFO_LOG("download thumb timeout, timeout count is: %{public}d", readyTaskData_->timeoutCount);
    int res = CloudSyncManager::GetInstance().StopFileCache(readyTaskData_->downloadId, true);
}
} // namespace Media
} // namespace OHOS