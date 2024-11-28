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

#ifndef THUMBNAIL_READY_MANAGER_H
#define THUMBNAIL_READY_MANAGER_H

#include "thumbnail_data.h"
#include "thumbnail_utils.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class ReadyTaskData {
public:
    bool isCloudTaskFinish{true};
    bool isLocalTaskFinish{true};
    bool allLocalFileFinished{false};
    int32_t requestId{0};
    int64_t downloadId{-1};
    int32_t timeoutCount{0};
    std::unordered_map<std::string, ThumbnailData> downloadThumbMap;
    std::vector<ThumbnailData> localInfos;
    std::vector<std::string> cloudPaths;
    ThumbRdbOpt opts;
};
class ReadyTaskManager {
public:
    ReadyTaskManager();
    ~ReadyTaskManager() = default;
    EXPORT static ReadyTaskManager* GetInstance();
    EXPORT void InitReadyTaskData();
    EXPORT std::shared_ptr<ReadyTaskData> GetReadyTaskData();
    void StartReadyTaskTimer(int32_t requestId);
    bool IsDownloadThumbTimeout(int32_t requestId);
    void EndDownloadThumbTimeoutWatcherThread();
    void ThumbTimeoutWatcher(int32_t requestId);
    void HandleDownloadThumbTimeout(int32_t requestId);
    std::shared_ptr<ReadyTaskData> readyTaskData_;
    bool isDownloadTaskWaiting_ = false;
    std::mutex downloadThumbLock_;
    std::mutex readyTaskLock_;
    std::condition_variable downloadThumbTimeoutWatcherCv_;
    std::thread DownloadThumbTimeoutWatcherThread_;
};
} // namespace Media
} // namespace OHOS

#endif // THUMBNAIL_READY_MANAGER_H