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

#ifndef OHOS_MEDIALIBRARY_ALBUMS_REFRESH_WORKER_H
#define OHOS_MEDIALIBRARY_ALBUMS_REFRESH_WORKER_H

#include <queue>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <condition_variable>
#include <string>
#include "userfile_manager_types.h"
#include "albums_refresh_notify.h"

namespace OHOS {
namespace Media {

class AlbumsRefreshWorker {
public:
    AlbumsRefreshWorker();
    ~AlbumsRefreshWorker();
    void StartConsumerThread();
    void AddAlbumRefreshTask(SyncNotifyInfo& info);
    void AlbumsRefreshTaskFusion();
    void GetSystemAlbumIds(SyncNotifyInfo& info, std::vector<std::string>& albumIds);
    void TryDeleteAlbum(SyncNotifyInfo &info, std::vector<std::string>& albumIds);

private:
    std::atomic<bool> stop;
    std::atomic<bool> isThreadAlive;
    std::mutex queueMutex_;
    std::condition_variable condVar_;
    std::mutex releaseMutex_;
    std::condition_variable releaseVar_;
    std::queue<SyncNotifyInfo> taskQueue_;

    void DealWithTasks();
    void TaskFusion(SyncNotifyInfo& info);
    void TaskExecute(SyncNotifyInfo& info);
    void TaskNotify(SyncNotifyInfo& info);
};
} // namespace Media
} // namespace OHOS
#endif  // OHOS_MEDIALIBRARY_ALBUMS_REFRESH_WORKER_H