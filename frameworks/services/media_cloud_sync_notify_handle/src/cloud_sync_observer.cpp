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

#include "cloud_sync_observer.h"

#include "cloud_sync_notify_handler.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {

static void HandleCloudNotify(AsyncTaskData *data)
{
    auto* taskData = static_cast<CloudSyncNotifyData*>(data);
    shared_ptr<CloudSyncNotifyHandler> notifyHandler = make_shared<CloudSyncNotifyHandler>(taskData->notifyInfo_);
    notifyHandler->MakeResponsibilityChain();
}

void CloudSyncObserver::OnChange(const ChangeInfo &changeInfo)
{
    CloudSyncNotifyInfo notifyInfo = {changeInfo.uris_, changeInfo.changeType_};
    auto *taskData = new (nothrow) CloudSyncNotifyData(notifyInfo);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to new taskData");
        return;
    }
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Can not get asyncWorker");
        delete taskData;
        return;
    }
    shared_ptr<MediaLibraryAsyncTask> notifyHandleAsyncTask = make_shared<MediaLibraryAsyncTask>(
        HandleCloudNotify, taskData);
    if (notifyHandleAsyncTask != nullptr) {
        asyncWorker->AddTask(notifyHandleAsyncTask, true);
    }
}
} // namespace Media
} // namespace OHOS
