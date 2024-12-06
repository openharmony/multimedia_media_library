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

#include <vector>
#include <string>

#include "cloud_sync_observer.h"

#include "cloud_sync_notify_handler.h"
#include "media_analysis_helper.h"
#include "medialibrary_unistore_manager.h"
#include "media_column.h"
#include "media_log.h"
#include "result_set_utils.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t SYNC_INTERVAL = 10000;
static void HandleCloudNotify(AsyncTaskData *data)
{
    auto* taskData = static_cast<CloudSyncNotifyData*>(data);
    shared_ptr<CloudSyncNotifyHandler> notifyHandler = make_shared<CloudSyncNotifyHandler>(taskData->notifyInfo_);
    notifyHandler->MakeResponsibilityChain();
}

CloudSyncObserver::CloudSyncObserver() : timer_("CloudSyncObserver")
{
    timer_.Setup();
}

void CloudSyncObserver::OnChange(const ChangeInfo &changeInfo)
{
    CloudSyncNotifyInfo notifyInfo = {changeInfo.uris_, changeInfo.changeType_};
    string uriString = notifyInfo.uris.front().ToString();
    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos && notifyInfo.type == ChangeType::OTHER) {
        lock_guard<mutex> lock(syncMutex_);
        if (!isPending_) {
            MEDIA_INFO_LOG("set timer handle index");
            timerId_ = timer_.Register(bind(&CloudSyncObserver::HandleIndex, this), SYNC_INTERVAL, true);
            isPending_ = true;
        }
    }

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

void CloudSyncObserver::HandleIndex()
{
    lock_guard<mutex> lock(syncMutex_);
    std::vector<std::string> idToDeleteIndex;
    MediaAnalysisHelper::AsyncStartMediaAnalysisService(
        static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_DELETE_INDEX), idToDeleteIndex);

    //update index
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return;
    }
    const std::string queryIdToUpdateIndex = "SELECT file_id FROM tab_analysis_search_index WHERE photo_status = 2";
    auto resultSetUpdateIndex = uniStore->QuerySql(queryIdToUpdateIndex);
    if (resultSetUpdateIndex == nullptr) {
        MEDIA_ERR_LOG("resultSetUpdateIndex is nullptr!");
        return;
    }
    std::vector<std::string> idToUpdateIndex;
    while (resultSetUpdateIndex->GoToNextRow() == NativeRdb::E_OK) {
        idToUpdateIndex.push_back(to_string(GetInt32Val("file_id", resultSetUpdateIndex)));
    }
    MEDIA_INFO_LOG("HandleIndex idToUpdateIndex size: %{public}zu", idToUpdateIndex.size());
    if (!idToUpdateIndex.empty()) {
        MediaAnalysisHelper::AsyncStartMediaAnalysisService(
            static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_UPDATE_INDEX), idToUpdateIndex);
    }
    isPending_ = false;
}
} // namespace Media
} // namespace OHOS
