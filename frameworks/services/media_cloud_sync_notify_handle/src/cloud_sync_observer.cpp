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

#include <chrono>
#include <vector>
#include <string>
#include <thread>

#include "cloud_sync_observer.h"

#include "cloud_sync_notify_handler.h"
#include "media_analysis_helper.h"
#include "medialibrary_unistore_manager.h"
#include "media_column.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "albums_refresh_manager.h"
#include "photo_album_column.h"
#include "albums_refresh_notify.h"
#include "notify_responsibility_chain_factory.h"

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

void CloudSyncObserver::OnChange(const ChangeInfo &changeInfo)
{
    CloudSyncNotifyInfo notifyInfo = {changeInfo.uris_, changeInfo.changeType_, changeInfo.data_};
    string uriString = notifyInfo.uris.front().ToString();
    MEDIA_DEBUG_LOG("#uriString: %{public}s, #uriSize: %{public}zu changeType: %{public}d",
        uriString.c_str(), changeInfo.uris_.size(), changeInfo.changeType_);
    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos && notifyInfo.type == ChangeType::OTHER) {
        SyncNotifyInfo info = AlbumsRefreshManager::GetInstance().GetSyncNotifyInfo(notifyInfo, PHOTO_URI_TYPE);
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        AlbumsRefreshManager::GetInstance().RefreshPhotoAlbumsBySyncNotifyInfo(rdbStore, info);
        lock_guard<mutex> lock(syncMutex_);
        if (!isPending_) {
            MEDIA_INFO_LOG("set timer handle index");
            std::thread([this]() {
                this->HandleIndex();
            }).detach();
            isPending_ = true;
        }
    }

    // 都先放到任务队列中，做保序处理，避免出现乱序现象
    if (uriString.find(PhotoAlbumColumns::ALBUM_GALLERY_CLOUD_URI_PREFIX) != string::npos) {
        // 相册刷新下行，只做cloudId到fileid的转换，通知图库
        SyncNotifyInfo info = AlbumsRefreshManager::GetInstance().GetSyncNotifyInfo(notifyInfo, ALBUM_URI_TYPE);
        AlbumsRefreshManager::GetInstance().AddAlbumRefreshTask(info);
        return;
    }
    
    if (uriString.find(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX) != string::npos) {
        if (notifyInfo.type == ChangeType::UPDATE || notifyInfo.type == ChangeType::OTHER) {
            CloudSyncHandleData handleData;
            handleData.orgInfo = notifyInfo;
            shared_ptr<BaseHandler> chain = NotifyResponsibilityChainFactory::CreateChain(GALLERY_PHOTO_DELETE);
            chain->Handle(handleData);
        }
        // 资产刷新下行，调用刷新模块
        SyncNotifyInfo info = AlbumsRefreshManager::GetInstance().GetSyncNotifyInfo(notifyInfo, PHOTO_URI_TYPE);
        AlbumsRefreshManager::GetInstance().AddAlbumRefreshTask(info);
        return;
    }

    auto *taskData = new (nothrow) CloudSyncNotifyData(notifyInfo);
    CHECK_AND_RETURN_LOG(taskData != nullptr, "Failed to new taskData");
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
    std::this_thread::sleep_for(std::chrono::milliseconds(SYNC_INTERVAL));
    lock_guard<mutex> lock(syncMutex_);
    std::vector<std::string> idToDeleteIndex;
    MediaAnalysisHelper::AsyncStartMediaAnalysisService(
        static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_DELETE_INDEX), idToDeleteIndex);

    //update index
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(uniStore != nullptr, "uniStore is nullptr!");
    const std::string queryIdToUpdateIndex = "SELECT file_id FROM tab_analysis_search_index WHERE photo_status = 2";
    auto resultSetUpdateIndex = uniStore->QuerySql(queryIdToUpdateIndex);
    CHECK_AND_RETURN_LOG(resultSetUpdateIndex != nullptr, "resultSetUpdateIndex is nullptr!");
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
