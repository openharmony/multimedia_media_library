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

#define MLOG_TAG "AnalysisHandler"

#include "analysis_handler.h"

#include "medialibrary_errno.h"
#include "medialibrary_period_worker.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_utils.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "power_efficiency_manager.h"
#include "result_set_utils.h"
#include "vision_column.h"

using namespace std;

namespace OHOS {
namespace Media {

using ChangeType = DataShare::DataShareObserver::ChangeType;

std::mutex AnalysisHandler::mtx_;
queue<CloudSyncHandleData> AnalysisHandler::taskQueue_;
std::atomic<uint16_t> AnalysisHandler::counts_(0);
static constexpr uint16_t HANDLE_IDLING_TIME = 5;

AnalysisHandler::~AnalysisHandler() {}

static vector<string> GetFileIds(const CloudSyncHandleData &handleData)
{
    vector<string> fileIds;
    for (auto &uri : handleData.orgInfo.uris) {
        string uriString = uri.ToString();
        auto index = uriString.rfind('/');
        if (index == string::npos) {
            continue;
        }
        auto fileIdStr = uriString.substr(index + 1);
        fileIds.push_back(fileIdStr);
    }
    return fileIds;
}

static list<Uri> UpdateAnalysisAlbumsForCloudSync(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    vector<string> albumIds, const vector<string> &fileIds)
{
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIds, fileIds);
    list<Uri> sendUris;
    for (auto albumId : albumIds) {
        sendUris.push_back(Uri(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX + albumId));
    }

    return sendUris;
}

static void AddNewNotify(CloudSyncHandleData &handleData, const list<Uri> &sendUris)
{
    if (sendUris.size() <= 0) {
        return;
    }
    ChangeType changeType = static_cast<ChangeType>(NotifyType::NOTIFY_UPDATE);
    if (handleData.notifyInfo.find(changeType) == handleData.notifyInfo.end()) {
        handleData.notifyInfo[changeType] = sendUris;
    } else {
        handleData.notifyInfo[changeType].insert(
            handleData.notifyInfo[changeType].end(), sendUris.begin(), sendUris.end());
    }
    return;
}

static int32_t GetHandleData(CloudSyncHandleData &handleData)
{
    lock_guard<mutex> lockGuard(AnalysisHandler::mtx_);
    if (AnalysisHandler::taskQueue_.empty()) {
        ++AnalysisHandler::counts_;
        if (AnalysisHandler::counts_.load() > HANDLE_IDLING_TIME) {
            auto periodWorker = MediaLibraryPeriodWorker::GetInstance();
            if (periodWorker == nullptr) {
                MEDIA_ERR_LOG("failed to get period worker instance");
                return E_ERR;
            }
            periodWorker->StopThread(PeriodTaskType::CLOUD_ANALYSIS_ALBUM);
        }
        return E_ERR;
    } else {
        AnalysisHandler::counts_.store(0);
        handleData = AnalysisHandler::taskQueue_.front();
        AnalysisHandler::taskQueue_.pop();
    }
    return E_OK;
}

static vector<string> GetAlbumIds(const shared_ptr<MediaLibraryRdbStore> rdbStore, const vector<string> &fileIds)
{
    vector<string> albumIds;
    vector<string> columns = {
        "DISTINCT (map_album)"
    };
    NativeRdb::RdbPredicates predicates(ANALYSIS_PHOTO_MAP_TABLE);
    predicates.In(PhotoMap::ASSET_ID, fileIds);
    shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed query AnalysisAlbum");
        return albumIds;
    };
    while (resultSet->GoToNextRow() == E_OK) {
        albumIds.push_back(get<string>(ResultSetUtils::GetValFromColumn(
            ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ALBUM_ID, resultSet, TYPE_STRING)));
    }
    resultSet->Close();
    return albumIds;
}

static void ProcessHandleData(PeriodTaskData *data)
{
    if (data == nullptr) {
        return;
    }
    auto analysisPeriodTaskData = static_cast<AnalysisPeriodTaskData*>(data);
    shared_ptr<BaseHandler> handle = analysisPeriodTaskData->nextHandler_;
    function<void(bool)> refreshAlbumsFunc = analysisPeriodTaskData->refreshALbumsFunc_;
    CloudSyncHandleData handleData;
    if (GetHandleData(handleData) != E_OK) {
        return;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore");
        return;
    }
    vector<string> fileIds;
    if (handleData.orgInfo.type == ChangeType::OTHER) {
        MEDIA_INFO_LOG("Update the AnalysisAlbum for ChangeType being OTHER");
        MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore);
    } else {
        fileIds = GetFileIds(handleData);
    }

    CloudSyncHandleData newHandleData = handleData;
    if (!fileIds.empty()) {
        vector<string> albumIds = GetAlbumIds(rdbStore, fileIds);
        int32_t albumSize = static_cast<int32_t>(albumIds.size());
        if (albumSize > 0) {
            int32_t fileSize = static_cast<int32_t>(fileIds.size());
            MEDIA_INFO_LOG("%{public}d files update %{public}d analysis album", fileSize, albumSize);
            list<Uri> sendUris = UpdateAnalysisAlbumsForCloudSync(rdbStore, albumIds, fileIds);
            AddNewNotify(newHandleData, sendUris);
        }
    } else {
        string uriString = newHandleData.orgInfo.uris.front().ToString();
        MEDIA_INFO_LOG("refresh: %{public}s, type: %{public}d", uriString.c_str(),
            static_cast<int32_t>(newHandleData.orgInfo.type));
        refreshAlbumsFunc(true);
    }
    if (handle != nullptr) {
        handle->Handle(newHandleData);
    }
}

void AnalysisHandler::init()
{
    auto periodWorker = MediaLibraryPeriodWorker::GetInstance();
    if (periodWorker == nullptr) {
        MEDIA_ERR_LOG("failed to get period worker instance");
        return;
    }
    if (periodWorker->IsThreadRunning(PeriodTaskType::CLOUD_ANALYSIS_ALBUM)) {
        MEDIA_DEBUG_LOG("cloud analysis album is running");
        return;
    }
    AnalysisHandler::counts_.store(0);
    AnalysisPeriodTaskData *data = new (std::nothrow) AnalysisPeriodTaskData(nextHandler_, refreshAlbumsFunc_);
    if (data == nullptr) {
        MEDIA_ERR_LOG("Failed to new taskdata");
        return;
    }
    periodWorker->StartTask(PeriodTaskType::CLOUD_ANALYSIS_ALBUM, ProcessHandleData, data);
}

void AnalysisHandler::MergeTask(const CloudSyncHandleData &handleData)
{
    lock_guard<mutex> lockGuard(AnalysisHandler::mtx_);
    if (AnalysisHandler::taskQueue_.empty()) {
        AnalysisHandler::taskQueue_.push(handleData);
        return;
    }
    CloudSyncHandleData &tempHandleData = AnalysisHandler::taskQueue_.front();
    if (tempHandleData.orgInfo.type == ChangeType::OTHER) {
        return;
    } else if (handleData.orgInfo.type == ChangeType::OTHER) {
        AnalysisHandler::taskQueue_.pop();
        AnalysisHandler::taskQueue_.push(handleData);
    } else {
        tempHandleData.orgInfo.uris.insert(
            tempHandleData.orgInfo.uris.end(), handleData.orgInfo.uris.begin(), handleData.orgInfo.uris.end());
    }
}

void AnalysisHandler::Handle(const CloudSyncHandleData &handleData)
{
    MergeTask(handleData);
}
} //namespace Media
} //namespace OHOS
