/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Background"
#include <string>

#include "media_critical_label_task.h"

#include "media_column.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "medialibrary_subscriber.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "critical_label_task_queue.h"
#include "watch_lite/cloud_audit_impl.h"
#include "watch_system_handler.h"
#include "parameters.h"

using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {

static const int32_t BATCH_SIZE = 50;
static const std::string CONST_MEDIA_SECURE_ALBUM = "const.media.secure_album";

bool MediaCriticalLabelTask::Accept()
{
    return MedialibrarySubscriber::IsCriticalTypeStatusOn();
}

void MediaCriticalLabelTask::Execute()
{
    HandleCriticalLabelProcessing();
}

PhotoBatchInfo MediaCriticalLabelTask::QueryPhotosBatch(std::shared_ptr<MediaLibraryRdbStore> &rdbStore,
    int32_t page, int32_t pageSize)
{
    PhotoBatchInfo batchInfo;
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, batchInfo, "rdbStore is nullptr");
    
    int32_t offset = page * pageSize;
    std::string sql = "SELECT " + MediaColumn::MEDIA_ID + ", " + 
                    MediaColumn::MEDIA_NAME + ", " + 
                    MediaColumn::MEDIA_FILE_PATH + ", " +
                    MediaColumn::MEDIA_TYPE + ", " +
                    MediaColumn::MEDIA_DATE_ADDED +
                    " FROM " + PhotoColumn::PHOTOS_TABLE +
                    " WHERE " + PhotoColumn::PHOTO_RISK_STATUS + "= " +
                    std::to_string(static_cast<int32_t>(PhotoRiskStatus::UNIDENTIFIED)) +
                    " LIMIT " + std::to_string(pageSize) +
                    " OFFSET " + std::to_string(offset);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, batchInfo, "Query photos batch fails");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoInfo photoInfo;
        photoInfo.fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        photoInfo.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        photoInfo.filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        photoInfo.mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
        photoInfo.addedTime = GetInt32Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);

        batchInfo.emplace_back(photoInfo);
    }
    resultSet->Close();
    return batchInfo;
}

std::string MediaCriticalLabelTask::ConstructPhotoUri(const std::string &fileAssetData, 
    const std::string &displayName, int32_t fileId)
{
    return MediaFileUtils::GetFileAssetUri(fileAssetData, displayName, fileId);
}

void MediaCriticalLabelTask::SendToAnlyze(AsyncTaskData *data)
{
    if (data == nullptr) {
        MEDIA_INFO_LOG("SendToAnlyze: SendToAnlyze failed to start, data is NULL");
        return;
    }
    CriticalLabelAsyncTaskData* notifyData = static_cast<CriticalLabelAsyncTaskData*>(data);
    CHECK_AND_RETURN_LOG(notifyData != nullptr, "notifyData is empty");

    MEDIA_INFO_LOG("CriticalLabelTask: SendToAnlyze start");
    for (const auto &photo : notifyData->batchInfo) {
        std::string uri = ConstructPhotoUri(photo.filePath, photo.displayName, photo.fileId);
        MEDIA_INFO_LOG("file_id: %{public}d, display_name: %{public}s, type: %{public}d, uri: %{public}s",
            photo.fileId, photo.displayName.c_str(), photo.mediaType, uri.c_str());
        // Sepreate this part make for unit test work in phone
#ifdef MEDIALIBRARY_SECURE_ALBUM_ENABLE
    if (OHOS::system::GetParameter(CONST_MEDIA_SECURE_ALBUM, "") == "true") {
        TTLPriorityQueue::AssetParams params;
        params.display_name = photo.displayName;
        params.id = 0;
        params.priority = 1;
        params.type = photo.mediaType;
        params.uri = uri;
        params.added_time = photo.addedTime;
        auto criticalLabelTaskQueue = TTLPriorityQueue::GetInstance();
        CHECK_AND_RETURN_LOG(criticalLabelTaskQueue != nullptr, "criticalLabelTaskQueue is nullptr");
        criticalLabelTaskQueue->AddElement(params);
        MEDIA_DEBUG_LOG("non-realtime addElement, displayName: %{public}s", params.display_name.c_str());
    }
#endif
    }
}

void MediaCriticalLabelTask::HandleCriticalLabelProcessing()
{
    MEDIA_INFO_LOG("MediaCriticalLabelTask Start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");
    std::shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_LOG(asyncWorker != nullptr, "asyncWorker is nullptr");

    int32_t page = 0;
    uint32_t totalProcessed = 0;

    while (true) {
        // Check if task should continue
        if (!this->Accept()) {
            MEDIA_INFO_LOG("MediaCriticalLabelTask check condition failed, stopping at page: %{public}d", page);
            break;
        }

        // Query batch of photos
        PhotoBatchInfo batchInfo = QueryPhotosBatch(rdbStore, page, BATCH_SIZE);
        
        // If batch is empty, we're done
        if (batchInfo.empty()) {
            MEDIA_INFO_LOG("No more photos to process, iteration complete");
            break;
        }

        CriticalLabelAsyncTaskData* taskData = new (std::nothrow) CriticalLabelAsyncTaskData();
        if (taskData == nullptr) {
            MEDIA_ERR_LOG("Failed to create new taskData");
            return;
        }

        taskData->batchInfo = batchInfo;
        
        shared_ptr<MediaLibraryAsyncTask> criticalLabelAsyncTask = make_shared<MediaLibraryAsyncTask>(
            SendToAnlyze, taskData);

        if (criticalLabelAsyncTask != nullptr) {
            // Process and print each photo in the batch
            asyncWorker->AddTask(criticalLabelAsyncTask, true);
            totalProcessed+= batchInfo.size();
            // Move to next page
            page++;
        } else {
            MEDIA_ERR_LOG("Start SendToAnlyze failed");
        }
    }

    MEDIA_INFO_LOG("MediaCriticalLabelTask End, total processed: %{public}d", totalProcessed);
}
}  // namespace OHOS::Media::Background