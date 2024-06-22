/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "DownloadCloudFilesBackground"

#include "download_cloud_files_background.h"

#include <sys/statvfs.h>

#include "abs_rdb_predicates.h"
#include "cloud_sync_helper.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
static constexpr int32_t DOWNLOAD_BATCH_SIZE = 5;
static constexpr int32_t LOCAL_FILES_COUNT_THRESHOLD = 10000;
static constexpr int32_t VIDEO_DOWNLOAD_MAX_SIZE = 300 * 1000 * 1000; // 300MB

// The task can be performed only when the the ratio of available storage capacity reaches this value
static constexpr double PROPER_DEVICE_STORAGE_CAPACITY_RATIO = 0.3;

void DownloadCloudFilesBackground::DownloadCloudFiles()
{
    if (IsStorageInsufficient() || IsLocalFilesExceedsThreshold()) {
        return;
    }
    auto resultSet = QueryCloudFiles();
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query cloud files!");
        return;
    }
    std::vector<std::string> photoPaths;
    FillPhotoPaths(resultSet, photoPaths);
    if (photoPaths.empty()) {
        MEDIA_DEBUG_LOG("No cloud photos exist, no need to download");
        return;
    }
    int32_t err = AddDownloadTask(photoPaths);
    if (err) {
        MEDIA_WARN_LOG("Failed to add download task! err: %{public}d", err);
    }
}

bool DownloadCloudFilesBackground::IsStorageInsufficient()
{
    struct statvfs diskInfo;
    int ret = statvfs("/data", &diskInfo);
    if (ret != 0) {
        MEDIA_ERR_LOG("Get file system status information failed, ret=%{public}d", ret);
        return false;
    }

    double freeSize = static_cast<double>(diskInfo.f_bsize) * static_cast<double>(diskInfo.f_bfree);
    double totalSize = static_cast<double>(diskInfo.f_bsize) * static_cast<double>(diskInfo.f_blocks);
    double freeRatio = freeSize / totalSize;

    return freeRatio < PROPER_DEVICE_STORAGE_CAPACITY_RATIO;
}

bool DownloadCloudFilesBackground::IsLocalFilesExceedsThreshold()
{
    const std::vector<std::string> localPositions = {
        std::to_string(POSITION_LOCAL),
        std::to_string((POSITION_LOCAL | POSITION_CLOUD)),
    };
    const std::vector<std::string> photosType = { std::to_string(MEDIA_TYPE_IMAGE), std::to_string(MEDIA_TYPE_VIDEO) };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_POSITION, localPositions);
    predicates.In(PhotoColumn::MEDIA_TYPE, photosType);
    auto resultSet = MediaLibraryRdbStore::Query(predicates, { PhotoColumn::MEDIA_ID });
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query local files!");
        return false;
    }
    int32_t count = 0;
    int32_t err = resultSet->GetRowCount(count);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
        return false;
    }
    return count > LOCAL_FILES_COUNT_THRESHOLD;
}

std::shared_ptr<NativeRdb::ResultSet> DownloadCloudFilesBackground::QueryCloudFiles()
{
    const std::vector<std::string> columns = { PhotoColumn::MEDIA_FILE_PATH, PhotoColumn::MEDIA_TYPE };

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(POSITION_CLOUD))
        ->And()
        ->IsNotNull(MediaColumn::MEDIA_FILE_PATH)
        ->And()
        ->NotEqualTo(MediaColumn::MEDIA_FILE_PATH, DEFAULT_STR)
        ->And()
        ->BeginWrap()
        ->BeginWrap()
        ->EqualTo(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_IMAGE))
        ->And()
        ->GreaterThan(MediaColumn::MEDIA_SIZE, 0)
        ->EndWrap()
        ->Or()
        ->BeginWrap()
        ->EqualTo(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_VIDEO))
        ->And()
        ->GreaterThan(MediaColumn::MEDIA_SIZE, 0)
        ->And()
        ->LessThan(MediaColumn::MEDIA_SIZE, VIDEO_DOWNLOAD_MAX_SIZE)
        ->EndWrap()
        ->EndWrap()
        ->Limit(DOWNLOAD_BATCH_SIZE);

    return MediaLibraryRdbStore::Query(predicates, columns);
}

void DownloadCloudFilesBackground::FillPhotoPaths(std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    std::vector<std::string> &photoPaths)
{
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(PhotoColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get cloud file uri!");
            continue;
        }
        int32_t mediaType =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::MEDIA_TYPE, resultSet, TYPE_INT32));
        if (mediaType == static_cast<int32_t>(MEDIA_TYPE_VIDEO)) {
            photoPaths.clear();
            photoPaths.push_back(path);
            return;
        }
        photoPaths.push_back(path);
    }
}

int32_t DownloadCloudFilesBackground::AddDownloadTask(const std::vector<std::string> &photoPaths)
{
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }
    auto *taskData = new (std::nothrow) DownloadCloudFilesData();
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for downloading cloud files!");
        return E_NO_MEMORY;
    }
    taskData->paths = photoPaths;
    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(DownloadCloudFilesExecutor, taskData);
    asyncWorker->AddTask(asyncTask, false);
    return E_OK;
}

void DownloadCloudFilesBackground::DownloadCloudFilesExecutor(AsyncTaskData *data)
{
    auto *taskData = static_cast<DownloadCloudFilesData *>(data);

    MEDIA_DEBUG_LOG("Try to download %{public}zu cloud files.", taskData->paths.size());
    for (const auto &path : taskData->paths) {
        CloudSyncHelper::GetInstance()->StartDownloadFile(path);
    }
}
} // namespace Media
} // namespace OHOS
