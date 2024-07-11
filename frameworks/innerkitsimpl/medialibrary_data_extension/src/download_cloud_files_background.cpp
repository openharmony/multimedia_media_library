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
#include "cloud_sync_manager.h"
#include "common_timer_errors.h"
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
using namespace FileManagement::CloudSync;

static constexpr int32_t DOWNLOAD_BATCH_SIZE = 5;
static constexpr int32_t DOWNLOAD_INTERVAL = 60 * 1000; // 1 minute
static constexpr int32_t DOWNLOAD_DURATION = 20 * 1000; // 20 seconds

// The task can be performed only when the ratio of available storage capacity reaches this value
static constexpr double PROPER_DEVICE_STORAGE_CAPACITY_RATIO = 0.4;

recursive_mutex DownloadCloudFilesBackground::mutex_;
Utils::Timer DownloadCloudFilesBackground::timer_("download_cloud_files_background");
uint32_t DownloadCloudFilesBackground::startTimerId_ = 0;
uint32_t DownloadCloudFilesBackground::stopTimerId_ = 0;
std::vector<std::string> DownloadCloudFilesBackground::curDownloadPaths_;

void DownloadCloudFilesBackground::DownloadCloudFiles()
{
    MEDIA_INFO_LOG("Start downloading cloud files task");
    if (IsStorageInsufficient()) {
        MEDIA_WARN_LOG("Insufficient storage space, stop downloading cloud files");
        return;
    }

    auto resultSet = QueryCloudFiles();
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query cloud files!");
        return;
    }

    DownloadFiles downloadFiles;
    ParseDownloadFiles(resultSet, downloadFiles);
    if (downloadFiles.paths.empty()) {
        MEDIA_DEBUG_LOG("No cloud files need to be downloaded");
        return;
    }

    int32_t ret = AddDownloadTask(downloadFiles);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to add download task! err: %{public}d", ret);
    }
}

bool DownloadCloudFilesBackground::IsStorageInsufficient()
{
    struct statvfs diskInfo;
    int ret = statvfs("/data", &diskInfo);
    if (ret != 0) {
        MEDIA_ERR_LOG("Get file system status information failed, err: %{public}d", ret);
        return true;
    }

    double totalSize = static_cast<double>(diskInfo.f_bsize) * static_cast<double>(diskInfo.f_blocks);
    if (totalSize < 1e-9) {
        MEDIA_ERR_LOG("Get file system total size failed, totalSize=%{public}f", totalSize);
        return true;
    }

    double freeSize = static_cast<double>(diskInfo.f_bsize) * static_cast<double>(diskInfo.f_bfree);
    double freeRatio = freeSize / totalSize;

    return freeRatio < PROPER_DEVICE_STORAGE_CAPACITY_RATIO;
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
        ->GreaterThan(MediaColumn::MEDIA_SIZE, 0)
        ->And()
        ->BeginWrap()
        ->BeginWrap()
        ->EqualTo(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_IMAGE))
        ->EndWrap()
        ->Or()
        ->BeginWrap()
        ->EqualTo(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_VIDEO))
        ->EndWrap()
        ->EndWrap()
        ->Limit(DOWNLOAD_BATCH_SIZE);

    return MediaLibraryRdbStore::Query(predicates, columns);
}

void DownloadCloudFilesBackground::ParseDownloadFiles(std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    DownloadFiles &downloadFiles)
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
            downloadFiles.paths.clear();
            downloadFiles.paths.push_back(path);
            downloadFiles.mediaType = MEDIA_TYPE_VIDEO;
            return;
        }
        downloadFiles.paths.push_back(path);
    }
    downloadFiles.mediaType = MEDIA_TYPE_IMAGE;
}

int32_t DownloadCloudFilesBackground::AddDownloadTask(const DownloadFiles &downloadFiles)
{
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }

    auto *taskData = new (std::nothrow) DownloadCloudFilesData(downloadFiles);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for downloading cloud files!");
        return E_NO_MEMORY;
    }

    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(DownloadCloudFilesExecutor, taskData);
    asyncWorker->AddTask(asyncTask, false);
    return E_OK;
}

void DownloadCloudFilesBackground::DownloadCloudFilesExecutor(AsyncTaskData *data)
{
    auto *taskData = static_cast<DownloadCloudFilesData *>(data);
    auto downloadFiles = taskData->downloadFiles_;

    MEDIA_INFO_LOG("Try to download %{public}zu cloud files.", downloadFiles.paths.size());
    for (const auto &path : downloadFiles.paths) {
        int32_t ret = CloudSyncManager::GetInstance().StartDownloadFile(path);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Failed to download cloud file, err: %{public}d, path: %{public}s", ret, path.c_str());
        }
    }

    lock_guard<recursive_mutex> lock(mutex_);
    curDownloadPaths_ = downloadFiles.paths;
    if (downloadFiles.mediaType == MEDIA_TYPE_VIDEO) {
        if (stopTimerId_ > 0) {
            timer_.Unregister(stopTimerId_);
        }
        stopTimerId_ = timer_.Register([=]() { StopDownloadFiles(downloadFiles.paths); }, DOWNLOAD_DURATION, true);
    }
}

void DownloadCloudFilesBackground::StopDownloadFiles(const std::vector<std::string> &filePaths)
{
    for (const auto &path : filePaths) {
        MEDIA_INFO_LOG("Try to Stop downloading cloud file, the path is %{public}s", path.c_str());
        int32_t ret = CloudSyncManager::GetInstance().StopDownloadFile(path);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Stop downloading cloud file failed, err: %{public}d, path: %{public}s", ret, path.c_str());
        }
    }
}

void DownloadCloudFilesBackground::StartTimer()
{
    lock_guard<recursive_mutex> lock(mutex_);
    if (startTimerId_ > 0) {
        timer_.Unregister(startTimerId_);
    }
    uint32_t ret = timer_.Setup();
    if (ret != Utils::TIMER_ERR_OK) {
        MEDIA_ERR_LOG("Failed to start background download cloud files timer, err: %{public}d", ret);
    }
    startTimerId_ = timer_.Register(DownloadCloudFiles, DOWNLOAD_INTERVAL);
}

void DownloadCloudFilesBackground::StopTimer()
{
    lock_guard<recursive_mutex> lock(mutex_);
    timer_.Unregister(startTimerId_);
    timer_.Unregister(stopTimerId_);
    timer_.Shutdown();
    startTimerId_ = 0;
    stopTimerId_ = 0;
    StopDownloadFiles(curDownloadPaths_);
}
} // namespace Media
} // namespace OHOS
