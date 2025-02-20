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

#define MLOG_TAG "BackgroundCloudFileProcessor"

#include "background_cloud_file_processor.h"

#include <sys/statvfs.h>

#include "abs_rdb_predicates.h"
#include "cloud_sync_manager.h"
#include "common_timer_errors.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "metadata_extractor.h"
#include "mimetype_utils.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"
#include "photo_day_month_year_operation.h"

namespace OHOS {
namespace Media {
using namespace FileManagement::CloudSync;

static constexpr int32_t DOWNLOAD_BATCH_SIZE = 2;
static constexpr int32_t UPDATE_BATCH_CLOUD_SIZE = 2;
static constexpr int32_t UPDATE_BATCH_LOCAL_VIDEO_SIZE = 50;
static constexpr int32_t UPDATE_BATCH_LOCAL_IMAGE_SIZE = 200;
static constexpr int32_t MAX_RETRY_COUNT = 2;
static constexpr int32_t UPDATE_DAY_MONTH_YEAR_BATCH_SIZE = 200;

// The task can be performed only when the ratio of available storage capacity reaches this value
static constexpr double PROPER_DEVICE_STORAGE_CAPACITY_RATIO = 0.55;

int32_t BackgroundCloudFileProcessor::processInterval_ = PROCESS_INTERVAL;  // 5 minute
int32_t BackgroundCloudFileProcessor::downloadDuration_ = DOWNLOAD_DURATION; // 10 seconds
recursive_mutex BackgroundCloudFileProcessor::mutex_;
Utils::Timer BackgroundCloudFileProcessor::timer_("background_cloud_file_processor");
uint32_t BackgroundCloudFileProcessor::startTimerId_ = 0;
uint32_t BackgroundCloudFileProcessor::stopTimerId_ = 0;
std::vector<std::string> BackgroundCloudFileProcessor::curDownloadPaths_;
bool BackgroundCloudFileProcessor::isUpdating_ = true;
int32_t BackgroundCloudFileProcessor::cloudUpdateOffset_ = 0;
int32_t BackgroundCloudFileProcessor::localImageUpdateOffset_ = 0;
int32_t BackgroundCloudFileProcessor::localVideoUpdateOffset_ = 0;
int32_t BackgroundCloudFileProcessor::cloudRetryCount_ = 0;
bool BackgroundCloudFileProcessor::isDownload_ = false;

void BackgroundCloudFileProcessor::DownloadCloudFiles()
{
    if (!isDownload_) {
        MEDIA_DEBUG_LOG("download task is closed");
        return;
    }
    MEDIA_DEBUG_LOG("Start downloading cloud files task");
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

void BackgroundCloudFileProcessor::UpdateCloudData()
{
    MEDIA_DEBUG_LOG("Start update cloud data task");
    std::vector<QueryOption> queryList = {{false, true}, {false, false}, {true, true}};
    int32_t count = 0;
    UpdateData updateData;
    for (auto option : queryList) {
        std::shared_ptr<NativeRdb::ResultSet> resultSet = QueryUpdateData(option.isCloud, option.isVideo);
        if (resultSet == nullptr || resultSet->GetRowCount(count) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to query data, %{public}d, %{public}d", option.isCloud, option.isVideo);
            continue;
        }
        if (count == 0) {
            MEDIA_DEBUG_LOG("no need to update, %{public}d, %{public}d", option.isCloud, option.isVideo);
            continue;
        }
        ParseUpdateData(resultSet, updateData, option.isCloud, option.isVideo);
        break;
    }

    if (updateData.abnormalData.empty()) {
        MEDIA_DEBUG_LOG("No data need to update");
        return;
    }
    int32_t ret = AddUpdateDataTask(updateData);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to add update task! err: %{public}d", ret);
    }
}

void BackgroundCloudFileProcessor::UpdateAbnormalDayMonthYearExecutor(AsyncTaskData *data)
{
    auto *taskData = static_cast<UpdateAbnormalDayMonthYearData *>(data);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("taskData is nullptr!");
        return;
    }

    std::vector<std::string> fileIds = taskData->fileIds_;
    auto ret = PhotoDayMonthYearOperation::UpdateAbnormalDayMonthYear(fileIds);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to update abnormal day month year data task! err: %{public}d", ret);
    }
}

void BackgroundCloudFileProcessor::UpdateAbnormalDayMonthYear()
{
    MEDIA_DEBUG_LOG("Start update abnormal day month year data task");

    auto [ret, needUpdateFileIds] =
        PhotoDayMonthYearOperation::QueryNeedUpdateFileIds(UPDATE_DAY_MONTH_YEAR_BATCH_SIZE);

    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query abnormal day month year data! err: %{public}d", ret);
        return;
    }

    if (needUpdateFileIds.empty()) {
        MEDIA_DEBUG_LOG("No abnormal day month year data need to update");
        return;
    }

    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return;
    }

    auto *taskData = new (std::nothrow) UpdateAbnormalDayMonthYearData(needUpdateFileIds);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for update abnormal day month year data!");
        return;
    }

    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(UpdateAbnormalDayMonthYearExecutor, taskData);
    asyncWorker->AddTask(asyncTask, false);
}

void BackgroundCloudFileProcessor::ProcessCloudData()
{
    UpdateCloudData();
    DownloadCloudFiles();
    UpdateAbnormalDayMonthYear();
}

bool BackgroundCloudFileProcessor::IsStorageInsufficient()
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

std::shared_ptr<NativeRdb::ResultSet> BackgroundCloudFileProcessor::QueryCloudFiles()
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return nullptr;
    }

    const string sql = "SELECT " + PhotoColumn::MEDIA_FILE_PATH + ", " + PhotoColumn::MEDIA_TYPE +
        " FROM(SELECT COUNT(*) AS count, " + PhotoColumn::MEDIA_FILE_PATH + ", " + PhotoColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
        PhotoColumn::PHOTO_CLEAN_FLAG + " = " + std::to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)) +
        " AND " + PhotoColumn::PHOTO_POSITION + " = " + std::to_string(POSITION_CLOUD) + " AND " +
        PhotoColumn::MEDIA_FILE_PATH + " IS NOT NULL AND " + PhotoColumn::MEDIA_FILE_PATH + " != '' AND " +
        MediaColumn::MEDIA_SIZE + " > 0 AND(" + PhotoColumn::MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_IMAGE) +
        " OR " + PhotoColumn::MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_VIDEO) + ") GROUP BY " +
        PhotoColumn::MEDIA_FILE_PATH + " HAVING count = 1) ORDER BY " + PhotoColumn::MEDIA_TYPE + " DESC, " +
        MediaColumn::MEDIA_DATE_MODIFIED + " DESC LIMIT " + std::to_string(DOWNLOAD_BATCH_SIZE);

    return uniStore->QuerySql(sql);
}

void BackgroundCloudFileProcessor::ParseDownloadFiles(std::shared_ptr<NativeRdb::ResultSet> &resultSet,
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

int32_t BackgroundCloudFileProcessor::AddDownloadTask(const DownloadFiles &downloadFiles)
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

void BackgroundCloudFileProcessor::DownloadCloudFilesExecutor(AsyncTaskData *data)
{
    auto *taskData = static_cast<DownloadCloudFilesData *>(data);
    auto downloadFiles = taskData->downloadFiles_;

    MEDIA_DEBUG_LOG("Try to download %{public}zu cloud files.", downloadFiles.paths.size());
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
        stopTimerId_ = timer_.Register(StopDownloadFiles, downloadDuration_, true);
    }
}

void BackgroundCloudFileProcessor::StopDownloadFiles()
{
    for (const auto &path : curDownloadPaths_) {
        MEDIA_INFO_LOG("Try to Stop downloading cloud file, the path is %{public}s", path.c_str());
        int32_t ret = CloudSyncManager::GetInstance().StopDownloadFile(path);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Stop downloading cloud file failed, err: %{public}d, path: %{public}s", ret, path.c_str());
        }
    }
    curDownloadPaths_.clear();
}

void BackgroundCloudFileProcessor::SetPredicates(NativeRdb::RdbPredicates &predicates, bool isCloud, bool isVideo)
{
    if (isCloud) {
        predicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD))
            ->OrderByAsc(MediaColumn::MEDIA_ID)
            ->Limit(cloudUpdateOffset_, UPDATE_BATCH_CLOUD_SIZE);
    } else {
        if (isVideo) {
            predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD))->And()
                ->BeginWrap()
                ->EqualTo(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_VIDEO))->And()
                ->BeginWrap()
                ->EqualTo(MediaColumn::MEDIA_DURATION, 0)->Or()
                ->IsNull(MediaColumn::MEDIA_DURATION)
                ->EndWrap()
                ->EndWrap()
                ->OrderByAsc(MediaColumn::MEDIA_ID)
                ->Limit(localVideoUpdateOffset_, UPDATE_BATCH_LOCAL_VIDEO_SIZE);
        } else {
            predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD))->And()
                ->NotEqualTo(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_VIDEO))
                ->OrderByAsc(MediaColumn::MEDIA_ID)
                ->Limit(localImageUpdateOffset_, UPDATE_BATCH_LOCAL_IMAGE_SIZE);
        }
    }
}

std::shared_ptr<NativeRdb::ResultSet> BackgroundCloudFileProcessor::QueryUpdateData(bool isCloud, bool isVideo)
{
    const std::vector<std::string> columns = { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH,
        MediaColumn::MEDIA_TYPE, MediaColumn::MEDIA_SIZE,
        PhotoColumn::PHOTO_WIDTH, PhotoColumn::PHOTO_HEIGHT,
        MediaColumn::MEDIA_MIME_TYPE, MediaColumn::MEDIA_DURATION };

    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.BeginWrap()
        ->EqualTo(MediaColumn::MEDIA_SIZE, 0)
        ->Or()
        ->IsNull(MediaColumn::MEDIA_SIZE)
        ->Or()
        ->EqualTo(PhotoColumn::PHOTO_WIDTH, 0)
        ->Or()
        ->IsNull(PhotoColumn::PHOTO_WIDTH)
        ->Or()
        ->EqualTo(PhotoColumn::PHOTO_HEIGHT, 0)
        ->Or()
        ->IsNull(PhotoColumn::PHOTO_HEIGHT)
        ->Or()
        ->EqualTo(MediaColumn::MEDIA_MIME_TYPE, "")
        ->Or()
        ->IsNull(MediaColumn::MEDIA_MIME_TYPE)
        ->Or()
        ->BeginWrap()
        ->EqualTo(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_VIDEO))
        ->And()
        ->BeginWrap()
        ->EqualTo(MediaColumn::MEDIA_DURATION, 0)
        ->Or()
        ->IsNull(MediaColumn::MEDIA_DURATION)
        ->EndWrap()
        ->EndWrap()
        ->EndWrap()
        ->And()
        ->EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0)
        ->And()
        ->EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE))
        ->And()
        ->EqualTo(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN))
        ->And();
    SetPredicates(predicates, isCloud, isVideo);
    return MediaLibraryRdbStore::Query(predicates, columns);
}

void BackgroundCloudFileProcessor::ParseUpdateData(std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    UpdateData &updateData, bool isCloud, bool isVideo)
{
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        int64_t size =
            get<int64_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_SIZE, resultSet, TYPE_INT64));
        int32_t width =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_WIDTH, resultSet, TYPE_INT32));
        int32_t height =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_HEIGHT, resultSet, TYPE_INT32));
        int32_t duration =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_DURATION, resultSet, TYPE_INT32));
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get data path");
            continue;
        }
        std::string mimeType =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_MIME_TYPE, resultSet, TYPE_STRING));
        int32_t mediaType =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_TYPE, resultSet, TYPE_INT32));

        AbnormalData abnormalData;
        abnormalData.fileId = fileId;
        abnormalData.path = path;
        abnormalData.size = size;
        abnormalData.width = width;
        abnormalData.height = height;
        abnormalData.duration = duration;
        abnormalData.mimeType = mimeType;
        abnormalData.isCloud = isCloud;
        abnormalData.isVideo = isVideo;

        if (isCloud && mediaType == static_cast<int32_t>(MEDIA_TYPE_VIDEO)) {
            updateData.abnormalData.clear();
            abnormalData.mediaType = MEDIA_TYPE_VIDEO;
            updateData.abnormalData.push_back(abnormalData);
            return;
        }
        abnormalData.mediaType = static_cast<MediaType>(mediaType);
        updateData.abnormalData.push_back(abnormalData);
    }
}

int32_t BackgroundCloudFileProcessor::AddUpdateDataTask(const UpdateData &updateData)
{
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }

    auto *taskData = new (std::nothrow) UpdateAbnormalData(updateData);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for update cloud data!");
        return E_NO_MEMORY;
    }

    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(UpdateCloudDataExecutor, taskData);
    asyncWorker->AddTask(asyncTask, false);
    return E_OK;
}

void BackgroundCloudFileProcessor::UpdateCurrentOffset(bool isCloud, bool isVideo)
{
    if (isCloud) {
        if (cloudRetryCount_ >= MAX_RETRY_COUNT) {
            cloudUpdateOffset_ += 1;
            cloudRetryCount_ = 0;
        } else {
            cloudRetryCount_ += 1;
        }
        MEDIA_INFO_LOG("cloudUpdateOffset_ is %{public}d, cloudRetryCount_ is %{public}d",
            cloudUpdateOffset_, cloudRetryCount_);
        return;
    }
    if (isVideo) {
        localVideoUpdateOffset_++;
        MEDIA_INFO_LOG("localVideoUpdateOffset_ is %{public}d", localVideoUpdateOffset_);
    } else {
        localImageUpdateOffset_++;
        MEDIA_INFO_LOG("localImageUpdateOffset_ is %{public}d", localImageUpdateOffset_);
    }
}

void BackgroundCloudFileProcessor::UpdateCloudDataExecutor(AsyncTaskData *data)
{
    auto *taskData = static_cast<UpdateAbnormalData *>(data);
    auto updateData = taskData->updateData_;

    MEDIA_INFO_LOG("start update %{public}zu cloud files.", updateData.abnormalData.size());
    for (const auto &abnormalData : updateData.abnormalData) {
        if (!isUpdating_) {
            MEDIA_INFO_LOG("stop update data, isUpdating_ is %{public}d.", isUpdating_);
            return;
        }
        std::unique_ptr<Metadata> metadata = make_unique<Metadata>();
        metadata->SetFilePath(abnormalData.path);
        metadata->SetFileMediaType(abnormalData.mediaType);
        metadata->SetFileId(abnormalData.fileId);
        metadata->SetFileDuration(abnormalData.duration);
        metadata->SetFileHeight(abnormalData.height);
        metadata->SetFileWidth(abnormalData.width);
        metadata->SetFileSize(abnormalData.size);
        metadata->SetFileMimeType(abnormalData.mimeType);
        GetSizeAndMimeType(metadata);
        if (abnormalData.size == 0 || abnormalData.mimeType.empty()) {
            int64_t fileSize = metadata->GetFileSize();
            string mimeType =  metadata->GetFileMimeType();
            metadata->SetFileSize(fileSize == 0 ? -1: fileSize);
            metadata->SetFileMimeType(mimeType.empty() ? DEFAULT_IMAGE_MIME_TYPE : mimeType);
        }
        if (abnormalData.width == 0 || abnormalData.height == 0
            || (abnormalData.duration == 0 && abnormalData.mediaType == MEDIA_TYPE_VIDEO)) {
            int32_t ret = GetExtractMetadata(metadata);
            if (ret != E_OK && MediaFileUtils::IsFileExists(abnormalData.path)) {
                UpdateCurrentOffset(abnormalData.isCloud, abnormalData.isVideo);
                MEDIA_ERR_LOG("failed to get extract metadata! err: %{public}d.", ret);
                continue;
            }
            int32_t width = metadata->GetFileWidth();
            int32_t height = metadata->GetFileHeight();
            int32_t duration = metadata->GetFileDuration();
            metadata->SetFileWidth(width == 0 ? -1: width);
            metadata->SetFileHeight(height == 0 ? -1: height);
            metadata->SetFileDuration((duration == 0 && abnormalData.mediaType == MEDIA_TYPE_VIDEO) ? -1: duration);
        }
        UpdateAbnormaldata(metadata, PhotoColumn::PHOTOS_TABLE);
        if (abnormalData.isCloud) {
            cloudRetryCount_ = 0;
        }
    }
}

static void SetAbnormalValuesFromMetaData(std::unique_ptr<Metadata> &metadata, NativeRdb::ValuesBucket &values)
{
    values.PutLong(MediaColumn::MEDIA_SIZE, metadata->GetFileSize());
    values.PutInt(MediaColumn::MEDIA_DURATION, metadata->GetFileDuration());
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, metadata->GetFileHeight());
    values.PutInt(PhotoColumn::PHOTO_WIDTH, metadata->GetFileWidth());
    values.PutString(MediaColumn::MEDIA_MIME_TYPE, metadata->GetFileMimeType());
}

void BackgroundCloudFileProcessor::UpdateAbnormaldata(std::unique_ptr<Metadata> &metadata, const std::string &tableName)
{
    int32_t updateCount(0);
    NativeRdb::ValuesBucket values;
    string whereClause = MediaColumn::MEDIA_ID + " = ?";
    vector<string> whereArgs = { to_string(metadata->GetFileId()) };
    SetAbnormalValuesFromMetaData(metadata, values);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Update operation failed. rdbStore is null");
        return ;
    }
    if (!isUpdating_) {
        MEDIA_INFO_LOG("stop update data,isUpdating_ is %{public}d.", isUpdating_);
        return;
    }
    int32_t result = rdbStore->Update(updateCount, tableName, values, whereClause, whereArgs);
    if (result != NativeRdb::E_OK || updateCount <= 0) {
        MEDIA_ERR_LOG("Update operation failed. Result %{public}d. Updated %{public}d", result, updateCount);
        return ;
    }
    MEDIA_INFO_LOG("id:%{public}d, duration:%{public}d, height:%{public}d, width:%{public}d, size:%{public}" PRId64,
        metadata->GetFileId(), metadata->GetFileDuration(), metadata->GetFileHeight(), metadata->GetFileWidth(),
        metadata->GetFileSize());
}

void BackgroundCloudFileProcessor::GetSizeAndMimeType(std::unique_ptr<Metadata> &metadata)
{
    std::string path = metadata->GetFilePath();
    struct stat statInfo {};
    if (stat(path.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err %{public}d", errno);
        metadata->SetFileSize(static_cast<int64_t>(0));
    } else {
        metadata->SetFileSize(statInfo.st_size);
    }
    string extension = ScannerUtils::GetFileExtension(path);
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
    metadata->SetFileExtension(extension);
    metadata->SetFileMimeType(mimeType);
}

int32_t BackgroundCloudFileProcessor::GetExtractMetadata(std::unique_ptr<Metadata> &metadata)
{
    int32_t err = 0;
    if (metadata->GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        err = MetadataExtractor::ExtractImageMetadata(metadata);
    } else {
        err = MetadataExtractor::ExtractAVMetadata(metadata);
    }
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to extract data");
        return err;
    }
    return E_OK;
}

void BackgroundCloudFileProcessor::StopUpdateData()
{
    isUpdating_ = false;
}

void BackgroundCloudFileProcessor::StartTimer()
{
    lock_guard<recursive_mutex> lock(mutex_);
    MEDIA_INFO_LOG("Turn on the background download cloud file timer");

    if (startTimerId_ > 0) {
        timer_.Unregister(startTimerId_);
    }
    uint32_t ret = timer_.Setup();
    if (ret != Utils::TIMER_ERR_OK) {
        MEDIA_ERR_LOG("Failed to start background download cloud files timer, err: %{public}d", ret);
    }
    isUpdating_ = true;
    startTimerId_ = timer_.Register(ProcessCloudData, processInterval_);
}

void BackgroundCloudFileProcessor::StopTimer()
{
    lock_guard<recursive_mutex> lock(mutex_);
    MEDIA_INFO_LOG("Turn off the background download cloud file timer");

    timer_.Unregister(startTimerId_);
    timer_.Unregister(stopTimerId_);
    timer_.Shutdown();
    startTimerId_ = 0;
    stopTimerId_ = 0;
    StopUpdateData();
    StopDownloadFiles();
}
} // namespace Media
} // namespace OHOS
