/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotosDataHandler"

#include "photos_data_handler.h"

#include <sstream>

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_file_utils.h"
#include "upgrade_restore_task_report.h"

namespace OHOS::Media {
void PhotosDataHandler::OnStart(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
{
    SetSceneCode(sceneCode).SetTaskId(taskId).SetMediaLibraryRdb(mediaLibraryRdb);
}

PhotosDataHandler &PhotosDataHandler::SetSceneCode(int32_t sceneCode)
{
    sceneCode_ = sceneCode;
    return *this;
}

PhotosDataHandler &PhotosDataHandler::SetTaskId(const std::string &taskId)
{
    taskId_ = taskId;
    return *this;
}

PhotosDataHandler &PhotosDataHandler::SetMediaLibraryRdb(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
{
    mediaLibraryRdb_ = mediaLibraryRdb;
    photosDao_.SetMediaLibraryRdb(mediaLibraryRdb);
    return *this;
}

void PhotosDataHandler::HandleDirtyFiles()
{
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t totalNumber = photosDao_.GetDirtyFilesCount();
    MEDIA_INFO_LOG("totalNumber = %{public}d", totalNumber);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    int64_t startClean = MediaFileUtils::UTCTimeMilliSeconds();
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset]() { HandleDirtyFilesBatch(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    int64_t startDelete = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t deleteCount = PhotosDataHandler::DeleteDirtyFilesInDb();
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("HANDLE_DIRTY_FILES", "",
            "total dirty count: " + std::to_string(totalNumber) +
            ", query total cost: " + std::to_string(startClean - startQuery) +
            "; clean files count: " + std::to_string(dirtyFileCleanNumber_) +
            ", clean files cost: " + std::to_string(startDelete - startClean) +
            ", failed clean files count: " + std::to_string(failedDirtyFileCleanNumber_) +
            "; clean db count: " + std::to_string(deleteCount) +
            ", delete in db cost: " + std::to_string(end - startDelete));
}

void PhotosDataHandler::HandleDirtyFilesBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start clean dirty files offset: %{public}d", offset);
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<PhotosDao::PhotosRowData> dirtyFiles = photosDao_.GetDirtyFiles(offset);
    int64_t startClean = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t count = CleanDirtyFiles(dirtyFiles);
    dirtyFileCleanNumber_ += count;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("query %{public}zu dirty files cost %{public}" PRId64", clean cost %{public}" PRId64,
        dirtyFiles.size(), startClean - startQuery, end - startClean);
}

int32_t PhotosDataHandler::CleanDirtyFiles(const std::vector<PhotosDao::PhotosRowData> &dirtyFiles)
{
    int32_t count = 0;
    CHECK_AND_RETURN_RET(!dirtyFiles.empty(), count);
    for (const auto &dirtyFile : dirtyFiles) {
        // clean cloud path
        bool deleteFileRet = MediaFileUtils::DeleteFileOrFolder(dirtyFile.data, true);
        // clean thumbs folder
        std::string thumbsFolder =
            BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::CLOUD_THUMB, dirtyFile.data);
        bool deleteThumbsRet = MediaFileUtils::DeleteFileOrFolder(thumbsFolder, false);
        if (!deleteFileRet || !deleteThumbsRet) {
            std::lock_guard<mutex> lock(cleanFailedFilesMutex_);
            MEDIA_ERR_LOG("Clean file failed, path: %{public}s, deleteFileRet: %{public}d, deleteThumbsRet: %{public}d,
                errno: %{public}d", BackupFileUtils::GarbleFilePath(dirtyFile.data, sceneCode_).c_str(),
                static_cast<int32_t>(deleteFileRet), static_cast<int32_t>(deleteThumbsRet), errno);
            cleanFailedFiles_.push_back(to_string(dirtyFile.fileId));
            failedDirtyFileCleanNumber_++;
            continue;
        }
        count++;
    }
    return count;
}

int32_t PhotosDataHandler::DeleteDirtyFilesInDb()
{
    // clean database
    NativeRdb::AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_BACKUP));
    predicates.NotIn(MediaColumn::MEDIA_ID, cleanFailedFiles_);
    int32_t changedRows = 0;
    int32_t deleteDbRet = BackupDatabaseUtils::Delete(predicates, changedRows, mediaLibraryRdb_);
    MEDIA_INFO_LOG("changedRows: %{public}d, deleteRet: %{public}d", changedRows, deleteDbRet);
    return changedRows;
}
}  // namespace OHOS::Media
