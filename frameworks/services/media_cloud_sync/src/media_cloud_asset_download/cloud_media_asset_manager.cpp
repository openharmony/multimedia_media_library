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

#define MLOG_TAG "CloudMediaAssetManager"

#include "cloud_media_asset_manager.h"

#include <iostream>
#include <chrono>
#include <mutex>

#include "abs_rdb_predicates.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_types.h"
#include "cloud_sync_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_command.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_notify.h"
#include "photo_album_column.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "thumbnail_service.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
using namespace FileManagement::CloudSync;

static const std::string UNKNOWN_VALUE = "NA";
std::shared_ptr<CloudMediaAssetDownloadOperation> CloudMediaAssetManager::operation_ = nullptr;
std::mutex CloudMediaAssetManager::deleteMutex_;
std::mutex CloudMediaAssetManager::updateMutex_;
std::atomic<TaskDeleteState> CloudMediaAssetManager::doDeleteTask_ = TaskDeleteState::IDLE;
static const int32_t BATCH_LIMIT_COUNT = 200;
static const int32_t CYCLE_NUMBER = 1024 * 1024;
static const int32_t SLEEP_FOR_DELETE = 1000;
static const int32_t BATCH_NOTIFY_CLOUD_FILE = 2000;
static const std::string DELETE_DISPLAY_NAME = "cloud_media_asset_deleted";
static const int32_t ALBUM_FROM_CLOUD = 2;
static const int32_t ZERO_ASSET_OF_ALBUM = 0;
const std::string SQL_DELETE_EMPTY_CLOUD_ALBUMS = "DELETE FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
    "( " + PhotoAlbumColumns::ALBUM_IS_LOCAL + " = " + to_string(ALBUM_FROM_CLOUD) + " AND " +
    PhotoAlbumColumns::ALBUM_ID + " NOT IN ( " +
        "SELECT DISTINCT " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
        PhotoColumn::PHOTO_CLEAN_FLAG + " = " + to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)) + " ))" +
    " OR " + PhotoAlbumColumns::ALBUM_DIRTY + " = " + to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)) + ";";

CloudMediaAssetManager& CloudMediaAssetManager::GetInstance()
{
    static CloudMediaAssetManager instance;
    return instance;
}

int32_t CloudMediaAssetManager::CheckDownloadTypeOfTask(const CloudMediaDownloadType &type)
{
    if (static_cast<int32_t>(type) < static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE) ||
        static_cast<int32_t>(type) > static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_GENTLE)) {
        MEDIA_ERR_LOG("CloudMediaDownloadType invalid input. downloadType: %{public}d", static_cast<int32_t>(type));
        return E_ERR;
    }
    return E_OK;
}

int32_t CloudMediaAssetManager::StartDownloadCloudAsset(const CloudMediaDownloadType &type)
{
    if (operation_ == nullptr) {
        CloudMediaAssetDownloadOperation taskOperator;
        operation_ = taskOperator.GetInstance();
    }
    if (CheckDownloadTypeOfTask(type) != E_OK) {
        return E_ERR;
    }

    switch (operation_->GetTaskStatus()) {
        case CloudMediaAssetTaskStatus::IDLE: {
            return operation_->StartDownloadTask(static_cast<int32_t>(type));
        }
        case CloudMediaAssetTaskStatus::PAUSED: {
            return operation_->ManualActiveRecoverTask(static_cast<int32_t>(type));
        }
        case CloudMediaAssetTaskStatus::DOWNLOADING: {
            if (type == operation_->GetDownloadType()) {
                MEDIA_WARN_LOG("No status changed.");
                return E_OK;
            }
            if (type == CloudMediaDownloadType::DOWNLOAD_GENTLE) {
                return operation_->PauseDownloadTask(CloudMediaTaskPauseCause::BACKGROUND_TASK_UNAVAILABLE);
            }
            return E_ERR;
        }
        default: {
            MEDIA_ERR_LOG("StartDownloadCloudAsset failed. now: taskStatus_, %{public}d; \
                downloadType_, %{public}d. input: type, %{public}d;",
                static_cast<int32_t>(operation_->GetTaskStatus()), static_cast<int32_t>(operation_->GetDownloadType()),
                static_cast<int32_t>(type));
            return E_ERR;
        }
    }
}

int32_t CloudMediaAssetManager::RecoverDownloadCloudAsset(const CloudMediaTaskRecoverCause &cause)
{
    bool cond = (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE);
    CHECK_AND_RETURN_RET(!cond, E_ERR);

    MEDIA_INFO_LOG("enter RecoverDownloadCloudAsset, RecoverCause: %{public}d", static_cast<int32_t>(cause));
    CHECK_AND_RETURN_RET_LOG(operation_->GetTaskStatus() != CloudMediaAssetTaskStatus::DOWNLOADING, E_OK,
        "The task status is download, no need to recover.");
    int32_t ret = operation_->PassiveStatusRecoverTask(cause);
    MEDIA_INFO_LOG("end to RecoverDownloadCloudAsset, status: %{public}s, ret: %{public}d.",
        GetCloudMediaAssetTaskStatus().c_str(), ret);
    return ret;
}

void CloudMediaAssetManager::CheckStorageAndRecoverDownloadTask()
{
    if (operation_ == nullptr || operation_->GetTaskStatus() != CloudMediaAssetTaskStatus::PAUSED ||
        operation_->GetTaskPauseCause() != CloudMediaTaskPauseCause::ROM_LIMIT) {
        return;
    }
    MEDIA_INFO_LOG("begin to check storage and recover downloadTask.");
    operation_->CheckStorageAndRecoverDownloadTask();
}

int32_t CloudMediaAssetManager::PauseDownloadCloudAsset(const CloudMediaTaskPauseCause &pauseCause)
{
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        MEDIA_INFO_LOG("no need to pause");
        return E_OK;
    }
    int32_t ret = operation_->PauseDownloadTask(pauseCause);
    MEDIA_INFO_LOG("end to PauseDownloadCloudAsset, status: %{public}s, ret: %{public}d.",
        GetCloudMediaAssetTaskStatus().c_str(), ret);
    return ret;
}

int32_t CloudMediaAssetManager::CancelDownloadCloudAsset()
{
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        MEDIA_INFO_LOG("no need to cancel");
        return E_OK;
    }
    int32_t ret = operation_->CancelDownloadTask();
    operation_.reset();
    return ret;
}

void CloudMediaAssetManager::StartDeleteCloudMediaAssets()
{
    TaskDeleteState expect = TaskDeleteState::IDLE;
    if (doDeleteTask_.compare_exchange_strong(expect, TaskDeleteState::BACKGROUND_DELETE)) {
        MEDIA_INFO_LOG("start delete cloud media assets task.");
        DeleteAllCloudMediaAssetsAsync();
    }
}

void CloudMediaAssetManager::StopDeleteCloudMediaAssets()
{
    TaskDeleteState expect = TaskDeleteState::BACKGROUND_DELETE;
    if (!doDeleteTask_.compare_exchange_strong(expect, TaskDeleteState::IDLE)) {
        MEDIA_INFO_LOG("current status is not suitable for stop delete cloud media assets task.");
    }
}

int32_t CloudMediaAssetManager::DeleteBatchCloudFile(const std::vector<std::string> &fileIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("DeleteBatchCloudFile");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "DeleteBatchCloudFile failed. rdbStore is null");
    AbsRdbPredicates deletePredicates(PhotoColumn::PHOTOS_TABLE);
    deletePredicates.In(MediaColumn::MEDIA_ID, fileIds);
    int32_t deletedRows = E_HAS_DB_ERROR;
    int32_t ret = rdbStore->Delete(deletedRows, deletePredicates);
    if (ret != NativeRdb::E_OK || deletedRows <= 0) {
        MEDIA_ERR_LOG("Delete operation failed. ret %{public}d. Deleted %{public}d", ret, deletedRows);
        return E_ERR;
    }
    MEDIA_INFO_LOG("Delete operation successful. ret %{public}d. Deleted %{public}d", ret, deletedRows);
    return E_OK;
}

int32_t CloudMediaAssetManager::ReadyDataForDelete(std::vector<std::string> &fileIds, std::vector<std::string> &paths,
    std::vector<std::string> &dateTakens)
{
    MediaLibraryTracer tracer;
    tracer.Start("ReadyDataForDelete");
    MEDIA_INFO_LOG("enter ReadyDataForDelete");
    AbsRdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.EqualTo(MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    queryPredicates.Limit(BATCH_LIMIT_COUNT);
    vector<string> columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, MediaColumn::MEDIA_DATE_TAKEN};

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "ReadyDataForDelete failed. rdbStorePtr is null");
    auto resultSet = rdbStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_ERR, "ReadyDataForDelete failed. resultSet is null");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get path!");
            continue;
        }
        MEDIA_DEBUG_LOG("get path: %{public}s.", MediaFileUtils::DesensitizePath(path).c_str());
        fileIds.push_back(GetStringVal(MediaColumn::MEDIA_ID, resultSet));
        paths.push_back(path);
        dateTakens.push_back(GetStringVal(MediaColumn::MEDIA_DATE_TAKEN, resultSet));
    }
    resultSet->Close();
    return E_OK;
}

static string GetEditDataDirPath(const string &path)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    return MEDIA_EDIT_DATA_DIR + path.substr(ROOT_MEDIA_DIR.length());
}

static int32_t DeleteEditdata(const std::string &path)
{
    string editDataDirPath = GetEditDataDirPath(path);
    CHECK_AND_RETURN_RET_LOG(!editDataDirPath.empty(), E_ERR, "Cannot get editPath, path: %{private}s", path.c_str());
    if (MediaFileUtils::IsFileExists(editDataDirPath)) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::DeleteDir(editDataDirPath), E_ERR,
            "Failed to delete edit data, path: %{private}s", editDataDirPath.c_str());
    }
    return E_OK;
}

void CloudMediaAssetManager::DeleteAllCloudMediaAssetsOperation(AsyncTaskData *data)
{
    std::lock_guard<std::mutex> lock(deleteMutex_);
    MEDIA_INFO_LOG("enter DeleteAllCloudMediaAssetsOperation");
    MediaLibraryTracer tracer;
    tracer.Start("DeleteAllCloudMediaAssetsOperation");
   
    std::vector<std::string> fileIds;
    std::vector<std::string> paths;
    std::vector<std::string> dateTakens;
    int32_t cycleNumber = 0;
    while (doDeleteTask_.load() > TaskDeleteState::IDLE && cycleNumber <= CYCLE_NUMBER) {
        int32_t ret = ReadyDataForDelete(fileIds, paths, dateTakens);
        if (ret != E_OK || fileIds.empty()) {
            MEDIA_WARN_LOG("ReadyDataForDelete failed or fileIds is empty, ret: %{public}d, size: %{public}d",
                ret, static_cast<int32_t>(fileIds.size()));
            break;
        }
        bool deleteFlag = true;
        for (size_t i = 0; i < fileIds.size(); i++) {
            if (DeleteEditdata(paths[i]) != E_OK || !ThumbnailService::GetInstance()->HasInvalidateThumbnail(
                fileIds[i], PhotoColumn::PHOTOS_TABLE, paths[i], dateTakens[i])) {
                MEDIA_ERR_LOG("Delete error, path: %{public}s.", MediaFileUtils::DesensitizePath(paths[i]).c_str());
                deleteFlag = false;
                break;
            }
            MEDIA_INFO_LOG("Detele cloud file, path: %{public}s.", MediaFileUtils::DesensitizePath(paths[i]).c_str());
        }
        if (!deleteFlag) {
            MEDIA_ERR_LOG("DeleteEditdata or InvalidateThumbnail failed!");
            break;
        }
        ret = DeleteBatchCloudFile(fileIds);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("DeleteBatchCloudFile failed!");
            break;
        }
        fileIds.clear();
        paths.clear();
        dateTakens.clear();
        cycleNumber++;
        this_thread::sleep_for(chrono::milliseconds(SLEEP_FOR_DELETE));
    }
    doDeleteTask_.store(TaskDeleteState::IDLE);
}

void CloudMediaAssetManager::DeleteAllCloudMediaAssetsAsync()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Can not get asyncWorker");
        return;
    }
    shared_ptr<MediaLibraryAsyncTask> deleteAsyncTask =
        make_shared<MediaLibraryAsyncTask>(DeleteAllCloudMediaAssetsOperation, nullptr);
    if (deleteAsyncTask == nullptr) {
        MEDIA_ERR_LOG("Can not get deleteAsyncTask");
        return;
    }
    asyncWorker->AddTask(deleteAsyncTask, true);
}

static bool HasDataForUpdate(std::vector<std::string> &updateFileIds)
{
    if (!updateFileIds.empty()) {
        MEDIA_WARN_LOG("updateFileIds is not null");
        updateFileIds.clear();
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "HasDataForUpdate failed. rdbStore is null.");
    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.NotEqualTo(MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    predicates.EqualTo(PhotoColumn::PHOTO_POSITION, to_string(static_cast<int32_t>(PhotoPositionType::CLOUD)));
    predicates.Limit(BATCH_LIMIT_COUNT);
    std::vector<std::string> columns = { MediaColumn::MEDIA_ID };
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "HasDataForUpdate failed. resultSet is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
        updateFileIds.emplace_back(fileId);
    }
    resultSet->Close();
    CHECK_AND_RETURN_RET_LOG(updateFileIds.size() > 0, false, "the size of updateFileIds 0.");
    return true;
}

static int32_t UpdateCloudAssets(const std::vector<std::string> &updateFileIds)
{
    CHECK_AND_RETURN_RET_LOG(!updateFileIds.empty(), E_ERR, "updateFileIds is null.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "UpdateCloudAssets failed. rdbStore is null.");
    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, updateFileIds);

    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NEED_CLEAN));
    values.PutInt(PhotoColumn::PHOTO_DIRTY, -1);
    values.PutLong(PhotoColumn::PHOTO_CLOUD_VERSION, 0);
    values.PutNull(PhotoColumn::PHOTO_CLOUD_ID);

    int32_t changedRows = -1;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changedRows > 0), E_ERR,
        "Failed to UpdateCloudAssets, ret: %{public}d, updateRows: %{public}d", ret, changedRows);
    return E_OK;
}

static void NotifyUpdateAssetsChange(const std::vector<std::string> &notifyFileIds)
{
    CHECK_AND_RETURN_LOG(!notifyFileIds.empty(), "notifyFileIds is null.");
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "watch is null.");
    for (size_t i = 0; i < notifyFileIds.size(); i++) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, notifyFileIds[i]),
            NotifyType::NOTIFY_REMOVE);
    }
}

int32_t CloudMediaAssetManager::UpdateCloudMeidaAssets()
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateCloudMeidaAssets");
    std::lock_guard<std::mutex> lock(updateMutex_);

    int32_t cycleNumber = 0;
    std::vector<std::string> notifyFileIds = {};
    std::vector<std::string> updateFileIds = {};
    while (HasDataForUpdate(updateFileIds) && cycleNumber <= CYCLE_NUMBER) {
        int32_t ret = UpdateCloudAssets(updateFileIds);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("UpdateCloudAssets failed, ret: %{public}d", ret);
            break;
        }

        notifyFileIds.insert(notifyFileIds.end(), updateFileIds.begin(), updateFileIds.end());
        updateFileIds.clear();
        if (notifyFileIds.size() == BATCH_NOTIFY_CLOUD_FILE) {
            NotifyUpdateAssetsChange(notifyFileIds);
            notifyFileIds.clear();
        }

        cycleNumber++;
        MEDIA_INFO_LOG("cycleNumber is %{public}d", cycleNumber);
    }
    if (notifyFileIds.size() > 0) {
        NotifyUpdateAssetsChange(notifyFileIds);
        notifyFileIds.clear();
    }
    if (cycleNumber > 0) {
        MEDIA_INFO_LOG("begin to refresh all albums.");
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "UpdateCloudMeidaAssets failed. rdbStore is null.");
        MediaLibraryRdbUtils::UpdateAllAlbums(rdbStore);
        return E_OK;
    }
    return E_ERR;
}

int32_t CloudMediaAssetManager::DeleteEmptyCloudAlbums()
{
    MEDIA_INFO_LOG("start DeleteEmptyCloudAlbums.");
    MediaLibraryTracer tracer;
    tracer.Start("DeleteEmptyCloudAlbums");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "DeleteEmptyCloudAlbums failed. rdbStore is null");

    int32_t ret = rdbStore->ExecuteSql(SQL_DELETE_EMPTY_CLOUD_ALBUMS);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to delete. ret %{public}d.", ret);
    MEDIA_INFO_LOG("end DeleteEmptyCloudAlbums. ret %{public}d.", ret);
    return E_OK;
}

int32_t CloudMediaAssetManager::ForceRetainDownloadCloudMedia()
{
    MEDIA_INFO_LOG("enter ForceRetainDownloadCloudMedia.");
    MediaLibraryTracer tracer;
    tracer.Start("ForceRetainDownloadCloudMedia");
    int32_t ret = UpdateCloudMeidaAssets();
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "UpdateCloudMeidaAssets failed. ret %{public}d.", ret);
    ret = DeleteEmptyCloudAlbums();
    CHECK_AND_PRINT_LOG(ret == E_OK, "DeleteEmptyCloudAlbums failed. ret %{public}d.", ret);

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        MEDIA_INFO_LOG("begin to notify album update.");
        watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_UPDATE);
    }

    MEDIA_INFO_LOG("begin to CleanGalleryDentryFile");
    CloudSyncManager::GetInstance().CleanGalleryDentryFile();
    MEDIA_INFO_LOG("end to CleanGalleryDentryFile");

    TaskDeleteState expect = TaskDeleteState::IDLE;
    if (doDeleteTask_.compare_exchange_strong(expect, TaskDeleteState::ACTIVE_DELETE)) {
        MEDIA_INFO_LOG("start delete cloud media assets task.");
        DeleteAllCloudMediaAssetsAsync();
    } else {
        doDeleteTask_.store(TaskDeleteState::ACTIVE_DELETE);
    }
    MEDIA_INFO_LOG("end to ForceRetainDownloadCloudMedia.");
    return ret;
}

std::string CloudMediaAssetManager::GetCloudMediaAssetTaskStatus()
{
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        MEDIA_ERR_LOG("cloud media download task not exit.");
        return to_string(static_cast<int32_t>(CloudMediaAssetTaskStatus::IDLE)) + ",0,0,0,0,0";
    }
    return to_string(static_cast<int32_t>(operation_->GetTaskStatus())) + "," + operation_->GetTaskInfo() + "," +
        to_string(static_cast<int32_t>(operation_->GetTaskPauseCause()));
}

int32_t CloudMediaAssetManager::HandleCloudMediaAssetUpdateOperations(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnType()) {
        case OperationType::CLOUD_MEDIA_ASSET_TASK_START_FORCE: {
            return StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_FORCE);
        }
        case OperationType::CLOUD_MEDIA_ASSET_TASK_START_GENTLE: {
            return StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
        }
        case OperationType::CLOUD_MEDIA_ASSET_TASK_PAUSE: {
            return PauseDownloadCloudAsset(CloudMediaTaskPauseCause::USER_PAUSED);
        }
        case OperationType::CLOUD_MEDIA_ASSET_TASK_CANCEL: {
            return CancelDownloadCloudAsset();
        }
        case OperationType::CLOUD_MEDIA_ASSET_TASK_RETAIN_FORCE: {
            return ForceRetainDownloadCloudMedia();
        }
        default: {
            MEDIA_ERR_LOG("OprnType is not exit.");
            return E_ERR;
        }
    }
}

string CloudMediaAssetManager::HandleCloudMediaAssetGetTypeOperations(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnType()) {
        case OperationType::CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY: {
            return GetCloudMediaAssetTaskStatus();
        }
        default: {
            MEDIA_ERR_LOG("OprnType is not exit.");
            return "";
        }
    }
}

bool CloudMediaAssetManager::SetIsThumbnailUpdate()
{
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        return false;
    }
    if (!operation_->isThumbnailUpdate_) {
        MEDIA_INFO_LOG("Success set isThumbnailUpdate.");
        operation_->isThumbnailUpdate_ = true;
    }
    MEDIA_INFO_LOG("Update count and size of download cloud media asset.");
    if (operation_->InitDownloadTaskInfo() != E_OK) {
        MEDIA_INFO_LOG("remainCount of download cloud media assets is 0.");
        operation_->CancelDownloadTask();
    }
    return true;
}

int32_t CloudMediaAssetManager::GetTaskStatus()
{
    if (operation_ == nullptr) {
        return static_cast<int32_t>(CloudMediaAssetTaskStatus::IDLE);
    }
    return static_cast<int32_t>(operation_->GetTaskStatus());
}

int32_t CloudMediaAssetManager::GetDownloadType()
{
    if (operation_ == nullptr) {
        MEDIA_INFO_LOG("cloud media download task not exit.");
        return E_ERR;
    }
    return static_cast<int32_t>(operation_->GetDownloadType());
}

bool CloudMediaAssetManager::SetBgDownloadPermission(const bool &flag)
{
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        return false;
    }
    MEDIA_INFO_LOG("Success set isBgDownloadPermission, flag: %{public}d.", static_cast<int32_t>(flag));
    operation_->isBgDownloadPermission_ = flag;
    return true;
}
} // namespace Media
} // namespace OHOS