/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#include <cinttypes>

#include "abs_rdb_predicates.h"
#include "album_accurate_refresh.h"
#include "asset_accurate_refresh.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_types.h"
#include "cloud_sync_notify_handler.h"
#include "cloud_sync_helper.h"
#include "cloud_sync_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_command.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#ifdef META_RECOVERY_SUPPORT
#include "medialibrary_meta_recovery.h"
#endif
#include "medialibrary_operation.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_notify.h"
#include "parameters.h"
#include "photo_album_column.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "thumbnail_service.h"
#include "cloud_media_asset_uri.h"
#include "dfx_const.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
using namespace FileManagement::CloudSync;

static const std::string UNKNOWN_VALUE = "NA";
// batch limit count of update cloud data
constexpr int32_t BATCH_UPDATE_LIMIT_COUNT = 500;
// batch limit count of delete cloud data
constexpr int32_t BATCH_DELETE_LIMIT_COUNT = 300;
static const int32_t CYCLE_NUMBER = 1024 * 1024;
static const int32_t SLEEP_FOR_DELETE = 600;
static const int32_t BATCH_NOTIFY_CLOUD_FILE = 2000;
static const std::string DELETE_DISPLAY_NAME = "cloud_media_asset_deleted";
static const int32_t ALBUM_FROM_CLOUD = 2;
static const int32_t ZERO_ASSET_OF_ALBUM = 0;
const std::string START_QUERY_ZERO = "0";

const std::string SQL_CONDITION_EMPTY_CLOUD_ALBUMS = "FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
    "( " + PhotoAlbumColumns::ALBUM_IS_LOCAL + " = " + to_string(ALBUM_FROM_CLOUD) + " AND " +
    PhotoAlbumColumns::ALBUM_ID + " NOT IN ( " +
        "SELECT DISTINCT " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
        PhotoColumn::PHOTO_CLEAN_FLAG + " = " + to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)) + " ))" +
    " OR " + PhotoAlbumColumns::ALBUM_DIRTY + " = " + to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED));
const std::string SQL_QUERY_EMPTY_CLOUD_ALBUMS = "SELECT * " + SQL_CONDITION_EMPTY_CLOUD_ALBUMS;
const std::string SQL_DELETE_EMPTY_CLOUD_ALBUMS = "DELETE " + SQL_CONDITION_EMPTY_CLOUD_ALBUMS;

// 持久化清除状态, 防止重启后清除错误服务端的图片数据: 时间戳|0
static const std::string CLOUD_RETIAN_STATUS_KEY = "persist.multimedia.medialibrary.retain.cloud.status";
static const std::string HDC_RETIAN_STATUS_KEY = "persist.multimedia.medialibrary.retain.hdc.status";

static const std::string MEIDA_RESTORE_FLAG = "multimedia.medialibrary.restoreFlag";
static const std::string MEIDA_BACKUP_FLAG = "multimedia.medialibrary.backupFlag";

// 同步服务模块使用: 时间戳|0，时间戳表征任务正在清理中，0表示无清理任务
static const std::string CLOUDSYNC_SWITCH_STATUS_KEY = "persist.kernel.cloudsync.switch_status"; // ms

// 超时时间 ForceRetainDownloadCloudMedia
static constexpr int64_t SOUTH_DEVICE_CLEAN_DATA_TIMEOUT_MILLISECOND = 12 * 60 * 60 * 1000;
static constexpr int64_t FORCE_RETAIN_CLOUD_MEDIA_WAIT_RESTORE_TIMEOUT_SECOND = 6 * 60 * 60;
static constexpr int64_t FORCE_RETAIN_CLOUD_MEDIA_WAIT_BACKUP_TIMEOUT_SECOND = 2 * 60 * 60;
static constexpr int64_t FORCE_RETAIN_CLOUD_MEDIA_WAIT_BACKUP_OR_RESTORE_SLEEP_TIME_MILLISECOND = 15000;

static std::mutex g_syncStatusMutex;
static bool SetSystemParameter(const std::string& key, int64_t value)
{
    std::string valueStr = std::to_string(value);
    return system::SetParameter(key, valueStr);
}

static void SetSouthDeviceSyncSwitchStatus(CloudSyncStatus status)
{
    std::lock_guard<std::mutex> lock(g_syncStatusMutex);
    bool retFlag = false;
    if (status == CloudSyncStatus::CLOUD_CLEANING) {
        auto timeStamp = MediaFileUtils::UTCTimeMilliSeconds();
        retFlag = SetSystemParameter(CLOUDSYNC_SWITCH_STATUS_KEY, timeStamp);
    } else {
        retFlag = SetSystemParameter(CLOUDSYNC_SWITCH_STATUS_KEY, 0);
    }
    MEDIA_INFO_LOG("set CloudSyncStatus: %{public}d, result bool: %{public}d", static_cast<int32_t>(status), retFlag);
}

static void SetSouthDeviceCleanStatus(CloudMediaRetainType retainType, CloudSyncStatus statusKey)
{
    auto retainTypeToInt = static_cast<int32_t>(retainType);
    // 防止一直无法恢复, 使用时间戳代替开关
    int64_t timeStamp = 0;
    if (statusKey ==  CloudSyncStatus::CLOUD_CLEANING) {
        timeStamp = MediaFileUtils::UTCTimeMilliSeconds();
    }

    std::lock_guard<std::mutex> lock(g_syncStatusMutex);
    bool retFlag = false;
    if (retainType == CloudMediaRetainType::RETAIN_FORCE) {
        retFlag = SetSystemParameter(CLOUD_RETIAN_STATUS_KEY, timeStamp);
    } else if (retainType == CloudMediaRetainType::HDC_RETAIN_FORCE) {
        retFlag = SetSystemParameter(HDC_RETIAN_STATUS_KEY, timeStamp);
    } else {
        MEDIA_ERR_LOG("invalid retainType: %{public}d, status: %{public}d", retainTypeToInt, statusKey);
        return;
    }
    MEDIA_INFO_LOG("set retainType: %{public}d, status: %{public}d, result bool: %{public}d",
        retainTypeToInt, statusKey, retFlag);
}

static bool IsSouthDeviceSyncCleaning(CloudMediaRetainType retainType, bool checkTimeout = true)
{
    std::lock_guard<std::mutex> lock(g_syncStatusMutex);
    int64_t timeStamp = 0;
    if (retainType == CloudMediaRetainType::RETAIN_FORCE) {
        timeStamp = system::GetIntParameter(CLOUD_RETIAN_STATUS_KEY, timeStamp);
    } else if (retainType == CloudMediaRetainType::HDC_RETAIN_FORCE) {
        timeStamp = system::GetIntParameter(HDC_RETIAN_STATUS_KEY, timeStamp);
    } else {
        MEDIA_ERR_LOG("get invalid retainType: %{public}d", static_cast<int32_t>(retainType));
    }
    if (timeStamp == 0) {
        return false;
    }

    if (!checkTimeout) {
        return true;
    }

    auto nowTime = MediaFileUtils::UTCTimeSeconds();
    return ((nowTime - timeStamp) < SOUTH_DEVICE_CLEAN_DATA_TIMEOUT_MILLISECOND);
}

static void WaitIfBackUpingOrRestoring(const std::string& key, int64_t waitTimeout, const std::string& info = "unknown")
{
    constexpr int64_t defaultValueTime = 0;
    int64_t startTimeClone = system::GetIntParameter(key, defaultValueTime);
    int64_t startTimeWait = MediaFileUtils::UTCTimeSeconds();
    MEDIA_INFO_LOG("Wait for %{public}s to exit. startTimeWait: %{public}" PRId64
        ", startTimeClone: %{public}" PRId64, info.c_str(), startTimeWait, startTimeClone);
    while (startTimeClone > 0) {
        auto nowTime = MediaFileUtils::UTCTimeSeconds();
        if ((nowTime - startTimeWait) > waitTimeout) {
            MEDIA_WARN_LOG("[%{public}s] timeout: now: %{public}" PRId64", startTimeWait: %{public}" PRId64
                ", startTimeClone: %{public}" PRId64, info.c_str(), nowTime, startTimeWait, startTimeClone);
            break;
        }
        MEDIA_DEBUG_LOG("[%{public}s] waiting: now: %{public}" PRId64", startTimeWait: %{public}" PRId64
            ", startTimeClone: %{public}" PRId64, info.c_str(), nowTime, startTimeWait, startTimeClone);
        std::this_thread::sleep_for(chrono::milliseconds(
            FORCE_RETAIN_CLOUD_MEDIA_WAIT_BACKUP_OR_RESTORE_SLEEP_TIME_MILLISECOND));
        startTimeClone = system::GetIntParameter(key, defaultValueTime);
    }

    MEDIA_INFO_LOG("the %{public}s has exited, currtime: %{public}" PRId64,
        info.c_str(), MediaFileUtils::UTCTimeSeconds());
}

static void WaitIfBackUpingOrRestoring()
{
    WaitIfBackUpingOrRestoring(MEIDA_RESTORE_FLAG,
        FORCE_RETAIN_CLOUD_MEDIA_WAIT_RESTORE_TIMEOUT_SECOND, "db restore");

    WaitIfBackUpingOrRestoring(MEIDA_BACKUP_FLAG,
        FORCE_RETAIN_CLOUD_MEDIA_WAIT_BACKUP_TIMEOUT_SECOND, "db backup");
}

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
    operation_->ResetDownloadTryTime();
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

    operation_->ResetDownloadTryTime();
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
    bool cond = (operation_ == nullptr || operation_->GetTaskStatus() != CloudMediaAssetTaskStatus::PAUSED ||
        operation_->GetTaskPauseCause() != CloudMediaTaskPauseCause::ROM_LIMIT);
    CHECK_AND_RETURN(!cond);
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
        MEDIA_ERR_LOG("Delete db operation failed. ret %{public}d. Deleted %{public}d", ret, deletedRows);
        return E_ERR;
    }
    MEDIA_INFO_LOG("Delete db operation successful. ret %{public}d. Deleted %{public}d", ret, deletedRows);
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
    queryPredicates.Limit(BATCH_DELETE_LIMIT_COUNT);
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
        fileIds.emplace_back(GetStringVal(MediaColumn::MEDIA_ID, resultSet));
        paths.emplace_back(path);
        dateTakens.emplace_back(GetStringVal(MediaColumn::MEDIA_DATE_TAKEN, resultSet));
    }
    resultSet->Close();
    return E_OK;
}

std::string CloudMediaAssetManager::GetEditDataDirPath(const std::string &path)
{
    CHECK_AND_RETURN_RET(path.length() >= ROOT_MEDIA_DIR.length(), "");
    return MEDIA_EDIT_DATA_DIR + path.substr(ROOT_MEDIA_DIR.length());
}

int32_t CloudMediaAssetManager::DeleteEditdata(const std::string &path)
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
    fileIds.reserve(BATCH_DELETE_LIMIT_COUNT);
    std::vector<std::string> paths;
    paths.reserve(BATCH_DELETE_LIMIT_COUNT);
    std::vector<std::string> dateTakens;
    dateTakens.reserve(BATCH_DELETE_LIMIT_COUNT);
    int32_t cycleNumber = 0;
    while (doDeleteTask_.load() > TaskDeleteState::IDLE && cycleNumber <= CYCLE_NUMBER) {
        int32_t ret = ReadyDataForDelete(fileIds, paths, dateTakens);
        if (ret != E_OK || fileIds.empty()) {
            MEDIA_WARN_LOG("ReadyDataForDelete failed or fileIds is empty, ret: %{public}d, size: %{public}d",
                ret, static_cast<int32_t>(fileIds.size()));
            break;
        }
        ret = DeleteBatchCloudFile(fileIds);
        CHECK_AND_BREAK_ERR_LOG(ret == E_OK, "DeleteBatchCloudFile failed!");
        for (size_t i = 0; i < fileIds.size(); i++) {
            CHECK_AND_PRINT_LOG(DeleteEditdata(paths[i]) == E_OK, "DeleteEditdata error.");
#ifdef META_RECOVERY_SUPPORT
            CHECK_AND_PRINT_LOG(MediaLibraryMetaRecovery::DeleteMetaDataByPath(paths[i]) == E_OK,
                "DeleteMetaDataByPath error.");
#endif
            CloudSyncManager::GetInstance().CleanGalleryDentryFile(paths[i]);
        }
        MEDIA_INFO_LOG("delete thumb files.");
        CHECK_AND_PRINT_LOG(ThumbnailService::GetInstance()->BatchDeleteThumbnailDirAndAstc(PhotoColumn::PHOTOS_TABLE,
            fileIds, paths, dateTakens), "DeleteThumbnailDirAndAstc error.");
        MEDIA_INFO_LOG("delete all cloud media asset. loop: %{public}d, deleted asset number: %{public}zu",
            cycleNumber, fileIds.size());
        fileIds.clear();
        paths.clear();
        dateTakens.clear();
        cycleNumber++;
        this_thread::sleep_for(chrono::milliseconds(SLEEP_FOR_DELETE));
    }
    doDeleteTask_.store(TaskDeleteState::IDLE);
    MEDIA_INFO_LOG("exit DeleteAllCloudMediaAssetsOperation");
}

void CloudMediaAssetManager::DeleteAllCloudMediaAssetsAsync()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_LOG(asyncWorker != nullptr, "Can not get asyncWorker");

    shared_ptr<MediaLibraryAsyncTask> deleteAsyncTask =
        make_shared<MediaLibraryAsyncTask>(DeleteAllCloudMediaAssetsOperation, nullptr);
    CHECK_AND_RETURN_LOG(deleteAsyncTask != nullptr, "Can not get deleteAsyncTask");

    asyncWorker->AddTask(deleteAsyncTask, true);
}

bool CloudMediaAssetManager::HasDataForUpdate(CloudMediaRetainType retainType,
    std::vector<std::string> &updateFileIds, const std::string &lastFileId)
{
    updateFileIds.clear();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "HasDataForUpdate failed. rdbStore is null.");
    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.GreaterThan(MediaColumn::MEDIA_ID, lastFileId);
    predicates.EqualTo(PhotoColumn::PHOTO_POSITION, to_string(static_cast<int32_t>(PhotoPositionType::CLOUD)));
    predicates.NotEqualTo(MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    predicates.OrderByAsc(MediaColumn::MEDIA_ID);
    predicates.Limit(BATCH_UPDATE_LIMIT_COUNT);
    std::vector<std::string> columns = { MediaColumn::MEDIA_ID };
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "HasDataForUpdate failed. resultSet is null.");

    updateFileIds.reserve(BATCH_UPDATE_LIMIT_COUNT);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
        updateFileIds.emplace_back(fileId);
    }
    resultSet->Close();
    CHECK_AND_RETURN_RET_LOG(updateFileIds.size() > 0, false, "the size of updateFileIds 0.");
    return true;
}

int32_t CloudMediaAssetManager::UpdateCloudAssets(const std::vector<std::string> &updateFileIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateCloudAssets");
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
    MEDIA_INFO_LOG("UpdateCloudAssets successfully. ret: %{public}d, updateRows: %{public}d", ret, changedRows);
    return E_OK;
}

void CloudMediaAssetManager::NotifyUpdateAssetsChange(const std::vector<std::string> &notifyFileIds)
{
    AccurateRefresh::AssetAccurateRefresh::NotifyForReCheck();
    CHECK_AND_RETURN_LOG(!notifyFileIds.empty(), "notifyFileIds is null.");
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "watch is null.");
    for (size_t i = 0; i < notifyFileIds.size(); i++) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, notifyFileIds[i]),
            NotifyType::NOTIFY_REMOVE);
    }
}

int32_t CloudMediaAssetManager::UpdateCloudMediaAssets(CloudMediaRetainType retainType)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateCloudMediaAssets");

    int32_t cycleNumber = 0;
    std::string lastFileId = START_QUERY_ZERO;
    std::vector<std::string> notifyFileIds;
    notifyFileIds.reserve(BATCH_NOTIFY_CLOUD_FILE);
    std::vector<std::string> updateFileIds;
    int32_t actualRet = E_OK;
    MEDIA_INFO_LOG("begin UpdateCloudMediaAssets");
    while (HasDataForUpdate(retainType, updateFileIds, lastFileId) && cycleNumber <= CYCLE_NUMBER) {
        int32_t ret = UpdateCloudAssets(updateFileIds);
        if (ret != E_OK) {
            MEDIA_WARN_LOG("UpdateCloudAssets failed, and try again ret: %{public}d", ret);
            ret = UpdateCloudAssets(updateFileIds);
        }
        if (ret != E_OK) {
            MEDIA_ERR_LOG("UpdateCloudAssets failed, ret: %{public}d", ret);
            actualRet = ret;
            continue;
        }
        lastFileId = updateFileIds.back();
        notifyFileIds.insert(notifyFileIds.end(), updateFileIds.begin(), updateFileIds.end());
        if (notifyFileIds.size() >= BATCH_NOTIFY_CLOUD_FILE) {
            NotifyUpdateAssetsChange(notifyFileIds);
            notifyFileIds.clear();
        }

        cycleNumber++;
    }
    MEDIA_INFO_LOG("end UpdateCloudMediaAssets");
    if (notifyFileIds.size() > 0) {
        NotifyUpdateAssetsChange(notifyFileIds);
        notifyFileIds.clear();
    }
    if (cycleNumber > 0) {
        MEDIA_INFO_LOG("begin to refresh all albums.");
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_OK, "UpdateAllAlbums failed. rdbStore is null.");
        MediaLibraryRdbUtils::UpdateAllAlbums(rdbStore);
    }
    return actualRet;
}

int32_t CloudMediaAssetManager::DeleteEmptyCloudAlbums()
{
    MEDIA_INFO_LOG("start DeleteEmptyCloudAlbums.");
    MediaLibraryTracer tracer;
    tracer.Start("DeleteEmptyCloudAlbums");
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> albumRefresh =
        std::make_shared<AccurateRefresh::AlbumAccurateRefresh>();
    CHECK_AND_RETURN_RET_LOG(albumRefresh != nullptr, E_ERR, "DeleteEmptyCloudAlbums failed. albumRefresh is null");
    int32_t ret = albumRefresh->Init(SQL_QUERY_EMPTY_CLOUD_ALBUMS, std::vector<NativeRdb::ValueObject>());
    CHECK_AND_PRINT_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, "Failed to init albumRefresh");

    ret = albumRefresh->ExecuteSql(SQL_DELETE_EMPTY_CLOUD_ALBUMS, AccurateRefresh::RdbOperation::RDB_OPERATION_REMOVE);
    CHECK_AND_RETURN_RET_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, E_ERR,
        "Failed to delete. ret %{public}d.", ret);
    albumRefresh->Notify();
    MEDIA_INFO_LOG("end DeleteEmptyCloudAlbums. ret %{public}d.", ret);
    return E_OK;
}

bool CloudMediaAssetManager::HasLocalAndCloudAssets(CloudMediaRetainType retainType,
    std::vector<std::string> &updateFileIds, const string &lastFileId)
{
    updateFileIds.clear();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "HasLocalAndCloudAssets failed. rdbStore is null.");

    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.GreaterThan(MediaColumn::MEDIA_ID, lastFileId);
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
    predicates.Or();
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    predicates.BeginWrap();
    predicates.IsNotNull(PhotoColumn::PHOTO_CLOUD_ID);
    predicates.Or();
    predicates.NotEqualTo(PhotoColumn::PHOTO_CLOUD_VERSION, 0);
    predicates.Or();
    predicates.NotEqualTo(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    predicates.Or();
    predicates.NotEqualTo(PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE,
        static_cast<int32_t>(SouthDeviceType::SOUTH_DEVICE_NULL));
    predicates.EndWrap();
    predicates.EndWrap();
    predicates.EndWrap();
    predicates.OrderByAsc(MediaColumn::MEDIA_ID);
    predicates.Limit(BATCH_UPDATE_LIMIT_COUNT);

    std::vector<std::string> columns = { MediaColumn::MEDIA_ID };
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false,
        "HasLocalAndCloudAssets failed. resultSet is null.");

    updateFileIds.reserve(BATCH_UPDATE_LIMIT_COUNT);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
        updateFileIds.emplace_back(fileId);
    }
    resultSet->Close();
    CHECK_AND_RETURN_RET_LOG(updateFileIds.size() > 0, false, "the size of updateFileIds 0.");
    return true;
}

int32_t CloudMediaAssetManager::UpdateLocalAndCloudAssets(const std::vector<std::string> &updateFileIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLocalAndCloudAssets");
    CHECK_AND_RETURN_RET_LOG(!updateFileIds.empty(), E_ERR, "updateFileIds is null.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "UpdateLocalAndCloudAssets failed. rdbStore is null.");
    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, updateFileIds);

    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    values.PutLong(PhotoColumn::PHOTO_CLOUD_VERSION, 0);
    values.PutNull(PhotoColumn::PHOTO_CLOUD_ID);
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    values.PutInt(PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE, static_cast<int32_t>(SouthDeviceType::SOUTH_DEVICE_NULL));

    int32_t changedRows = -1;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changedRows >= 0), E_ERR,
        "Failed to UpdateLocalAndCloudAssets, ret: %{public}d, updateRows: %{public}d", ret, changedRows);
    MEDIA_INFO_LOG("UpdateLocalAndCloudAssets successfully. ret: %{public}d, updateRows: %{public}d", ret, changedRows);
    return E_OK;
}

int32_t CloudMediaAssetManager::ClearDeletedDbData()
{
    MEDIA_INFO_LOG("start ClearDeletedDbData.");
    MediaLibraryTracer tracer;
    tracer.Start("ClearDeletedDbData");

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "ClearDeletedDbData failed. rdbStore is null.");

    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_DIRTY, to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)));

    int32_t deletedRows = -1;
    auto ret = rdbStore->Delete(deletedRows, predicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && deletedRows >= 0), E_ERR,
        "Failed to ClearDeletedDbData, ret: %{public}d, deletedRows: %{public}d", ret, deletedRows);
    MEDIA_INFO_LOG("ClearDeletedDbData successfully. ret: %{public}d, deletedRows: %{public}d", ret, deletedRows);
    return E_OK;
}

int32_t CloudMediaAssetManager::UpdateBothLocalAndCloudAssets(CloudMediaRetainType retainType)
{
    MEDIA_INFO_LOG("start UpdateBothLocalAndCloudAssets.");
    MediaLibraryTracer tracer;
    tracer.Start("UpdateBothLocalAndCloudAssets");

    int32_t deleteRet = ClearDeletedDbData();
    CHECK_AND_PRINT_LOG(deleteRet == E_OK, "ClearDeletedDbData failed. ret %{public}d.", deleteRet);

    int32_t cycleNumber = 0;
    std::string lastFileId = START_QUERY_ZERO;
    std::vector<std::string> updateFileIds;
    while (HasLocalAndCloudAssets(retainType, updateFileIds, lastFileId) && cycleNumber <= CYCLE_NUMBER) {
        int32_t ret = UpdateLocalAndCloudAssets(updateFileIds);
        CHECK_AND_BREAK_ERR_LOG(ret == E_OK, "UpdateBothLocalAndCloudAssets failed, ret: %{public}d", ret);
        lastFileId = updateFileIds.back();
        cycleNumber++;
    }
    MEDIA_INFO_LOG("end UpdateBothLocalAndCloudAssets.");
    return E_OK;
}

int32_t CloudMediaAssetManager::UpdateLocalAlbums()
{
    MEDIA_INFO_LOG("start UpdateLocalAlbums.");
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLocalAlbums");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "UpdateLocalAlbums failed. rdbStore is null");

    AbsRdbPredicates predicates = AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    values.PutNull(PhotoAlbumColumns::ALBUM_CLOUD_ID);

    int32_t changedRows = E_HAS_DB_ERROR;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changedRows >= 0), E_ERR,
        "Failed to UpdateLocalAlbums, ret: %{public}d, changedRows: %{public}d", ret, changedRows);
    MEDIA_INFO_LOG("UpdateLocalAlbums successfully. ret %{public}d. changedRows %{public}d", ret, changedRows);
    return E_OK;
}

int32_t CloudMediaAssetManager::ForceRetainDownloadCloudMedia(CloudMediaRetainType retainType,
    bool needAvoidRepeatedDoing)
{
    MediaLibraryTracer tracer;
    auto retainTypeInt = static_cast<int32_t>(retainType);
    tracer.Start(std::string("ForceRetainDownloadCloudMedia") + std::to_string(retainTypeInt));
    MEDIA_INFO_LOG("enter. retainType: %{public}d", retainTypeInt);

    if (needAvoidRepeatedDoing && IsSouthDeviceSyncCleaning(retainType)) {
        MEDIA_INFO_LOG("this south device is cleaning, retainType: %{public}d", retainTypeInt);
        return E_OK;
    }

    // 判断是不是已经有个南向设备端在cleaning, 如果有也直接返回
    bool isCloudCleaning = IsSouthDeviceSyncCleaning(CloudMediaRetainType::RETAIN_FORCE);
    bool isHdcCleaning = IsSouthDeviceSyncCleaning(CloudMediaRetainType::HDC_RETAIN_FORCE);
    SetSouthDeviceCleanStatus(retainType, CloudSyncStatus::CLOUD_CLEANING);
    if (needAvoidRepeatedDoing && (isCloudCleaning || isHdcCleaning)) {
        MEDIA_INFO_LOG("some south device is cleaning. cloud: %{public}d, hdc: %{public}d",
            isCloudCleaning, isHdcCleaning);
        return E_OK;
    }
    SetSouthDeviceSyncSwitchStatus(CloudSyncStatus::CLOUD_CLEANING);

    // 主动停止端云同步
    MEDIA_INFO_LOG("ForceRetainDownloadCloudMedia StopSync bundleName:%{public}s", BUNDLE_NAME.c_str());
    CloudSyncManager::GetInstance().StopSync(BUNDLE_NAME);

    // 备份/恢复需要特殊处理，等待备份和恢复完成再清除;
    WaitIfBackUpingOrRestoring();

    auto ret = ForceRetainDownloadCloudMediaEx(retainType);
    MEDIA_INFO_LOG("ForceRetainDownloadCloudMediaEx ret: %{public}d", ret);
    SetSouthDeviceCleanStatus(retainType, CloudSyncStatus::SYNC_SWITCHED_OFF);
    isCloudCleaning = IsSouthDeviceSyncCleaning(CloudMediaRetainType::RETAIN_FORCE);
    isHdcCleaning = IsSouthDeviceSyncCleaning(CloudMediaRetainType::HDC_RETAIN_FORCE);

    if (isCloudCleaning) {
        ret |= ForceRetainDownloadCloudMediaEx(CloudMediaRetainType::RETAIN_FORCE);
        SetSouthDeviceCleanStatus(CloudMediaRetainType::RETAIN_FORCE, CloudSyncStatus::SYNC_SWITCHED_OFF);
        CHECK_AND_PRINT_LOG(ret == E_OK, "cloud force retain. ret %{public}d.", ret);
    }

    if (isHdcCleaning) {
        ret |= ForceRetainDownloadCloudMediaEx(CloudMediaRetainType::HDC_RETAIN_FORCE);
        SetSouthDeviceCleanStatus(CloudMediaRetainType::HDC_RETAIN_FORCE, CloudSyncStatus::SYNC_SWITCHED_OFF);
        CHECK_AND_PRINT_LOG(ret == E_OK, "hdc force retain. ret %{public}d.", ret);
    }
    SetSouthDeviceSyncSwitchStatus(CloudSyncStatus::SYNC_SWITCHED_OFF);

    TryToStartSync();

    MEDIA_INFO_LOG("exit. retainType: %{public}d", retainTypeInt);
    return ret;
}

int32_t CloudMediaAssetManager::ForceRetainDownloadCloudMediaEx(CloudMediaRetainType retainType)
{
    auto retainTypeInt = static_cast<int32_t>(retainType);
    MEDIA_INFO_LOG("enter ForceRetainDownloadCloudMediaEx. retainType: %{public}d", retainTypeInt);

    std::unique_lock<std::mutex> lock(updateMutex_, std::defer_lock);
    CHECK_AND_RETURN_RET_WARN_LOG(lock.try_lock(), E_ERR, // 此处的作用貌似和避免重复的逻辑一致
        "retainType: %{public}d, data is cleaning, skipping this operation", retainTypeInt);

    MediaLibraryTracer tracer;
    tracer.Start(std::string("ForceRetainDownloadCloudMediaEx, retainType:") + std::to_string(retainTypeInt));
    // 停止后台异步清理云图任务，待本次云上信息标记完后重新开启
    doDeleteTask_.store(TaskDeleteState::IDLE);

    int32_t updateRet = UpdateCloudMediaAssets(retainType);
    CHECK_AND_PRINT_LOG(updateRet == E_OK, "UpdateCloudMediaAssets failed. ret %{public}d.", updateRet);
    int32_t ret = DeleteEmptyCloudAlbums();
    CHECK_AND_PRINT_LOG(ret == E_OK, "DeleteEmptyCloudAlbums failed. ret %{public}d.", ret);
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        MEDIA_INFO_LOG("begin to notify album update.");
        watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_UPDATE);
    }

    ret = UpdateBothLocalAndCloudAssets(retainType);
    CHECK_AND_PRINT_LOG(ret == E_OK, "UpdateBothLocalAndCloudAssets failed. ret %{public}d.", ret);
    ret = UpdateLocalAlbums();
    CHECK_AND_PRINT_LOG(ret == E_OK, "UpdateLocalAlbums failed. ret %{public}d.", ret);

    MEDIA_INFO_LOG("start delete cloud media assets task.");
    doDeleteTask_.store(TaskDeleteState::ACTIVE_DELETE);
    DeleteAllCloudMediaAssetsAsync();

    CHECK_AND_RETURN_RET_WARN_LOG(updateRet == E_OK, updateRet,
        "exit ForceRetainDownloadCloudMediaEx, Type: %{public}d, updateRet: %{public}d.", retainTypeInt, updateRet);
    MEDIA_INFO_LOG("exit ForceRetainDownloadCloudMediaEx, retainType: %{public}d", retainTypeInt);
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
            return ForceRetainDownloadCloudMedia(CloudMediaRetainType::RETAIN_FORCE);
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
    CHECK_AND_RETURN_RET(operation_ != nullptr, static_cast<int32_t>(CloudMediaAssetTaskStatus::IDLE));
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
    bool cond = (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE);
    CHECK_AND_RETURN_RET(!cond, false);
    MEDIA_INFO_LOG("Success set isBgDownloadPermission, flag: %{public}d.", static_cast<int32_t>(flag));
    operation_->isBgDownloadPermission_ = flag;
    return true;
}

void CloudMediaAssetManager::RestartForceRetainCloudAssets()
{
    std::thread([&] {
        MEDIA_INFO_LOG("enter RestartForceRetainCloudAssets.");
        auto isCleaning = IsSouthDeviceSyncCleaning(CloudMediaRetainType::RETAIN_FORCE, false);
        isCleaning = isCleaning || IsSouthDeviceSyncCleaning(CloudMediaRetainType::HDC_RETAIN_FORCE, false);
        if (isCleaning) {
            MEDIA_WARN_LOG("restart continue retain force, given the current design, any of hdc/cloud can be chosen");
            ForceRetainDownloadCloudMedia(CloudMediaRetainType::RETAIN_FORCE, false);
        }
    }).detach();
}

void CloudMediaAssetManager::TryToStartSync()
{
    if (!CloudSyncHelper::GetInstance()->IsSyncSwitchOpen()) {
        MEDIA_INFO_LOG("syncSwitch is not open");
        return;
    }
    MEDIA_INFO_LOG("cloud sync manager start sync");
    int32_t ret = CloudSyncManager::GetInstance().StartSync(BUNDLE_NAME);
    CHECK_AND_PRINT_LOG(ret == E_OK, "cloud sync manager start sync err %{public}d", ret);
    MEDIA_INFO_LOG("cloud sync manager end sync");
}
} // namespace Media
} // namespace OHOS