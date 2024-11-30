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

#include "abs_rdb_predicates.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_types.h"
#include "cloud_sync_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_store.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const std::string UNKNOWN_VALUE = "NA";
std::shared_ptr<CloudMediaAssetDownloadOperation> CloudMediaAssetManager::operation_ = nullptr;
static const int32_t BATCH_DELETE_CLOUD_FILE = 50;
static const std::string PHOTO_RELATIVE_PATH = "/Photo/";
static const std::string THUMBNAIL_RELATIVE_PATH = "/.thumbs/Photo/";

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
    if (operation_ == nullptr || operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::IDLE) {
        return E_ERR;
    }
    MEDIA_INFO_LOG("enter RecoverDownloadCloudAsset, RecoverCause: %{public}d", static_cast<int32_t>(cause));
    if (operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::DOWNLOADING) {
        MEDIA_WARN_LOG("The task status is download, no need to recover.");
        return E_OK;
    }
    int32_t ret = operation_->PassiveStatusRecoverTask(cause);
    MEDIA_INFO_LOG("end to RecoverDownloadCloudAsset, status: %{public}s, ret: %{public}d.",
        GetCloudMediaAssetTaskStatus().c_str(), ret);
    return ret;
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

int32_t CloudMediaAssetManager::DeleteBatchCloudFile(const std::vector<string> &pathVec)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("ForceRetainDownloadCloudMedia failed. rdbStore is null");
        return E_ERR;
    }
    AbsRdbPredicates deletePredicates(PhotoColumn::PHOTOS_TABLE);
    deletePredicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    deletePredicates.In(MediaColumn::MEDIA_FILE_PATH, pathVec);
    int32_t deletedRows = E_HAS_DB_ERROR;
    int32_t ret = rdbStore->ComletelyDeleteDBData(deletedRows, deletePredicates);
    if (ret != NativeRdb::E_OK || deletedRows <= 0) {
        MEDIA_ERR_LOG("Delete operation failed. ret %{public}d. Deleted %{public}d", ret, deletedRows);
    }
    return deletedRows;
}

int32_t CloudMediaAssetManager::DataReadyForDelete(std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("ForceRetainDownloadCloudMedia failed. rdbStorePtr is null");
        return E_ERR;
    }
    std::vector<string> pathVec;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int columnIndex = 0;
        string path;
        if (resultSet->GetColumnIndex(MediaColumn::MEDIA_FILE_PATH, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetString(columnIndex, path);
        }
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get path!");
            continue;
        }
        MEDIA_WARN_LOG("get path: %{public}s.", MediaFileUtils::DesensitizePath(path).c_str());

        pathVec.push_back(path);
        if (pathVec.size() == BATCH_DELETE_CLOUD_FILE) {
            DeleteBatchCloudFile(pathVec);
            pathVec.clear();
        }
        size_t pos = path.find(PHOTO_RELATIVE_PATH);
        if (pos == string::npos) {
            MEDIA_INFO_LOG("The path is invalid, path: %{public}s.", MediaFileUtils::DesensitizePath(path).c_str());
            continue;
        }
        std::string thumbnailPath = path.replace(pos, PHOTO_RELATIVE_PATH.length(), THUMBNAIL_RELATIVE_PATH);
        if (!MediaFileUtils::IsFileExists(thumbnailPath)) {
            MEDIA_INFO_LOG("Thumbnail path not exit, path: %{public}s.",
                MediaFileUtils::DesensitizePath(thumbnailPath).c_str());
            continue;
        }
        if (!MediaFileUtils::DeleteDir(thumbnailPath)) {
            MEDIA_INFO_LOG("Delete thumbnail path failed, path: %{public}s.",
                MediaFileUtils::DesensitizePath(thumbnailPath).c_str());
        }
    }
    resultSet->Close();
    return DeleteBatchCloudFile(pathVec);
}

int32_t CloudMediaAssetManager::ForceRetainDownloadCloudMedia()
{
    MEDIA_INFO_LOG("enter ForceRetainDownloadCloudMedia.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("ForceRetainDownloadCloudMedia failed. rdbStore is null");
        return E_ERR;
    }
    AbsRdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    vector<string> columns = { MediaColumn::MEDIA_FILE_PATH };
    auto queryResult = rdbStore->Query(queryPredicates, columns);
    if (queryResult == nullptr) {
        MEDIA_ERR_LOG("Failed to query!");
        return E_ERR;
    }
    int32_t ret = DataReadyForDelete(queryResult);
    MEDIA_INFO_LOG("end to ForceRetainDownloadCloudMedia, ret: %{public}d.", ret);
    return ret;
}

int32_t CloudMediaAssetManager::GentleRetainDownloadCloudMedia()
{
    MEDIA_INFO_LOG("enter GentleRetainDownloadCloudMedia.");
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NEED_CLEAN));
    MediaLibraryCommand cmd(OperationObject::PAH_PHOTO, OperationType::UPDATE, values);

    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    int32_t updatedRows = E_HAS_DB_ERROR;
    int32_t ret = uniStore->Update(cmd, updatedRows);
    if (ret != NativeRdb::E_OK || updatedRows <= 0) {
        MEDIA_ERR_LOG("Update operation failed. ret %{public}d. Updated %{public}d", ret, updatedRows);
    }
    MEDIA_INFO_LOG("end to GentleRetainDownloadCloudMedia, Updated: %{public}d, ret: %{public}d.", updatedRows, ret);
    return updatedRows;
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
        case OperationType::CLOUD_MEDIA_ASSET_TASK_RETAIN_GENTLE: {
            return GentleRetainDownloadCloudMedia();
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
    if (operation_->GetTaskStatus() == CloudMediaAssetTaskStatus::PAUSED) {
        MEDIA_INFO_LOG("Update count and size of download cloud media asset.");
        operation_->InitDownloadTaskInfo();
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