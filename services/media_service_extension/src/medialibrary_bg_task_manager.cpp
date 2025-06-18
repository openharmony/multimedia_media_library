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

#define MLOG_TAG "MediaBgTask_MediaLibraryBgTaskManager"

#include "medialibrary_bg_task_manager.h"

#include <context.h>
#include <context_impl.h>

#include "add_permission_for_cloud_enhancement_processor.h"
#include "analyze_photos_table_processor.h"
#include "check_db_backup_processor.h"
#include "medialibrary_all_album_refresh_processor.h"
#include "clean_invalid_cloud_album_and_data_processor.h"
#include "clear_beta_and_hdc_dirty_data_processor.h"
#include "moving_photo_processor.h"
#include "delete_cloud_media_assets_processor.h"
#include "delete_temporary_photos_processor.h"
#include "dfx_manager.h"
#include "do_thumbnail_bg_operation_processor.h"
#include "do_update_burst_from_gallery_processor.h"
#include "background_cloud_file_processor.h"
#include "migrate_high_light_info_to_new_path_processor.h"
#include "repair_history_dirty_data_processor.h"
#include "repair_no_origin_photo_processor.h"
#include "storage_aging_operation_processor.h"
#include "trash_aging_operation_processor.h"
#include "update_invalid_mime_type_processor.h"
#include "upload_db_file_processor.h"
#include "wal_check_processor.h"

#include "media_log.h"
#include "medialibrary_errno.h"

using namespace std;
namespace OHOS {
namespace Media {
std::mutex MediaLibraryBgTaskManager::mapMutex_;

// operation
static const std::string OPERATION_START = "start";
static const std::string OPERATION_STOP = "stop";

static const std::unordered_map<std::string, MediaLibraryBgTaskManager::BgTaskFunc> BG_TASK_FUNC_MAP = {
    { OPERATION_START,  &MediaLibraryBgTaskManager::Start },
    { OPERATION_STOP,   &MediaLibraryBgTaskManager::Stop },
};

static const std::unordered_map<std::string, std::shared_ptr<MediaLibraryBaseBgProcessor>> PROCESSORS_MAP = {
    { DELETE_TEMPORARY_PHOTOS,                  std::make_shared<DeleteTemporaryPhotosProcessor>() },
    { STORAGE_AGING_OPERATION,                  std::make_shared<StorageAgingOperationProcessor>() },
    { TRASH_AGING_OPERATION,                    std::make_shared<TrashAgingOperationProcessor>() },
    { ALL_ALBUM_REFRESH,                        MediaLibraryAllAlbumRefreshProcessor::GetInstance() },
    { DO_THUMBNAIL_BG_OPERATION,                std::make_shared<DoThumbnailBgOperationProcessor>() },
    { DOWNLOAD_ORIGIN_CLOUD_FILES_FOR_LOGIN,    std::make_shared<BackgroundCloudFileProcessor>() },
    { CLEAN_INVALID_CLOUD_ALBUM_AND_DATA,       std::make_shared<CleanInvalidCloudAlbumAndDataProcessor>() },
    { COMPAT_OLD_VERSION_MOVING_PHOTO,          std::make_shared<MovingPhotoProcessor>() },
    { DO_UPDATE_BURST_FORM_GALLERY,             std::make_shared<DoUpdateBurstFromGalleryProcessor>() },
    { MIGRATE_HIGH_LIGHT_INFO_TO_NEW_PATH,      std::make_shared<MigrateHighLightInfoToNewPathProcessor>() },
    { DFX_HANDLE_HALF_DAY_MISSIONS,             DfxManager::GetInstance() },
    { UPLOAD_DB_FILE,                           std::make_shared<UploadDbFileProcessor>() },
    { ANALYZE_PHOTOS_TABLE,                     std::make_shared<AnalyzePhotosTableProcessor>() },
    { CHECK_DB_BACKUP,                          std::make_shared<CheckDbBackupProcessor>() },
    { WAL_CHECK,                                std::make_shared<WalCheckProcessor>() },
    { ADD_PERMISSION_FOR_CLOUD_ENHANCEMENT,     std::make_shared<AddPermissionForCloudEnhancementProcessor>() },
    { CLEAR_BETA_AND_HDC_DIRTY_DATA,            std::make_shared<ClearBetaAndHdcDirtyDataProcessor>() },
    { DELETE_CLOUD_MEDIA_ASSETS,                std::make_shared<DeleteCloudMediaAssetsProcessor>() },
    { REPAIR_HISTORY_DIRTY_DATA,                std::make_shared<RepairHistoryDirtyDataProcessor>() },
    { REPAIR_NO_ORIGIN_PHOTO,                   std::make_shared<RepairNoOriginPhotoPrecessor>() },
    { UPDATE_INVALID_MIME_TYPE,                 std::make_shared<UpdateInvalidMimeTypePrecessor>() },
};

MediaLibraryBgTaskManager& MediaLibraryBgTaskManager::GetInstance()
{
    static MediaLibraryBgTaskManager instance;
    return instance;
}

int32_t MediaLibraryBgTaskManager::CommitTaskOps(const std::string &operation, const std::string &taskName,
    const std::string &taskExtra)
{
    auto it = BG_TASK_FUNC_MAP.find(operation);
    CHECK_AND_RETURN_RET_LOG(it != BG_TASK_FUNC_MAP.end(), E_ERR,
        "The operation is not exist, operation: %{public}s.", operation.c_str());

    auto func = it->second;
    return (this->*func)(taskName, taskExtra);
}

int32_t MediaLibraryBgTaskManager::Start(const std::string &taskName, const std::string &taskExtra)
{
    auto it = PROCESSORS_MAP.find(taskName);
    if (it == PROCESSORS_MAP.end()) {
        MEDIA_ERR_LOG("The taskName not in PROCESSORS_MAP, taskName: %{public}s.", taskName.c_str());
        return E_ERR;
    }
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto processor = it->second;
    it = processorMap_.find(taskName);
    if (it != processorMap_.end()) {
        MEDIA_WARN_LOG("The taskName is exist, taskName: %{public}s.", taskName.c_str());
        return E_OK;
    }
    CHECK_AND_RETURN_RET_LOG(processor != nullptr, E_ERR, "Processor is nullptr.");
    processor->AddRemoveTaskNameCallback([this](const std::string& processorName) {
        this->OnRemoveTaskNameComplete(processorName);
    });

    processorMap_[taskName] = processor;
    MEDIA_INFO_LOG("Register success, taskName: %{public}s, taskExtra: %{public}s, map size: %{public}zu.",
        taskName.c_str(), taskExtra.c_str(), processorMap_.size());
    lock.unlock();
    return processor->Start(taskExtra);
}

int32_t MediaLibraryBgTaskManager::Stop(const std::string &taskName, const std::string &taskExtra)
{
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto it = processorMap_.find(taskName);
    if (it == processorMap_.end()) {
        MEDIA_ERR_LOG("The taskName is not exist, taskName: %{public}s.", taskName.c_str());
        return E_ERR;
    }
    auto processor = processorMap_.at(taskName);
    CHECK_AND_RETURN_RET_LOG(
        processor != nullptr, E_ERR, "Processor is nullptr, taskName: %{public}s.", taskName.c_str());
    int32_t ret = processor->Stop(taskExtra);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("failed to processor->Stop, ret: %{public}d.", ret);
        return ret;
    }
    processorMap_.erase(taskName);
    MEDIA_INFO_LOG("taskName: %{public}s, taskName: %{public}s, map size: %{public}zu.",
        taskName.c_str(), taskExtra.c_str(), processorMap_.size());
    return E_OK;
}

void MediaLibraryBgTaskManager::OnRemoveTaskNameComplete(const std::string &taskName)
{
    std::unique_lock<std::mutex> lock(mapMutex_);
    auto it = processorMap_.find(taskName);
    if (it == processorMap_.end()) {
        MEDIA_WARN_LOG("No need report, The taskName is not exist, taskName: %{public}s.", taskName.c_str());
        return;
    }
    processorMap_.erase(taskName);
    MEDIA_INFO_LOG("OnRemoveTaskNameComplete success, taskName: %{public}s, map size: %{public}zu.",
        taskName.c_str(), processorMap_.size());
}
} // namespace Media
} // namespace OHOS
