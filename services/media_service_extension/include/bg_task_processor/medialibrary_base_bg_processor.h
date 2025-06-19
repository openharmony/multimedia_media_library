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

#ifndef MEDIALIBRARY_BASE_BG_PROCESSOR_H
#define MEDIALIBRARY_BASE_BG_PROCESSOR_H

#include <mutex>
#include <string>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
// taskName
// aging_task
static const std::string DELETE_TEMPORARY_PHOTOS = "DeleteTemporaryPhotos";
static const std::string STORAGE_AGING_OPERATION = "StorageAgingOperation";
static const std::string TRASH_AGING_OPERATION = "TrashAgingOperation";

// asset_change_task
static const std::string ALL_ALBUM_REFRESH = "AllAlbumRefresh";

// bg_generate_thumbnail_task
static const std::string DO_THUMBNAIL_BG_OPERATION = "DoThumbnailBgOperation";

// cloud_download_task
static const std::string DOWNLOAD_ORIGIN_CLOUD_FILES_FOR_LOGIN = "DownloadOriginCloudFilesForLogin";

// compatible_with_gallery_task
static const std::string CLEAN_INVALID_CLOUD_ALBUM_AND_DATA = "CleanInvalidCloudAlbumAndData";
static const std::string COMPAT_OLD_VERSION_MOVING_PHOTO = "CompatOldVersionMovingPhoto";
static const std::string DO_UPDATE_BURST_FORM_GALLERY = "DoUpdateBurstFromGallery";
static const std::string MIGRATE_HIGH_LIGHT_INFO_TO_NEW_PATH = "MigrateHighlightInfoToNewPath";

// dfx_task
static const std::string DFX_HANDLE_HALF_DAY_MISSIONS = "DfxHandleMissions";
static const std::string UPLOAD_DB_FILE = "UploadDBFile";

// preserve_db_task
static const std::string ANALYZE_PHOTOS_TABLE = "AnalyzePhotosTable";
static const std::string CHECK_DB_BACKUP = "CheckDbBackup";
static const std::string WAL_CHECK = "WalCheck";

// repair_dirty_data_task
static const std::string ADD_PERMISSION_FOR_CLOUD_ENHANCEMENT = "AddPermissionForCloudEnhancement";
static const std::string CLEAR_BETA_AND_HDC_DIRTY_DATA = "ClearBetaAndHDCDirtyData";
static const std::string DELETE_CLOUD_MEDIA_ASSETS = "DeleteCloudMediaAssets";
static const std::string REPAIR_HISTORY_DIRTY_DATA = "RepairHistoryDirtyData";
static const std::string REPAIR_NO_ORIGIN_PHOTO = "RepairNoOriginPhoto";
static const std::string UPDATE_INVALID_MIME_TYPE = "UpdateInvalidMimeType";

class MediaLibraryBaseBgProcessor {
public:
    MediaLibraryBaseBgProcessor() {}
    EXPORT virtual ~MediaLibraryBaseBgProcessor() {}
    EXPORT virtual int32_t Start(const std::string &taskExtra) = 0;
    EXPORT virtual int32_t Stop(const std::string &taskExtra) = 0;

    EXPORT static void WriteModifyInfo(const std::string &key, const std::string &value, std::string &modifyInfo);

    EXPORT static void RemoveTaskName(const std::string &taskName);
    EXPORT static void AddRemoveTaskNameCallback(std::function<void(const std::string &)> callback);

    EXPORT static void ReportTaskComplete(const std::string &taskName);
    EXPORT static void ModifyTask(const std::string &taskName, const std::string& modifyInfo);

private:

    static std::mutex removeTaskNameMutex_;
    static std::function<void(const std::string &)> removeTaskNameCallback_;

protected:
    static std::mutex ipcMutex_;
};
} // namespace Media
} // namespace OHOS
#endif  // MEDIALIBRARY_BASE_BG_PROCESSOR_H
