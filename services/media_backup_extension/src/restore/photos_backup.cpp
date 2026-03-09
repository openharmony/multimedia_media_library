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
#include "photos_backup.h"

#include "backup_const_column.h"
#include "medialibrary_db_const.h"
#include "media_file_utils.h"
#include "nlohmann/json.hpp"
#include "upgrade_restore_task_report.h"

namespace OHOS::Media {
std::string PhotosBackup::BackupInfo::ToString() const
{
    nlohmann::json jsonObject = {
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_PHOTO + suffix},
            {STAT_KEY_NUMBER, photoCount}
        },
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_VIDEO + suffix},
            {STAT_KEY_NUMBER, videoCount}
        },
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_AUDIO + suffix},
            {STAT_KEY_NUMBER, audioCount}
        },
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_TOTAL_SIZE + suffix},
            {STAT_KEY_NUMBER, totalSize}
        },
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_CLOUD_PHOTO + suffix},
            {STAT_KEY_NUMBER, cloudPhotoCount}
        },
        {
            {STAT_KEY_BACKUP_INFO, STAT_TYPE_CLOUD_VIDEO + suffix},
            {STAT_KEY_NUMBER, cloudVideoCount}
        }
    };
    return jsonObject.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

PhotosBackup::PhotosBackup(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
{
    sceneCode_ = sceneCode;
    taskId_ = taskId;
    mediaLibraryRdb_ = mediaLibraryRdb;
    photosDao_.SetMediaLibraryRdb(mediaLibraryRdb);
}

std::string PhotosBackup::GetBackupInfo()
{
    std::string backupInfoOfMediaFile = GetBackupInfoOfMediaFile();
    std::string backupInfoOfLakeFile = GetBackupInfoOfLakeFile();
    return backupInfoOfMediaFile;
}

std::string PhotosBackup::GetBackupInfoOfMediaFile()
{
    BackupInfo backupInfo = {
        .suffix = "",
        .photoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_IMAGE}, {FileSourceType::MEDIA},
            {static_cast<int32_t>(PhotoPositionType::LOCAL),
             static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD)}),
        .videoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_VIDEO}, {FileSourceType::MEDIA},
            {static_cast<int32_t>(PhotoPositionType::LOCAL),
             static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD)}),
        .cloudPhotoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_IMAGE}, {FileSourceType::MEDIA},
            {static_cast<int32_t>(PhotoPositionType::CLOUD)}),
        .cloudVideoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_VIDEO}, {FileSourceType::MEDIA},
            {static_cast<int32_t>(PhotoPositionType::CLOUD)}),
        .audioCount = photosDao_.GetBackupAudioCount({MediaType::MEDIA_TYPE_AUDIO}),
        .totalSize = GetBackupTotalSizeOfMediaFile()
    };
    UpgradeRestoreTaskReport(sceneCode_, taskId_).Report("BACKUP_INFO_MEDIA", "0", backupInfo.ToString());
    return backupInfo.ToString();
}

std::string PhotosBackup::GetBackupInfoOfLakeFile()
{
    BackupInfo backupInfo = {
        .suffix = "_anco",
        .photoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_IMAGE}, {FileSourceType::MEDIA_HO_LAKE},
            {static_cast<int32_t>(PhotoPositionType::LOCAL),
             static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD)}),
        .videoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_VIDEO}, {FileSourceType::MEDIA_HO_LAKE},
            {static_cast<int32_t>(PhotoPositionType::LOCAL),
             static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD)}),
        .cloudPhotoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_IMAGE},
            {FileSourceType::MEDIA_HO_LAKE}, {static_cast<int32_t>(PhotoPositionType::CLOUD)}),
        .cloudVideoCount = photosDao_.GetBackupMediaCount({MediaType::MEDIA_TYPE_VIDEO},
            {FileSourceType::MEDIA_HO_LAKE}, {static_cast<int32_t>(PhotoPositionType::CLOUD)}),
        .audioCount = 0,
        .totalSize = GetBackupTotalSizeOfLakeFile()
    };
    UpgradeRestoreTaskReport(sceneCode_, taskId_).Report("BACKUP_INFO_ANCO", "0", backupInfo.ToString());
    return backupInfo.ToString();
}

size_t PhotosBackup::GetBackupTotalSizeOfMediaFile()
{
    size_t totalSize = static_cast<size_t>(photosDao_.GetAssetTotalSizeByFileSourceType(FileSourceType::MEDIA));
    // other meta data dir size
    size_t editDataTotalSize {0};
    size_t rdbTotalSize {0};
    size_t kvdbTotalSize {0};
    size_t highlightTotalSize {0};
    MediaFileUtils::StatDirSize(CLONE_STAT_EDIT_DATA_DIR, editDataTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_RDB_DIR, rdbTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_KVDB_DIR, kvdbTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_HIGHLIGHT_DIR, highlightTotalSize);
    totalSize += editDataTotalSize + rdbTotalSize + kvdbTotalSize + highlightTotalSize;
    return totalSize;
}

size_t PhotosBackup::GetBackupTotalSizeOfLakeFile()
{
    return static_cast<size_t>(photosDao_.GetAssetTotalSizeByFileSourceType(FileSourceType::MEDIA_HO_LAKE));
}
}