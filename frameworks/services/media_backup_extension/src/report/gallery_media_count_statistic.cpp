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
#include "gallery_media_count_statistic.h"

#include "media_log.h"
#include "backup_database_utils.h"
#include "backup_const.h"
#include "gallery_media_dao.h"
#include "media_backup_report_data_type.h"

namespace OHOS::Media {
std::vector<AlbumMediaStatisticInfo> GalleryMediaCountStatistic::Load()
{
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("galleryRdb_ is nullptr, Maybe init failed.");
        return {};
    }
    return {this->GetAllStatInfo(),
        this->GetSdCardStatInfo(),
        this->GetScreenStatInfo(),
        this->GetImportsStatInfo(),
        this->GetAllRestoreStatInfo(),
        this->GetDuplicateStatInfo(),
        this->GetAppTwinStatInfo()};
}

int32_t GalleryMediaCountStatistic::QueryGalleryAllCount()
{
    static string QUERY_GALLERY_ALL_COUNT = "SELECT count(1) AS count FROM gallery_media";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_ALL_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryImageCount()
{
    static string QUERY_GALLERY_IMAGE_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE media_type = 1 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_IMAGE_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryVideoCount()
{
    static string QUERY_GALLERY_VIDEO_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE media_type = 3 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_VIDEO_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryHiddenCount()
{
    static string QUERY_GALLERY_HIDDEN_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE local_media_id = -4 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_HIDDEN_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryTrashedCount()
{
    static string QUERY_GALLERY_TRASHED_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE local_media_id = 0 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_TRASHED_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryFavoriteCount()
{
    static string QUERY_GALLERY_FAVORITE_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_favorite = 1 AND _size > 0 AND local_media_id != -1";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_FAVORITE_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryImportsCount()
{
    static string QUERY_GALLERY_IMPORTS_COUNT =
        string("SELECT count(1) AS count FROM gallery_media WHERE ") +
        " _data LIKE '/storage/emulated/0/Pictures/cloud/Imports%' AND _size > 0 AND local_media_id != -1";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_IMPORTS_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryCloneCount()
{
    static string QUERY_GALLERY_CLONE_COUNT =
        string("SELECT count(1) AS count FROM gallery_media WHERE local_media_id = -3 AND _size > 0 ") +
        "AND (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN ( " +
        "SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1)";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_CLONE_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGallerySdCardCount()
{
    static string QUERY_GALLERY_SD_CARD_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE storage_id NOT IN (0, 65537) AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_SD_CARD_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryScreenVideoCount()
{
    static string QUERY_GALLERY_SCRENN_VIDEO_COUNT = "SELECT count(1) AS count FROM gallery_media \
        WHERE local_media_id = -3 AND bucket_id = 1028075469 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_SCRENN_VIDEO_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryCloudCount()
{
    static string QUERY_GALLERY_CLOUD_COUNT = "SELECT count(1) AS count FROM gallery_media \
        WHERE local_media_id = -1 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_CLOUD_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryBurstCoverCount()
{
    static string QUERY_GALLERY_BURST_COVER_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_burst = 1 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_BURST_COVER_COUNT, CUSTOM_COUNT);
}

int32_t GalleryMediaCountStatistic::QueryGalleryBurstTotalCount()
{
    static string QUERY_GALLERY_BURST_TOTAL_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_burst IN (1, 2) AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->galleryRdb_, QUERY_GALLERY_BURST_TOTAL_COUNT, CUSTOM_COUNT);
}

bool GalleryMediaCountStatistic::HasLowQualityImage()
{
    std::string sql = "SELECT count(1) AS count FROM gallery_media WHERE (local_media_id != -1) AND \
        (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN (SELECT DISTINCT relative_bucket_id FROM \
        garbage_album WHERE type = 1) AND _size = 0 AND photo_quality = 0";
    int count = BackupDatabaseUtils::QueryInt(galleryRdb_, sql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("HasLowQualityImage count:%{public}d", count);
    return count > 0;
}

int32_t GalleryMediaCountStatistic::GetGalleryMediaCount()
{
    bool hasLowQualityImage = this->HasLowQualityImage();
    return GalleryMediaDao(this->galleryRdb_).GetGalleryMediaCount(this->shouldIncludeSd_, hasLowQualityImage);
}

int32_t GalleryMediaCountStatistic::QueryGalleryAppTwinDataCount()
{
    std::string sql = "SELECT count(1) AS count FROM gallery_media WHERE _data LIKE '/storage/emulated/%' AND "
        "CAST (substr(_data, length('/storage/emulated/') + 1, 3) AS INTEGER) BETWEEN 128 AND 147 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(galleryRdb_, sql, CUSTOM_COUNT);
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetAllStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "ALL";
    info.totalCount = this->QueryGalleryAllCount();
    info.imageCount = this->QueryGalleryImageCount();
    info.videoCount = this->QueryGalleryVideoCount();
    info.hiddenCount = this->QueryGalleryHiddenCount();
    info.trashedCount = this->QueryGalleryTrashedCount();
    info.cloudCount = this->QueryGalleryCloudCount();
    info.favoriteCount = this->QueryGalleryFavoriteCount();
    info.burstTotalCount = this->QueryGalleryBurstTotalCount();
    info.burstCoverCount = this->QueryGalleryBurstCoverCount();
    return info;
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetSdCardStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "SD_CARD";
    info.totalCount = this->QueryGallerySdCardCount();
    return info;
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetScreenStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "SCREEN";
    info.videoCount = this->QueryGalleryScreenVideoCount();
    return info;
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetImportsStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "IMPORTS";
    info.totalCount = this->QueryGalleryImportsCount();
    return info;
}
AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetAllRestoreStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "ALL_RESTORE";
    info.totalCount = this->GetGalleryMediaCount();
    return info;
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetDuplicateStatInfo()
{
    int32_t duplicateDataCount;
    int32_t duplicateDataTotal;
    BackupDatabaseUtils::QueryGalleryDuplicateDataCount(this->galleryRdb_, duplicateDataCount, duplicateDataTotal);
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "DUPLICATE";
    info.totalCount = duplicateDataTotal;
    return info;
}

AlbumMediaStatisticInfo GalleryMediaCountStatistic::GetAppTwinStatInfo()
{
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "APP_TWIN";
    info.totalCount = this->QueryGalleryAppTwinDataCount();
    return info;
}
}  // namespace OHOS::Media