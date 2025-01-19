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
#include "gallery_media_dao.h"

#include <string>
#include <vector>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "media_log.h"

namespace OHOS::Media {
void GalleryMediaDao::SetGalleryRdb(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    this->galleryRdb_ = galleryRdb;
}

/**
 * @brief Get the gallery_media to restore to Photos.
 */
std::shared_ptr<NativeRdb::ResultSet> GalleryMediaDao::GetGalleryMedia(
    int32_t offset, int pageSize, bool shouldIncludeSd, bool hasLowQualityImage)
{
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag, offset, pageSize};
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: galleryRdb_ is null.");
        return nullptr;
    }
    return this->galleryRdb_->QuerySql(this->SQL_GALLERY_MEDIA_QUERY_FOR_RESTORE, params);
}

/**
 * @brief Get the gallery_media to restore cloud to Photos.
 */
std::shared_ptr<NativeRdb::ResultSet> GalleryMediaDao::GetCloudGalleryMedia(
    int32_t offset, int pageSize, bool shouldIncludeSd, bool hasLowQualityImage)
{
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: galleryRdb_ is null.");
        return nullptr;
    }
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag, offset, pageSize};
    return this->galleryRdb_->QuerySql(this->SQL_GALLERY_CLOUD_QUERY_FOR_RESTORE, params);
}

/**
 * @brief Get the row count of gallery_media.
 */
int32_t GalleryMediaDao::GetGalleryMediaCount(bool shouldIncludeSd, bool hasLowQualityImage)
{
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag};
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: galleryRdb_ is null.");
        return 0;
    }
    auto resultSet = this->galleryRdb_->QuerySql(this->SQL_GALLERY_MEDIA_QUERY_COUNT, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Get the row count of cloud_meta.
 */
int32_t GalleryMediaDao::GetCloudMetaCount(bool shouldIncludeSd, bool hasLowQualityImage)
{
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Cloud_meta_Restore: galleryRdb_ is null.");
        return 0;
    }
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag};
    auto resultSet = this->galleryRdb_->QuerySql(this->SQL_CLOUD_META_QUERY_COUNT, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Get the row count of gallery_media no need migrate count.
 */
int32_t GalleryMediaDao::GetNoNeedMigrateCount(bool shouldIncludeSd)
{
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {shouldIncludeSdFlag};
    if (this->galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: galleryRdb_ is null.");
        return 0;
    }
    auto resultSet = this->galleryRdb_->QuerySql(this->SQL_GALLERY_MEDIA_QUERY_NO_NEED_MIGRATE_COUNT, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}
}  // namespace OHOS::Media