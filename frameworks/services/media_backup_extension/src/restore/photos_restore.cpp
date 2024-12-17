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
#include <string>
#include <vector>

#include "photos_restore.h"
#include "backup_const.h"
#include "backup_file_utils.h"
#include "userfile_manager_types.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "photo_album_dao.h"
#include "album_plugin_config.h"
#include "backup_file_utils.h"
#include "mimetype_utils.h"

namespace OHOS::Media {
/**
 * @brief Get the gallery_media to restore to Photos.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosRestore::GetGalleryMedia(
    int32_t offset, int pageSize, bool shouldIncludeSd, bool hasLowQualityImage)
{
    return this->galleryMediaDao_.GetGalleryMedia(offset, pageSize, shouldIncludeSd, hasLowQualityImage);
}

/**
 * @brief Get the row count of gallery_media.
 */
int32_t PhotosRestore::GetGalleryMediaCount(bool shouldIncludeSd, bool hasLowQualityImage)
{
    return this->galleryMediaDao_.GetGalleryMediaCount(shouldIncludeSd, hasLowQualityImage);
}

/**
 * @brief Get the PhotoAlbum basic info.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotosRestore::FindAlbumInfo(const FileInfo &fileInfo)
{
    std::string lPath = fileInfo.lPath;
    // Scenario 2, WHEN FileInfo is in hidden album, THEN override lPath to the folder in sourcePath.
    // Scenario 3, WHEN FileInfo is not belongs to any album, THEN override lPath to the folder in sourcePath.
    if (fileInfo.lPath.empty() || this->ToLower(fileInfo.lPath) == this->ToLower(GALLERT_HIDDEN_ALBUM)) {
        lPath = this->photoAlbumDao_.ParseSourcePathToLPath(fileInfo.sourcePath);
        MEDIA_INFO_LOG("Media_Restore: fix lPath of album.fileInfo.lPath: %{public}s, "
                       "lPathFromSourcePath: %{public}s, lowercase: %{public}s, FileInfo Object: %{public}s",
            fileInfo.lPath.c_str(),
            lPath.c_str(),
            this->ToLower(lPath).c_str(),
            this->ToString(fileInfo).c_str());
    }
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    // Scenario 1, WHEN FileInfo is in /Pictures/Screenshots and Video type, THEN redirect to /Pictures/Screenrecords
    if (this->ToLower(lPath) == this->ToLower(AlbumPlugin::LPATH_SCREEN_SHOTS) &&
        fileInfo.fileType == MediaType::MEDIA_TYPE_VIDEO) {
        albumInfo = this->photoAlbumDao_.BuildAlbumInfoOfRecorders();
        albumInfo = this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumInfo);
        MEDIA_INFO_LOG("Media_Restore: screenshots redirect to screenrecords, fileInfo.lPath: %{public}s, "
                       "lPathForScreenshot: %{public}s, Object: %{public}s, albumInfo: %{public}s",
            fileInfo.lPath.c_str(),
            lPath.c_str(),
            this->ToString(fileInfo).c_str(),
            this->photoAlbumDao_.ToString(albumInfo).c_str());
        return albumInfo;
    }
    albumInfo = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
    return this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumInfo);
}

/**
 * @brief Get the PhotoAlbum basic info.
 */
int32_t PhotosRestore::FindAlbumId(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Can not find PhotoAlbum. fileInfo.lPath= %{public}s, fileInfo.sourcePath= %{public}s",
            fileInfo.lPath.c_str(),
            fileInfo.sourcePath.c_str());
    }
    return albumInfo.albumId;
}

/**
 * @brief find lPath by FileInfo.
 */
std::string PhotosRestore::FindlPath(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Can not find PhotoAlbum. fileInfo.lPath= %{public}s, fileInfo.sourcePath= %{public}s",
            fileInfo.lPath.c_str(),
            fileInfo.sourcePath.c_str());
    }
    return albumInfo.lPath;
}

/**
 * @brief Find PackageName by FileInfo.
 */
std::string PhotosRestore::FindPackageName(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Can not find PhotoAlbum. fileInfo.lPath= %{public}s, fileInfo.sourcePath= %{public}s",
            fileInfo.lPath.c_str(),
            fileInfo.sourcePath.c_str());
    }
    return albumInfo.albumName;
}

/**
 * @brief Find BundleName by FileInfo.
 */
std::string PhotosRestore::FindBundleName(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Can not find PhotoAlbum. fileInfo.lPath= %{public}s, fileInfo.sourcePath= %{public}s",
            fileInfo.lPath.c_str(),
            fileInfo.sourcePath.c_str());
    }
    return albumInfo.bundleName;
}

/**
 * @brief Find BurstKey by FileInfo.
 */
std::string PhotosRestore::FindBurstKey(const FileInfo &fileInfo)
{
    if (fileInfo.burstKey.size() > 0) {
        return fileInfo.burstKey;
    }
    return "";
}

/**
 * @brief Find Dirty by FileInfo.
 */
int32_t PhotosRestore::FindDirty(const FileInfo &fileInfo)
{
    return static_cast<int32_t>(DirtyTypes::TYPE_NEW);
}

/**
 * @brief Find burst_cover_level by FileInfo.
 */
int32_t PhotosRestore::FindBurstCoverLevel(const FileInfo &fileInfo)
{
    // identify burst photo
    if (fileInfo.isBurst == static_cast<int32_t>(BurstCoverLevelType::COVER) ||
        fileInfo.isBurst == static_cast<int32_t>(BurstCoverLevelType::MEMBER)) {
        return fileInfo.isBurst;
    }
    return static_cast<int32_t>(BurstCoverLevelType::COVER);
}

/**
 * @brief Find subtype by FileInfo.
 */
int32_t PhotosRestore::FindSubtype(const FileInfo &fileInfo)
{
    if (fileInfo.burstKey.size() > 0) {
        return static_cast<int32_t>(PhotoSubType::BURST);
    }
    if (BackupFileUtils::IsLivePhoto(fileInfo)) {
        return static_cast<int32_t>(PhotoSubType::MOVING_PHOTO);
    }
    return static_cast<int32_t>(PhotoSubType::DEFAULT);
}

/**
 * @brief Find date_trashed by FileInfo.
 */
int64_t PhotosRestore::FindDateTrashed(const FileInfo &fileInfo)
{
    // prevent Photos marked as deleted when it's in use.
    if (fileInfo.recycleFlag == 0) {
        return 0;
    }
    // LOG INFO for analyser.
    if (fileInfo.recycledTime != 0) {
        string fileName = fileInfo.displayName;
        MEDIA_WARN_LOG("the file :%{public}s is trash.", BackupFileUtils::GarbleFileName(fileName).c_str());
    }
    return fileInfo.recycledTime;
}

/**
 * @brief Get duplicate data in gallery db.
 */
void PhotosRestore::GetDuplicateData(int32_t duplicateDataCount)
{
    if (duplicateDataCount <= 0) {
        return;
    }
    std::string querySql = this->SQL_GALLERY_MEDIA_QUERY_DUPLICATE_DATA;
    int rowCount = 0;
    int offset = 0;
    int pageSize = 200;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, pageSize};
        if (this->galleryRdb_ == nullptr) {
            MEDIA_ERR_LOG("Media_Restore: galleryRdb_ is null.");
            break;
        }
        auto resultSet = this->galleryRdb_->QuerySql(querySql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string data = GetStringVal(GALLERY_FILE_DATA, resultSet);
            int32_t count = GetInt32Val(CUSTOM_COUNT, resultSet);
            this->duplicateDataUsedCountMap_[data] = 0;
            MEDIA_INFO_LOG("Get duplicate data: %{public}s, count: %{public}d",
                BackupFileUtils::GarbleFilePath(data, DEFAULT_RESTORE_ID).c_str(),
                count);
        }
        // Check if there are more rows to fetch.
        resultSet->GetRowCount(rowCount);
        offset += pageSize;
    } while (rowCount > 0);
}

/**
 * @brief Check if it is duplicate data in gallery db.
 */
bool PhotosRestore::IsDuplicateData(const std::string &data)
{
    std::lock_guard<mutex> lock(this->duplicateDataUsedCountMutex_);
    if (this->duplicateDataUsedCountMap_.count(data) == 0) {
        return false;
    }
    this->duplicateDataUsedCountMap_[data]++;
    return this->duplicateDataUsedCountMap_.at(data) > 1;
}

/**
 * @brief Find PhotoQuality by FileInfo.
 */
int32_t PhotosRestore::FindPhotoQuality(const FileInfo &fileInfo)
{
    if (fileInfo.photoQuality == 1 && fileInfo.fileType == MediaType::MEDIA_TYPE_VIDEO) {
        return 0;
    }
    return fileInfo.photoQuality;
}

/**
 * @brief Find suffix of displayName. include dot, e.g. ".jpg"
 * @return return the suffix of displayName. "" if not found.
 */
std::string PhotosRestore::GetSuffix(const std::string &displayName)
{
    size_t dotPos = displayName.rfind('.');
    if (dotPos != std::string::npos) {
        return this->ToLower(displayName.substr(dotPos + 1));  // without dot, e.g. "jpg"
    }
    return "";
}

/**
 * @brief Find media_type by FileInfo.
 */
int32_t PhotosRestore::FindMediaType(const FileInfo &fileInfo)
{
    int32_t dualMediaType = fileInfo.fileType;
    if (dualMediaType == DUAL_MEDIA_TYPE::IMAGE_TYPE || dualMediaType == DUAL_MEDIA_TYPE::VIDEO_TYPE) {
        return dualMediaType == DUAL_MEDIA_TYPE::VIDEO_TYPE ? MediaType::MEDIA_TYPE_VIDEO : MediaType::MEDIA_TYPE_IMAGE;
    }
    std::string suffix = this->GetSuffix(fileInfo.displayName);
    MediaType mediaType = MimeTypeUtils::GetMediaTypeFromMimeType(MimeTypeUtils::GetMimeTypeFromExtension(suffix));
    MEDIA_INFO_LOG("Media_Restore: correct mediaType from %{public}d to %{public}d, displayName: %{public}s",
        fileInfo.fileType,
        mediaType,
        fileInfo.displayName.c_str());
    return mediaType;
}

/**
 * @brief Find source_path for the target device by FileInfo.
 */
std::string PhotosRestore::FindSourcePath(const FileInfo &fileInfo)
{
    if (!fileInfo.sourcePath.empty()) {
        return fileInfo.sourcePath;
    }
    std::string lPath = "/Pictures/其它";
    if (!fileInfo.lPath.empty()) {
        lPath = fileInfo.lPath;
    } else {
        MEDIA_ERR_LOG("Media_Restore: fileInfo.lPath is empty. Use default lPath: %{public}s", lPath.c_str());
    }
    return this->SOURCE_PATH_PREFIX + lPath + "/" + fileInfo.displayName;
}
}  // namespace OHOS::Media