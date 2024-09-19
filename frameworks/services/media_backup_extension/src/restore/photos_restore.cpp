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
#include "userfile_manager_types.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "photo_album_dao.h"
#include "album_plugin_config.h"
#include "backup_file_utils.h"

namespace OHOS::Media {
/**
 * @brief Get the gallery_media to restore to Photos.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosRestore::GetGalleryMedia(
    int32_t offset, int pageSize, bool shouldIncludeSd, bool hasLowQualityImage)
{
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag, offset, pageSize};
    return this->galleryRdb_->QuerySql(this->SQL_GALLERY_MEDIA_QUERY_FOR_RESTORE, params);
}

/**
 * @brief Get the row count of gallery_media.
 */
int32_t PhotosRestore::GetGalleryMediaCount(bool shouldIncludeSd, bool hasLowQualityImage)
{
    int32_t shouldIncludeSdFlag = shouldIncludeSd == true ? 1 : 0;
    int32_t hasLowQualityImageFlag = hasLowQualityImage == true ? 1 : 0;
    std::vector<NativeRdb::ValueObject> params = {hasLowQualityImageFlag, shouldIncludeSdFlag};
    auto resultSet = this->galleryRdb_->QuerySql(this->SQL_GALLERY_MEDIA_QUERY_COUNT, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Parse the sourcePath to lPath.
 * example, sourcePath=/storage/emulated/0/DCIM/Camera/IMG_20240829_072213.jpg, lPath=/DCIM/Camera
 * if the sourcePath can not be parsed, return /Pictures/其它.
 */
std::string PhotosRestore::ParseSourcePathToLPath(const std::string &sourcePath)
{
    size_t start_pos = sourcePath.find(GALLERT_ROOT_PATH);
    size_t end_pos = sourcePath.find_last_of("/");

    std::string result = "/Pictures/其它";
    if (start_pos != std::string::npos && end_pos != std::string::npos) {
        start_pos += GALLERT_ROOT_PATH.length();
        result = sourcePath.substr(start_pos, end_pos - start_pos);
        start_pos = result.find_first_of("/");
        if (start_pos != std::string::npos) {
            result = result.substr(start_pos);
        }
    }
    return result;
}

/**
 * @brief Build PhotoAlbumRowData for ScreenRecorder.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotosRestore::BuildAlbumInfoOfRecorders()
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    // bind albumName and bundleName by lPath.
    albumInfo.albumName = AlbumPlugin::ALBUM_NAME_SCREEN_RECORDS;
    albumInfo.bundleName = AlbumPlugin::BUNDLE_NAME_SCREEN_RECORDS;
    albumInfo.lPath = AlbumPlugin::LPATH_SCREEN_RECORDS;
    albumInfo.albumType = static_cast<int32_t>(PhotoAlbumType::SOURCE);
    albumInfo.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC);
    albumInfo.priority = 1;
    return albumInfo;
}

/**
 * @brief Build PhotoAlbumRowData from lPath.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotosRestore::BuildAlbumInfoByLPath(const std::string &lPath)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    // find albumName from lPath
    std::string albumName = "其它";
    std::string albumlPath = lPath;
    size_t fileIndex = albumlPath.find_last_of(FILE_SEPARATOR);
    if (fileIndex != string::npos) {
        albumName = albumlPath.substr(fileIndex + 1);
    } else {
        albumlPath = "/Pictures/其它";
    }
    albumInfo.albumName = albumName;
    albumInfo.lPath = albumlPath;
    albumInfo.albumType = static_cast<int32_t>(PhotoAlbumType::SOURCE);
    albumInfo.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC);
    albumInfo.priority = 1;
    return albumInfo;
}

/**
 * @brief Get the PhotoAlbum basic info.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotosRestore::FindAlbumInfo(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    // Scenario 1, WHEN FileInfo is in /Pictures/Screenshots and Video type, THEN redirect to /Pictures/Screenrecords
    std::string lPathForScreenshot =
        fileInfo.lPath.empty() ? this->ParseSourcePathToLPath(fileInfo.sourcePath) : fileInfo.lPath;
    if (fileInfo.lPath.empty() && !lPathForScreenshot.empty()) {
        MEDIA_INFO_LOG(
            "Media_Restore: fix lPath of screenshots album."
            "fileInfo.lPath: %{public}s, lPathForScreenshot: %{public}s, lowercase: %{public}s, Object: %{public}s",
            fileInfo.lPath.c_str(),
            lPathForScreenshot.c_str(),
            this->ToLower(lPathForScreenshot).c_str(),
            this->ToString(fileInfo).c_str());
    }
    if (this->ToLower(lPathForScreenshot) == this->ToLower(AlbumPlugin::LPATH_SCREEN_SHOTS) &&
        fileInfo.fileType == MediaType::MEDIA_TYPE_VIDEO) {
        MEDIA_INFO_LOG("Media_Restore: screenshots redirect to screenrecords, fileInfo.lPath: %{public}s, "
                       "lPathForScreenshot: %{public}s, Object: %{public}s",
            fileInfo.lPath.c_str(),
            lPathForScreenshot.c_str(),
            this->ToString(fileInfo).c_str());
        albumInfo = this->BuildAlbumInfoOfRecorders();
        albumInfo = this->photoAlbumDaoPtr_->GetOrCreatePhotoAlbum(albumInfo);
        return albumInfo;
    }
    // Scenario 2, WHEN FileInfo is in hidden album, THEN override lPath to the folder in sourcePath.
    // Scenario 3, WHEN FileInfo is not belongs to any album, THEN override lPath to the folder in sourcePath.
    if (fileInfo.lPath.empty() || this->ToLower(fileInfo.lPath) == this->ToLower(GALLERT_HIDDEN_ALBUM)) {
        std::string lPathFromSourcePath = this->ParseSourcePathToLPath(fileInfo.sourcePath);
        albumInfo = this->BuildAlbumInfoByLPath(lPathFromSourcePath);
        albumInfo = this->photoAlbumDaoPtr_->GetOrCreatePhotoAlbum(albumInfo);
        return albumInfo;
    }
    return this->photoAlbumDaoPtr_->GetPhotoAlbum(fileInfo.lPath);
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
}  // namespace OHOS::Media