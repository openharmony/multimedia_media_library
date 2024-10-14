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
#ifndef OHOS_MEDIA_PHOTOS_RESTORE
#define OHOS_MEDIA_PHOTOS_RESTORE

#include <mutex>
#include <string>
#include "rdb_store.h"
#include "photo_album_restore.h"
#include "photos_dao.h"
#include "photo_album_dao.h"

namespace OHOS::Media {
class PhotosRestore {
public:
    PhotosRestore(PhotoAlbumRestore &albumRestore) : photoAlbumRestore_(albumRestore)
    {}
    /**
     * @brief Restore Start Event Handler.
     */
    void OnStart(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
    {
        this->mediaLibraryRdb_ = mediaLibraryRdb;
        this->galleryRdb_ = galleryRdb;
        this->photosDaoPtr_ = std::make_shared<PhotosDao>(mediaLibraryRdb);
        this->photoAlbumDaoPtr_ = std::make_shared<PhotoAlbumDao>(mediaLibraryRdb);
        this->photosBasicInfo_ = this->photosDaoPtr_->GetBasicInfo();
    }

    PhotosDao::PhotosRowData FindSameFile(const FileInfo &fileInfo)
    {
        int32_t maxFileId = this->photosBasicInfo_.maxFileId;
        return this->photosDaoPtr_->FindSameFile(fileInfo, maxFileId);
    }

    std::shared_ptr<NativeRdb::ResultSet> GetGalleryMedia(
        int32_t offset, int pageSize, bool shouldIncludeSd, bool hasLowQualityImage);
    int32_t GetGalleryMediaCount(bool shouldIncludeSd, bool hasLowQualityImage);
    void GetDuplicateData(int32_t duplicateDataCount);
    bool IsDuplicateData(const std::string &data);

public:
    std::string FindlPath(const FileInfo &fileInfo);
    std::string FindPackageName(const FileInfo &fileInfo);
    std::string FindBundleName(const FileInfo &fileInfo);
    int32_t FindAlbumId(const FileInfo &fileInfo);
    int32_t FindSubtype(const FileInfo &fileInfo);
    int32_t FindDirty(const FileInfo &fileInfo);
    std::string FindBurstKey(const FileInfo &fileInfo);
    int32_t FindBurstCoverLevel(const FileInfo &fileInfo);
    int64_t FindDateTrashed(const FileInfo &fileInfo);
    int32_t FindPhotoQuality(const FileInfo &fileInfo);

private:
    std::string ParseSourcePathToLPath(const std::string &sourcePath);
    PhotoAlbumDao::PhotoAlbumRowData BuildAlbumInfoByLPath(const std::string &lPath);
    PhotoAlbumDao::PhotoAlbumRowData FindAlbumInfo(const FileInfo &fileInfo);
    std::string ToLower(const std::string &str)
    {
        std::string lowerStr;
        std::transform(
            str.begin(), str.end(), std::back_inserter(lowerStr), [](unsigned char c) { return std::tolower(c); });
        return lowerStr;
    }
    std::string ToString(const FileInfo &fileInfo)
    {
        return "FileInfo[ fileId: " + std::to_string(fileInfo.fileIdOld) + ", displayName: " + fileInfo.displayName +
               ", bundleName: " + fileInfo.bundleName + ", lPath: " + fileInfo.lPath +
               ", size: " + std::to_string(fileInfo.fileSize) + ", fileType: " + std::to_string(fileInfo.fileType) +
               " ]";
    }

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;
    PhotosDao::PhotosBasicInfo photosBasicInfo_;
    PhotoAlbumRestore photoAlbumRestore_;
    std::shared_ptr<PhotosDao> photosDaoPtr_ = nullptr;
    std::shared_ptr<PhotoAlbumDao> photoAlbumDaoPtr_;
    std::mutex duplicateDataUsedCountMutex_;
    std::unordered_map<std::string, int32_t> duplicateDataUsedCountMap_;

private:
    const std::string SQL_GALLERY_MEDIA_QUERY_COUNT = "\
        SELECT COUNT(1) AS count \
        FROM gallery_media \
            LEFT JOIN gallery_album \
            ON gallery_media.albumId=gallery_album.albumId \
        WHERE (local_media_id != -1) AND \
            (relative_bucket_id IS NULL OR \
                relative_bucket_id NOT IN ( \
                    SELECT DISTINCT relative_bucket_id \
                    FROM garbage_album \
                    WHERE type = 1 \
                ) \
            ) AND \
            (_size > 0 OR (1 = ? AND _size = 0 AND photo_quality = 0)) AND \
            _data NOT LIKE '/storage/emulated/0/Pictures/cloud/Imports%' AND \
            COALESCE(_data, '') <> '' AND \
            (1 = ? OR storage_id IN (0, 65537) ) \
        ORDER BY _id ASC ;";
    const std::string SQL_GALLERY_MEDIA_QUERY_FOR_RESTORE = "\
        SELECT \
            _id, \
            local_media_id, \
            _data, \
            _display_name, \
            description, \
            is_hw_favorite, \
            recycledTime, \
            _size, \
            duration, \
            media_type, \
            showDateToken, \
            height, \
            width, \
            title, \
            orientation, \
            date_modified, \
            relative_bucket_id, \
            sourcePath, \
            is_hw_burst, \
            recycleFlag, \
            hash, \
            special_file_type, \
            first_update_time, \
            datetaken, \
            detail_time, \
            gallery_album.lPath \
        FROM gallery_media \
            LEFT JOIN gallery_album \
            ON gallery_media.albumId=gallery_album.albumId \
        WHERE (local_media_id != -1) AND \
            (relative_bucket_id IS NULL OR \
                relative_bucket_id NOT IN ( \
                    SELECT DISTINCT relative_bucket_id \
                    FROM garbage_album \
                    WHERE type = 1 \
                ) \
            ) AND \
            (_size > 0 OR (1 = ? AND _size = 0 AND photo_quality = 0)) AND \
            _data NOT LIKE '/storage/emulated/0/Pictures/cloud/Imports%' AND \
            COALESCE(_data, '') <> '' AND \
            (1 = ? OR storage_id IN (0, 65537) ) \
        ORDER BY _id ASC \
        LIMIT ?, ?;";
    const std::string SQL_GALLERY_MEDIA_QUERY_DUPLICATE_DATA = "\
        SELECT _data, count(1) as count \
        FROM gallery_media \
        GROUP BY _data \
        HAVING count(1) > 1 \
        LIMIT ?, ?;";
};
}  // namespace OHOS::Media

#endif  // OHOS_MEDIA_PHOTOS_RESTORE