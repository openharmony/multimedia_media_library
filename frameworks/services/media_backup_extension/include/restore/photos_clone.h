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
#ifndef OHOS_MEDIA_PHOTOS_CLONE
#define OHOS_MEDIA_PHOTOS_CLONE

#include <string>
#include <vector>

#include "rdb_store.h"
#include "backup_const.h"
#include "photos_dao.h"
#include "photo_album_dao.h"

namespace OHOS::Media {
class PhotosClone {
public:
    /**
     * @brief Restore Start Event Handler.
     */
    int32_t OnStart(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryTargetRdb,
        std::shared_ptr<NativeRdb::RdbStore> mediaLibraryOriginalRdb)
    {
        this->mediaLibraryTargetRdb_ = mediaLibraryTargetRdb;
        this->mediaLibraryOriginalRdb_ = mediaLibraryOriginalRdb;
        this->photosDaoPtr_ = std::make_shared<PhotosDao>(mediaLibraryTargetRdb);
        this->photosBasicInfo_ = this->photosDaoPtr_->GetBasicInfo();
        this->photoAlbumDaoPtr_ = std::make_shared<PhotoAlbumDao>(mediaLibraryTargetRdb);
        return 0;
    }

    int32_t OnStop(std::atomic<uint64_t> &totalNumber, std::atomic<int32_t> &processStatus)
    {
        processStatus = ProcessStatus::START;
        this->FixDuplicateBurstKeyInDifferentAlbum(totalNumber);
        processStatus = ProcessStatus::STOP;
        return 0;
    }

    PhotosDao::PhotosRowData FindSameFile(const FileInfo &fileInfo)
    {
        int32_t maxFileId = this->photosBasicInfo_.maxFileId;
        return this->photosDaoPtr_->FindSameFile(fileInfo, maxFileId);
    }

    std::shared_ptr<NativeRdb::ResultSet> GetPhotosInPhotoMap(int32_t offset, int32_t pageSize);
    std::shared_ptr<NativeRdb::ResultSet> GetPhotosNotInPhotoMap(int32_t offset, int32_t pageSize);
    int32_t GetPhotosRowCountInPhotoMap();
    int32_t GetPhotosRowCountNotInPhotoMap();
    std::string FindlPath(const FileInfo &fileInfo);
    int32_t FindAlbumId(const FileInfo &fileInfo);
    std::string FindPackageName(const FileInfo &info);
    std::string FindBundleName(const FileInfo &info);

private:
    enum { UUID_STR_LENGTH = 37 };

private:
    PhotoAlbumDao::PhotoAlbumRowData FindAlbumInfo(const FileInfo &fileInfo);
    int32_t FixDuplicateBurstKeyInDifferentAlbum(std::atomic<uint64_t> &totalNumber);
    std::vector<PhotosDao::PhotosRowData> FindDuplicateBurstKey();
    std::string ToString(const std::vector<NativeRdb::ValueObject> &values);
    std::string GenerateUuid();
    std::string ToString(const FileInfo &fileInfo);
    std::string ToLower(const std::string &str);

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryTargetRdb_;
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryOriginalRdb_;
    PhotosDao::PhotosBasicInfo photosBasicInfo_;
    std::shared_ptr<PhotosDao> photosDaoPtr_ = nullptr;
    std::shared_ptr<PhotoAlbumDao> photoAlbumDaoPtr_ = nullptr;

private:
    std::string SQL_PHOTOS_TABLE_COUNT_IN_PHOTO_MAP = "\
        SELECT COUNT(1) AS count \
        FROM PhotoAlbum \
            INNER JOIN PhotoMap \
            ON PhotoAlbum.album_id=PhotoMap.map_album \
            INNER JOIN Photos \
            ON PhotoMap.map_asset=Photos.file_id \
        WHERE Photos.position IN (1, 3) AND \
            (PhotoAlbum.album_type != 2048 OR PhotoAlbum.album_name != '.hiddenAlbum');";
    std::string SQL_PHOTOS_TABLE_QUERY_IN_PHOTO_MAP = "\
        SELECT PhotoAlbum.lpath, \
            Photos.* \
        FROM PhotoAlbum \
            INNER JOIN PhotoMap \
            ON PhotoAlbum.album_id=PhotoMap.map_album \
            INNER JOIN Photos \
            ON PhotoMap.map_asset=Photos.file_id \
        WHERE Photos.position IN (1, 3) AND \
            (PhotoAlbum.album_type != 2048 OR PhotoAlbum.album_name != '.hiddenAlbum') \
        ORDER BY Photos.file_id \
        LIMIT ?, ? ;";
    std::string SQL_PHOTOS_TABLE_COUNT_NOT_IN_PHOTO_MAP = "\
        SELECT COUNT(1) AS count \
        FROM Photos \
            LEFT JOIN PhotoAlbum \
            ON Photos.owner_album_id = PhotoAlbum.album_id \
        WHERE position IN (1, 3) AND \
            (COALESCE(PhotoAlbum.album_type, 0) != 2048 OR COALESCE(PhotoAlbum.album_name, '') != '.hiddenAlbum');";
    std::string SQL_PHOTOS_TABLE_QUERY_NOT_IN_PHOTO_MAP = "\
        SELECT \
            PhotoAlbum.lpath, \
            Photos.* \
        FROM Photos \
            LEFT JOIN PhotoAlbum \
            ON Photos.owner_album_id=PhotoAlbum.album_id \
        WHERE position IN (1, 3) AND \
            (COALESCE(PhotoAlbum.album_type, 0) != 2048 OR COALESCE(PhotoAlbum.album_name, '') != '.hiddenAlbum') \
        ORDER BY Photos.file_id \
        LIMIT ?, ? ;";
    std::string SQL_PHOTOS_TABLE_BURST_KEY_DUPLICATE_QUERY = "\
        SELECT DISTINCT \
            Photos.owner_album_id, \
            Photos.burst_key \
        FROM \
        ( \
            SELECT burst_key, \
                COUNT(1) AS count \
            FROM \
            ( \
                SELECT owner_album_id, burst_key \
                FROM Photos \
                WHERE burst_key IS NOT NULL \
                GROUP BY owner_album_id, burst_key \
            ) \
            GROUP BY burst_key \
        ) AS BURST \
        INNER JOIN Photos \
        ON BURST.burst_key = Photos.burst_key \
        WHERE BURST.count > 1 \
        ORDER BY Photos.burst_key \
        LIMIT ?, ? ;";
    std::string SQL_PHOTOS_TABLE_BURST_KEY_UPDATE = "\
        UPDATE Photos \
        SET burst_key = ? \
        WHERE owner_album_id = ? AND \
            burst_key = ?;";
};
}  // namespace OHOS::Media
#endif