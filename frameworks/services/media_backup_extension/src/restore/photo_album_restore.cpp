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
#include <vector>
#include <string>
#include <unordered_set>

#include "photo_album_restore.h"
#include "media_log.h"
#include "rdb_store.h"
#include "rdb_errno.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "backup_const.h"
#include "photo_album_dao.h"

namespace OHOS::Media {
/**
 * @brief get the data of gallery_album table, to restore the PhotoAlbum table
 */
std::vector<PhotoAlbumRestore::GalleryAlbumRowData> PhotoAlbumRestore::GetGalleryAlbums()
{
    std::vector<PhotoAlbumRestore::GalleryAlbumRowData> result;
    std::string querySql = this->SQL_GALLERY_ALBUM_SELECT;
    int rowCount = 0;
    int offset = 0;
    int pageSize = 200;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, pageSize};
        CHECK_AND_BREAK_ERR_LOG(this->galleryRdb_ != nullptr, "Media_Restore: galleryRdb_ is null.");
        auto resultSet = this->galleryRdb_->QuerySql(querySql, params);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "Query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            PhotoAlbumRestore::GalleryAlbumRowData albumInfo;
            albumInfo.albumId = GetStringVal(this->GALLERY_ALBUM_ID, resultSet);
            albumInfo.albumName = GetStringVal(this->GALLERY_ALBUM_NAME, resultSet);
            albumInfo.relativeBucketId = GetStringVal(this->GALLERY_ALBUM_BUCKET_ID, resultSet);
            albumInfo.lPath = GetStringVal(this->GALLERY_ALBUM_lPATH, resultSet);
            albumInfo.bundleName = GetStringVal(this->GALLERY_BUNDLE_NAME, resultSet);
            albumInfo.priority = GetInt32Val(this->GALLERY_PRIORITY, resultSet);
            result.emplace_back(albumInfo);
        }
        // Check if there are more rows to fetch.
        resultSet->GetRowCount(rowCount);
        offset += pageSize;
    } while (rowCount > 0);
    return result;
}

/**
 * @brief Find the albums that need to be restored.
 */
std::vector<PhotoAlbumDao::PhotoAlbumRowData> PhotoAlbumRestore::GetAlbumsToRestore(
    const std::vector<PhotoAlbumDao::PhotoAlbumRowData> &photoAlbums,
    const std::vector<PhotoAlbumRestore::GalleryAlbumRowData> &galleryAlbums)
{
    // cache the lPath of the albums in the gallery_media table
    std::unordered_set<std::string> uniquePaths;
    for (const auto &album : photoAlbums) {
        uniquePaths.insert(album.lPath);
    }
    // filter gallery_media by lPath, find the albums that need to be restored
    // Note 1, the album with the same lPath is considered to be the same album.
    // Note 2, the lPath is case-sensitively matched here,
    // for case-insensitive matching is performed in the SQL excution at the end.
    std::vector<PhotoAlbumRestore::GalleryAlbumRowData> filteredAlbums;
    std::copy_if(galleryAlbums.begin(),
        galleryAlbums.end(),
        std::back_inserter(filteredAlbums),
        [&uniquePaths](const PhotoAlbumRestore::GalleryAlbumRowData &album) {
            return uniquePaths.find(album.lPath) == uniquePaths.end();
        });
    // build the result
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> result;
    for (const PhotoAlbumRestore::GalleryAlbumRowData &galleryAlbum : filteredAlbums) {
        PhotoAlbumDao::PhotoAlbumRowData albumRowData;
        albumRowData.albumType = static_cast<int32_t>(PhotoAlbumType::SOURCE);
        albumRowData.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC);
        albumRowData.albumName = galleryAlbum.albumName;
        albumRowData.bundleName = galleryAlbum.bundleName;
        albumRowData.lPath = galleryAlbum.lPath;
        albumRowData.priority = galleryAlbum.priority;
        result.emplace_back(albumRowData);
    }
    return result;
}
}  // namespace OHOS::Media