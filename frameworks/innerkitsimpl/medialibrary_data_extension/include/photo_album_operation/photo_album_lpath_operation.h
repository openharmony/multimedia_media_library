/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PHOTO_ALBUM_LPATH_OPERATION_H
#define OHOS_MEDIA_PHOTO_ALBUM_LPATH_OPERATION_H

#include <string>
#include <vector>
#include <sstream>

#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
class PhotoAlbumLPathOperation {
private:
    class PhotoAlbumInfo {
    public:
        int32_t albumId;
        std::string albumName;
        std::string lPath;
        int32_t albumType;
        int32_t albumSubType;
        std::string bundleName;
        int32_t dirty;
        int32_t count;
        std::string cloudId;
        int32_t priority;

    public:
        std::string ToString() const
        {
            std::stringstream ss;
            ss << "PhotoAlbumInfo["
               << ", albumId: " << this->albumId << ", albumName: " << this->albumName << ", lPath: " << this->lPath
               << ", albumType: " << this->albumType << "albumSubType: " << this->albumSubType
               << ", bundleName: " << this->bundleName << ", cloudId: " << this->cloudId << ", dirty: " << this->dirty
               << ", count: " << this->count << ", priority: " << this->priority << "]";
            return ss.str();
        }
    };

public:
    PhotoAlbumLPathOperation &SetRdbStore(const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr);
    int32_t CleanInvalidPhotoAlbums();

private:
    std::vector<PhotoAlbumInfo> GetInvalidPhotoAlbums();

private:
    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;

private:
    const std::string SQL_PHOTO_ALBUM_EMPTY_QUERY = "\
        SELECT \
            album_id, \
            album_name, \
            album_type, \
            album_subtype, \
            lpath, \
            bundle_name, \
            dirty, \
            count, \
            cloud_id, \
            priority \
        FROM PhotoAlbum \
        WHERE COALESCE(lpath, '') = '' AND \
            album_type = 2048 AND \
            COALESCE(PhotoAlbum.dirty, 1) <> 4 AND \
            album_id NOT IN ( \
                SELECT DISTINCT owner_album_id \
                FROM Photos \
            ) AND \
            album_id NOT IN ( \
                SELECT DISTINCT map_album \
                FROM PhotoMap \
                    INNER JOIN Photos \
                    ON PhotoMap.map_asset = Photos.file_id \
            );";
    const std::string SQL_PHOTO_ALBUM_EMPTY_DELETE = "\
        DELETE FROM PhotoAlbum \
        WHERE COALESCE(lpath, '') = '' AND \
            album_type = 2048 AND \
            COALESCE(PhotoAlbum.dirty, 1) <> 4 AND \
            album_id NOT IN ( \
                SELECT DISTINCT owner_album_id \
                FROM Photos \
            ) AND \
            album_id NOT IN ( \
                SELECT DISTINCT map_album \
                FROM PhotoMap \
                    INNER JOIN Photos \
                    ON PhotoMap.map_asset = Photos.file_id \
            ) ;";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_ALBUM_LPATH_OPERATION_H