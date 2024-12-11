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

#ifndef OHOS_MEDIA_PHOTO_ALBUM_MERGE_OPERATION_H
#define OHOS_MEDIA_PHOTO_ALBUM_MERGE_OPERATION_H

#include <string>
#include <vector>
#include <sstream>

#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
class PhotoAlbumMergeOperation {
public:
    PhotoAlbumMergeOperation &SetRdbStore(const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr);
    int32_t MergeAlbum(const int32_t &oldAlbumId, const int32_t &newAlbumId);

private:
    std::string ToString(const std::vector<NativeRdb::ValueObject> &values);
    int32_t DeleteDuplicateRelationshipInPhotoMap(const int32_t &oldAlbumId, const int32_t &newAlbumId);
    int32_t UpdateRelationshipInPhotoMap(const int32_t &oldAlbumId, const int32_t &newAlbumId);
    int32_t UpdateRelationshipInPhotos(const int32_t &oldAlbumId, const int32_t &newAlbumId);
    int32_t DeleteOldAlbum(const int32_t &oldAlbumId);

private:
    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;

private:
    const std::string SQL_PHOTO_MAP_DUPLICATE_RELATIONSHIP_DELETE = "\
        DELETE FROM PhotoMap \
        WHERE map_album = ? AND \
            map_asset IN \
            ( \
                SELECT DISTINCT map_asset \
                FROM PhotoMap \
                WHERE map_album = ? \
            ); ";
    const std::string SQL_PHOTO_MAP_MOVE_RELATIONSHIP_UPDATE = "\
        UPDATE PhotoMap \
        SET map_album = ? \
        WHERE map_album = ? AND \
            ? IN ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE album_type IN (0, 2048) \
            );";
    const std::string SQL_PHOTOS_MOVE_RELATIONSHIP_UPDATE = "\
        UPDATE Photos \
        SET owner_album_id = ? \
        WHERE owner_album_id = ? AND \
            ? IN ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE album_type IN (0, 2048) \
            );";
    const std::string SQL_PHOTO_ALBUM_DELETE = "\
        DELETE FROM PhotoAlbum \
        WHERE album_id = ? AND \
            album_id NOT IN ( \
                SELECT DISTINCT owner_album_id \
                FROM Photos \
            ) AND \
            album_id NOT IN ( \
                SELECT DISTINCT map_album \
                FROM PhotoMap \
            );";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_ALBUM_MERGE_OPERATION_H