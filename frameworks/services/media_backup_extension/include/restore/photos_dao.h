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
#ifndef OHOS_MEDIA_PHOTOS_DAO
#define OHOS_MEDIA_PHOTOS_DAO

#include <string>

#include "backup_const.h"
#include "rdb_store.h"
#include "media_log.h"

namespace OHOS::Media {
class PhotosDao {
public:
    struct PhotosRowData {
        int32_t fileId;
        std::string data;
        int32_t ownerAlbumId;
        std::string burstKey;
    };

    struct PhotosBasicInfo {
        int32_t maxFileId;
        int32_t count;
    };

public:
    void SetMediaLibraryRdb(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
    {
        this->mediaLibraryRdb_ = mediaLibraryRdb;
    }
    /**
     * @brief Find same file info by lPath, displayName, size, orientation.
     * lPath - if original fileInfo's lPath is empty, it will be ignored.
     * orientation - if original fileInfo's fileType is not Video(2), it will be ignored.
     */
    PhotosRowData FindSameFile(const FileInfo &fileInfo, int32_t maxFileId)
    {
        PhotosRowData rowData;
        if (maxFileId <= 0) {
            return rowData;
        }
        if (fileInfo.lPath.empty()) {
            MEDIA_WARN_LOG("Media_Restore: lPath is empty, FindSameFileWithoutAlbum.");
            return this->FindSameFileWithoutAlbum(fileInfo, maxFileId);
        }
        return this->FindSameFileInAlbum(fileInfo, maxFileId);
    }
    PhotosBasicInfo GetBasicInfo();

private:
    PhotosRowData FindSameFileWithoutAlbum(const FileInfo &fileInfo, int32_t maxFileId);
    PhotosRowData FindSameFileInAlbum(const FileInfo &fileInfo, int32_t maxFileId);

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;

private:
    const std::string SQL_PHOTOS_BASIC_INFO = "\
        SELECT \
            MAX(file_id) AS max_file_id, \
            COUNT(1) AS count \
        FROM Photos; \
    ";
    const std::string SQL_PHOTOS_FIND_SAME_FILE_IN_ALBUM = "\
        SELECT \
            p.file_id, \
            p.data \
        FROM \
        ( \
            SELECT album_id \
            FROM PhotoAlbum \
            WHERE LOWER(lpath) = LOWER(?) \
        ) \
        AS a \
        INNER JOIN \
        ( \
            SELECT \
                file_id, \
                data, \
                size, \
                orientation, \
                owner_album_id \
            FROM Photos \
            WHERE file_id <= ? AND \
                display_name = ? AND \
                size = ? AND \
                ( 1 <> ? OR orientation= ? ) \
        ) \
        AS p \
        ON a.album_id = p.owner_album_id \
        LIMIT 1; ";
    const std::string SQL_PHOTOS_FIND_SAME_FILE_WITHOUT_ALBUM = "\
        SELECT \
            P.file_id, \
            P.data \
        FROM Photos AS P \
        WHERE file_id <= ? AND \
            display_name = ? AND \
            size = ? AND \
            (owner_album_id IS NULL OR owner_album_id = 0) AND \
            (1 <> ? OR orientation = ?) \
        LIMIT 1;";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTOS_DAO