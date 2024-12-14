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

#include "medialibrary_rdbstore.h"
#include "photo_album_info_po.h"

namespace OHOS::Media {
class PhotoAlbumLPathOperation {
public:
    static PhotoAlbumLPathOperation &GetInstance();
    PhotoAlbumLPathOperation &SetRdbStore(const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr);
    PhotoAlbumLPathOperation &CleanInvalidPhotoAlbums();
    PhotoAlbumLPathOperation &CleanDuplicatePhotoAlbums();
    PhotoAlbumLPathOperation &CleanEmptylPathPhotoAlbums();
    int32_t GetAlbumAffectedCount() const;
    PhotoAlbumLPathOperation &Start();
    void Stop();

private:
    std::string ToString(const std::vector<NativeRdb::ValueObject> &values);
    std::vector<PhotoAlbumInfoPo> GetInvalidPhotoAlbums();
    std::vector<PhotoAlbumInfoPo> GetDuplicatelPathAlbumInfoMain();
    std::vector<PhotoAlbumInfoPo> GetDuplicatelPathAlbumInfoSub(const PhotoAlbumInfoPo &albumInfo);
    int32_t MergePhotoAlbum(const PhotoAlbumInfoPo &mainAlbumInfo, const PhotoAlbumInfoPo &subAlbumInfo);
    std::vector<PhotoAlbumInfoPo> GetEmptylPathAlbumInfo();
    int32_t CleanDuplicatePhotoAlbum(const PhotoAlbumInfoPo &mainAlbumInfo);
    int32_t CleanEmptylPathPhotoAlbum(const PhotoAlbumInfoPo &subAlbumInfo);
    PhotoAlbumInfoPo GetLatestAlbumInfoBylPath(const std::string &lPath);
    int32_t UpdateAlbumInfoFromAlbumPluginByAlbumId(const PhotoAlbumInfoPo &albumInfo);
    int32_t UpdateAlbumLPathByAlbumId(const PhotoAlbumInfoPo &albumInfo);

private:
    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;
    int32_t albumAffectedCount_;
    std::atomic<bool> isContinue_{true};
    static std::shared_ptr<PhotoAlbumLPathOperation> instance_;
    static std::mutex objMutex_;

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
    const std::string SQL_PHOTO_ALBUM_DUPLICATE_LPATH_MAIN_QUERY = "\
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
        WHERE album_id IN \
        ( \
            SELECT \
                MAX(album_id) AS album_id \
            FROM PhotoAlbum \
            WHERE album_type IN (0, 2048) AND \
                COALESCE(lpath, '') <> '' \
            GROUP BY LOWER(lpath) \
            HAVING COUNT(1) > 1 \
        ) \
        ORDER BY album_id;";
    const std::string SQL_PHOTO_ALBUM_DUPLICATE_LPATH_SUB_QUERY = "\
        SELECT \
            PhotoAlbum.album_id, \
            album_name, \
            album_type, \
            album_subtype, \
            PhotoAlbum.lpath, \
            bundle_name, \
            dirty, \
            count, \
            cloud_id, \
            priority \
        FROM PhotoAlbum \
            LEFT JOIN \
            ( \
                SELECT \
                    ? AS album_id, \
                    ? AS lpath \
            ) AS INPUT \
            ON 1 = 1 \
        WHERE album_type IN (0, 2048) AND \
            LOWER(COALESCE(PhotoAlbum.lpath, '')) = LOWER(INPUT.lpath) AND \
            PhotoAlbum.album_id <> INPUT.album_id \
        ORDER BY PhotoAlbum.album_id;";
    const std::string SQL_PHOTO_ALBUM_FIX_LPATH_QUERY = "\
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
        FROM \
        ( \
            SELECT \
                album_id, \
                EMPTY.album_name, \
                album_type, \
                album_subtype, \
                CASE WHEN COALESCE(BUNDLE.bundle_name, '') <> '' THEN BUNDLE.lpath \
                    WHEN COALESCE(cloud_id, '') <> '' THEN '' \
                    WHEN COALESCE(NAME.album_name, '') <> '' THEN NAME.lpath \
                    ELSE '/Pictures/'||EMPTY.album_name \
                END AS lpath, \
                EMPTY.bundle_name, \
                dirty, \
                count, \
                cloud_id, \
                priority \
            FROM \
            ( \
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
                WHERE COALESCE(lPath, '') = '' AND \
                    album_type = 2048 \
            ) AS EMPTY \
            LEFT JOIN \
            ( \
                SELECT DISTINCT \
                    bundle_name, \
                    lpath \
                FROM album_plugin \
                WHERE COALESCE(bundle_name, '') <> '' AND \
                    COALESCE(priority, 1) = 1 \
            ) AS BUNDLE \
            ON COALESCE(EMPTY.bundle_name, '') = COALESCE(BUNDLE.bundle_name, '') \
            LEFT JOIN \
            ( \
                SELECT DISTINCT album_name, \
                    album_name_en, \
                    lpath \
                FROM album_plugin \
                WHERE COALESCE(album_name, '') <> '' AND \
                    COALESCE(priority, 1) = 1 \
            ) AS NAME \
            ON COALESCE(EMPTY.album_name, '') = COALESCE(NAME.album_name, '') OR \
                COALESCE(EMPTY.album_name, '') = COALESCE(NAME.album_name_en, '') \
        ) \
        WHERE COALESCE(lpath, '') <> '' \
        ORDER BY album_id; ";
    const std::string SQL_PHOTO_ALBUM_SYNC_BUNDLE_NAME_UPDATE = "\
        UPDATE PhotoAlbum \
        SET \
            album_name = COALESCE( \
                                ( \
                                    SELECT album_name \
                                    FROM album_plugin \
                                    WHERE LOWER(lpath) = LOWER(?) \
                                    LIMIT 1 \
                                ), album_name), \
            bundle_name = COALESCE( \
                                ( \
                                    SELECT bundle_name \
                                    FROM album_plugin \
                                    WHERE LOWER(lpath) = LOWER(?) \
                                    LIMIT 1 \
                                ), bundle_name), \
            priority = COALESCE( \
                                ( \
                                    SELECT priority \
                                    FROM album_plugin \
                                    WHERE LOWER(lpath) = LOWER(?) \
                                    LIMIT 1 \
                                ), priority) \
        WHERE album_id = ? AND \
            LOWER(lpath) = LOWER(?) AND \
            LOWER(lpath) IN ( \
                SELECT DISTINCT LOWER(lpath) \
                FROM album_plugin \
                WHERE COALESCE(lpath,'') <> '' \
            );";
    const std::string SQL_PHOTO_ALBUM_QUERY_BY_LPATH = "\
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
        WHERE LOWER(COALESCE(lpath, '')) = LOWER(?) \
        ORDER BY album_id DESC \
        LIMIT 1;";
    const std::string SQL_PHOTO_ALBUM_UPDATE_LPATH_BY_ALBUM_ID = "\
        UPDATE PhotoAlbum \
        SET lpath = ? \
        WHERE album_id = ? AND \
            album_type = 2048 AND \
            COALESCE(lpath, '') = '' AND \
            LOWER(?) NOT IN ( \
                SELECT DISTINCT LOWER(PA.lpath) \
                FROM PhotoAlbum AS PA \
                WHERE COALESCE(PA.lpath, '') <> '' \
            );";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_ALBUM_LPATH_OPERATION_H