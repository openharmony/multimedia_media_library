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

#ifndef OHOS_MEDIALIBRARY_ALBUM_COMPATIBILITY_FUSION_DATA_SQL_H
#define OHOS_MEDIALIBRARY_ALBUM_COMPATIBILITY_FUSION_DATA_SQL_H

#include "media_column.h"
#include "photo_map_column.h"
#include "source_album.h"

namespace OHOS {
namespace Media {

const std::string CREATE_TEMP_UPGRADE_PHOTO_MAP_TABLE =
    "CREATE TABLE IF NOT EXISTS temp_upgrade_photo_map AS SELECT MIN(map_album) AS map_album, map_asset FROM PhotoMap "
    "INNER JOIN Photos ON PhotoMap.map_asset=Photos.file_id where COALESCE(owner_album_id, 0) = 0 GROUP BY map_asset;";

const std::string QUERY_MATCHED_COUNT =
    "SELECT COUNT(1) from temp_upgrade_photo_map";

const std::string QUERY_SUCCESS_MATCHED_COUNT =
    "SELECT COUNT(1) from Photos where owner_album_id != 0";

const std::string CREATE_UNIQUE_TEMP_UPGRADE_INDEX_ON_MAP_ASSET =
    "CREATE INDEX IF NOT EXISTS unique_temp_upgrade_index_on_map_asset ON temp_upgrade_photo_map (map_asset);";

const std::string CREATE_UNIQUE_TEMP_UPGRADE_INDEX_ON_PHOTO_MAP =
    "CREATE UNIQUE INDEX IF NOT EXISTS unique_temp_upgrade_index_on_photo_map ON "
    "temp_upgrade_photo_map (map_album, map_asset);";

const std::string UPDATE_ALBUM_ASSET_MAPPING_CONSISTENCY_DATA_SQL =
    "UPDATE Photos SET owner_album_id =(SELECT map_album FROM temp_upgrade_photo_map WHERE file_id=map_asset "
    "UNION SELECT 0 AS map_album ORDER BY map_album DESC LIMIT 1) WHERE COALESCE(owner_album_id, 0)=0;";

const std::string DROP_PHOTO_ALBUM_CLEAR_MAP_SQL =
    "DROP TRIGGER IF EXISTS photo_album_clear_map";
const std::string DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM_SQL =
    "DROP TRIGGER IF EXISTS insert_photo_insert_source_album";
const std::string DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM_SQL =
    "DROP TRIGGER IF EXISTS insert_photo_update_source_album";

const std::string DROP_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER =
    "DROP TRIGGER IF EXISTS insert_source_photo_create_source_album_trigger";
const std::string DROP_INSERT_SOURCE_PHOTO_UPDATE_ALBUM_ID_TRIGGER =
    "DROP TRIGGER IF EXISTS insert_source_photo_update_album_id_trigger";

const std::string DROP_INDEX_SOURCE_ALBUM_INDEX =
    "DROP INDEX IF EXISTS " + SOURCE_ALBUM_INDEX;

const std::string DELETE_MATCHED_RELATIONSHIP_IN_PHOTOMAP_SQL =
    "UPDATE PhotoMap SET dirty = '4' WHERE EXISTS (SELECT 1 FROM temp_upgrade_photo_map "
    " WHERE PhotoMap.map_album=temp_upgrade_photo_map.map_album AND "
    " PhotoMap.map_asset=temp_upgrade_photo_map.map_asset);";

const std::string DROP_TEMP_UPGRADE_PHOTO_MAP_TABLE =
    "DROP TABLE IF EXISTS temp_upgrade_photo_map;";

const std::string FILL_ALBUM_ID_FOR_PHOTOS =
    "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " +
    "(SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
    " WHERE (" + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME +
    " OR bundle_name = NEW.owner_package) AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = " + std::to_string(OHOS::Media::PhotoAlbumType::SOURCE) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC) +
    " AND dirty != 4 ORDER BY priority DESC LIMIT 1) WHERE file_id = new.file_id";

const std::string PHOTO_ALBUM_NOTIFY_FUNC =
    "SELECT photo_album_notify_func((SELECT " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
    " FROM " + PhotoColumn::PHOTOS_TABLE +
    " WHERE " + MediaColumn::MEDIA_ID + " = NEW." + MediaColumn::MEDIA_ID + "));";

const std::string CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER = SOURCE_ALBUM_SQL;

const std::string QUERY_NOT_MATCHED_DATA_IN_PHOTOMAP_BY_PAGE =
    "SELECT " + PhotoMap::ASSET_ID + ", " + PhotoMap::ALBUM_ID + " FROM " + PhotoMap::TABLE +
    " WHERE dirty <>4 and dirty<>6 LIMIT 0, 200";

const std::string QUERY_NEW_NOT_MATCHED_DATA_IN_PHOTOMAP_BY_PAGE =
    "SELECT " + PhotoMap::ASSET_ID + ", " + PhotoMap::ALBUM_ID + " FROM " + PhotoMap::TABLE +
    " WHERE dirty <>4 LIMIT 0, 200";

const std::string QUERY_NOT_MATCHED_COUNT_IN_PHOTOMAP =
    "SELECT count(1) FROM PhotoMap WHERE dirty <>4 and dirty<>6";

const std::string QUERY_NEW_NOT_MATCHED_COUNT_IN_PHOTOMAP =
    "SELECT count(1) FROM PhotoMap WHERE dirty <>4";

const std::string CREATE_DEFALUT_ALBUM_FOR_NO_RELATIONSHIP_ASSET =
    "INSERT INTO " + PhotoAlbumColumns::TABLE +
        "(album_type, album_subtype, album_name,bundle_name, dirty, is_local, date_modified, " +
        "date_added, lpath, priority) Values ('2048', '2049', '其它', 'com.other.album', '1', '1', " +
        "strftime('%s000', 'now'), strftime('%s000', 'now'), '/Pictures/其它', '1')";

const std::string CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET =
    "INSERT INTO " + PhotoAlbumColumns::TABLE +
        "(album_type, album_subtype, album_name, bundle_name, dirty, is_local, date_added, lpath, priority)"
        " Values ('2048', '2049', '.hiddenAlbum', 'com.hidden.album', '1', "
        "'1', strftime('%s000', 'now'), '/Pictures/hiddenAlbum', '1')";

const std::string SELECT_HIDDEN_ALBUM_ID =
    "(SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_NAME + " = '.hiddenAlbum' AND " + PhotoAlbumColumns::ALBUM_DIRTY +
        " <> 4 AND " + PhotoAlbumColumns::ALBUM_TYPE + " = '2048')";

const std::string SELECT_ALL_HIDDEN_ALBUM_ASSET_ID =
    "(SELECT " + PhotoMap::ASSET_ID + " FROM " + PhotoMap::TABLE + " WHERE " +
        PhotoMap::ALBUM_ID + " = " + SELECT_HIDDEN_ALBUM_ID + ")";

const std::string DROP_UNWANTED_ALBUM_RELATIONSHIP_FOR_HIDDEN_ALBUM_ASSET =
    "UPDATE " + PhotoMap::TABLE + " SET " + PhotoMap::DIRTY + " = 4 " +
        "WHERE " + PhotoMap::ASSET_ID + " in " + SELECT_ALL_HIDDEN_ALBUM_ASSET_ID +
        " AND " + PhotoMap::ALBUM_ID + " <> " + SELECT_HIDDEN_ALBUM_ID;

} // namespace Media
} // namespace OHOS
#endif  // OHOS_MEDIALIBRARY_ALBUM_COMPATIBILITY_FUSION_DATA_SQL_H