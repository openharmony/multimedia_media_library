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

// UPDATE Photos SET owner_album_id =
const std::string UPDATE_ALBUM_ASSET_MAPPING_CONSISTENCY_DATA_SQL =
    "UPDATE " + PhotoColumn::PHOTO_TABLE +
    " SET " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " =" +
    " (SELECT " + PhotoColumn::ALBUM_ID + " FROM " + PhotoMap::TABLE +
    " WHERE Photos." + PhotoColumn::MEDIA_ID + " = PhotoMap." + PhotoMap::ASSET_ID +
    " ) WHERE EXISTS ( SELECT 1 FROM " + PhotoMap::TABLE +
    " WHERE Photos." + PhotoColumn::MEDIA_ID + " = " +
    " PhotoMap." + PhotoMap::ASSET_ID + " AND PhotoMap." + PhotoMap::ASSET_ID + " IN (" +
    " SELECT " + PhotoMap::ASSET_ID + " FROM " + PhotoMap::TABLE + " GROUP BY " +
    PhotoMap::ASSET_ID + " HAVING COUNT(*) = 1));";

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
    "UPDATE photoMap SET dirty = '4' WHERE map_asset "
    "IN (SELECT map_asset FROM PhotoMap GROUP BY map_asset HAVING COUNT(*) = 1)";

const std::string FILL_ALBUM_ID_FOR_PHOTOS =
    "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " +
    "(SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
    " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = " + std::to_string(OHOS::Media::PhotoAlbumType::SOURCE) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC) +
    " AND dirty != 4 ORDER BY priority DESC LIMIT 1) WHERE file_id = new.file_id";

const std::string CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER =
    "CREATE TRIGGER IF NOT EXIST insert_source_photo_create_source_album_trigger AFTER INSERT ON " +
    PhotoColumn::PHOTOS_TABLE + WHEN_SOURCE_PHOTO_COUNT + " = 0 " +
    " BEGIN INSERT INTO " + PhotoAlbumColumns::TABLE + "(" +
    PhotoAlbumColumns::ALBUM_TYPE + " , " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " , " +
    PhotoAlbumColumns::ALBUM_NAME + " , " +
    PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " , " +
    PhotoAlbumColumns::ALBUM_LPATH + " , " +
    PhotoAlbumColumns::ALBUM_PRIORITY + " , " +
    PhotoAlbumColumns::ALBUM_DATE_ADDED +
    " ) VALUES ( " +
    std::to_string(OHOS::Media::PhotoAlbumType::SOURCE) + " , " +
    std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC) + " , " +
    "NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " , " +
    "NEW." + MediaColumn::MEDIA_OWNER_PACKAGE + " , " +
    "COALESCE((SELECT lpath from album_plugin WHERE ((bundle_name = "
    "NEW.owner_package AND COALESCE(NEW.owner_package,'')!= '') OR album_name = NEW.package_name) "
    "and priority ='1', 'Pictures/'||NEW.package_name), 1, "
    "strftime('%s000', 'now')" +
    ");" + FILL_ALBUM_ID_FOR_PHOTOS + "; END;";

const std::string CREATE_INSERT_SOURCE_UPDATE_ALBUM_ID_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS insert_source_photo_update_album_id_trigger AFTER INSERT ON " +
    PhotoColumn::PHOTOS_TABLE + WHEN_SOURCE_PHOTO_COUNT + "> 0 AND NEW.owner_album_id = 0" +
    " BEGIN " + FILL_ALBUM_ID_FOR_PHOTOS + "; END;";

const std::string QUERY_NOT_MATCHED_DATA_IN_PHOTOMAP =
    "SELECT " + PhotoMap::ASSET_ID + ", " + PhotoMap::ALBUM_ID + " FROM " + PhotoMap::TABLE +
    " WHERE dirty != '4' AND " + PhotoMap::ASSET_ID + " IN (SELECT " + PhotoMap::ASSET_ID + " FROM " +
    PhotoMap::TABLE + " GROUP BY " + PhotoMap::ASSET_ID + " HAVING count(*) > 1) ORDER BY " +
    PhotoMap::ASSET_ID + " DESC";

const std::string QUERY_NEW_NOT_MATCHED_DATA_IN_PHOTOMAP =
    "SELECT " + PhotoMap::ASSET_ID + ", " + PhotoMap::ALBUM_ID + " FROM " + PhotoMap::TABLE +
    " WHERE dirty != '4'";

const std::string CREATE_DEFALUT_ALBUM_FOR_NO_RELATIONSHIP_ASSET =
    "INSERT INTO " + PhotoAlbumColumns::TABLE +
    "(album_type, album_subtype, album_name, bundle_name, dirty, is_local, date_added, lpath, priority)"
    " Values ('2048', '2049','其它', 'com.other.album', '1', '1', strftime('%s000', 'now'), '/Pictures/其它', '1')";

const std::string CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET =
    "INSERT INTO " + PhotoAlbumColumns::TABLE +
    "(album_type, album_subtype, album_name, bundle_name, dirty, is_local, date_added, lpath, priority)"
    " Values ('2048', '2049','.hiddenAlbum', 'com.hidden.album', '1', "
    "'1', strftime('%s000', 'now'), '/Pictures/hidden', '1')";
} // namespace Media
} // namespace OHOS
#endif //OHOS_MEDIALIBRARY_ALBUM_COMPATIBILITY_FUSION_DATA_SQL_H