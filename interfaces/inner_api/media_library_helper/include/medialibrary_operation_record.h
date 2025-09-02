/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_OPERATION_RECORD_H
#define MEDIALIBRARY_OPERATION_RECORD_H

#include "media_column.h"
#include "photo_album_column.h"
#include "photo_map_column.h"

namespace OHOS {
namespace Media {
const std::string OPT_TYPE = "opt_type";
const std::string TYPE = "type";
const std::string IS_SENT = "is_sent";

const std::string CREATE_TAB_ASSET_ALBUM_OPERATION = "CREATE TABLE IF NOT EXISTS " +
    PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    MediaColumn::MEDIA_ID + " INTEGER, " +
    MediaColumn::MEDIA_FILE_PATH + " TEXT, " +
    OPT_TYPE + " INTEGER, " +
    TYPE + " INTEGER, " +
    IS_SENT + " INTEGER, " +
    "UNIQUE (" + FILE_ID + ", " + TYPE + ", " + OPT_TYPE + ", " + IS_SENT + ") " +
    ") ";

// trigger
// Listening of Assets: insert
const std::string OPERATION_ASSET_INSERT_TRIGGER = "operation_asset_insert_trigger";
const std::string CREATE_OPERATION_ASSET_INSERT_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_asset_insert_trigger AFTER INSERT ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN (NEW.media_type = 1 OR NEW.media_type = 2)" +
    " AND NEW.POSITION <> 2" +
    " AND NEW." + PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " <> " +
    to_string(static_cast<int32_t>(FileSourceTypes::TEMP_FILE_MANAGER)) +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( NEW.file_id, NEW.data, 1, 1, 0);" +
    " END;";

// Listening of Assets: delete
const std::string OPERATION_ASSET_DELETE_TRIGGER = "operation_asset_delete_trigger";
const std::string CREATE_OPERATION_ASSET_DELETE_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_asset_delete_trigger AFTER DELETE ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN (OLD.media_type = 1 OR OLD.media_type = 2)" +
    " AND OLD.POSITION <> 2" +
    " AND OLD." + PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " <> " +
    to_string(static_cast<int32_t>(FileSourceTypes::TEMP_FILE_MANAGER)) +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( OLD.file_id, OLD.data, 2, 1, 0);" +
    " END;";

// Listening of Assets: update (title,date_modified,latitude,longitude
// date_day, date_month, date_year, shooting_mode, date_taken, hidden, date_trashed)
const std::string OPERATION_ASSET_UPDATE_TRIGGER = "operation_asset_update_trigger";
const std::string CREATE_OPERATION_ASSET_UPDATE_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_asset_update_trigger AFTER UPDATE ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN (" +
    " (OLD.POSITION = 2 AND NEW.POSITION = 3)" +
    " OR (OLD.POSITION = 3 AND NEW.POSITION = 2)" +
    " OR (NEW.POSITION <> 2" +
    " AND (NEW.data <> OLD.data" +
    " OR NEW.size <> OLD.size" +
    " OR NEW.media_type <> OLD.media_type" +
    " OR NEW.mime_type <> OLD.mime_type" +
    " OR NEW.owner_album_id <> OLD.owner_album_id" +
    " OR NEW.date_modified <> OLD.date_modified" +
    " OR NEW.date_trashed <> OLD.date_trashed" +
    " OR NEW.date_taken <> OLD.date_taken" +
    " OR NEW.height <> OLD.height" +
    " OR NEW.width <> OLD.width" +
    " OR NEW.latitude <> OLD.latitude" +
    " OR NEW.longitude <> OLD.longitude" +
    " OR NEW.duration <> OLD.duration" +
    " OR NEW.orientation <> OLD.orientation" +
    " OR NEW.display_name <> OLD.display_name" +
    " OR NEW.is_favorite <> OLD.is_favorite" +
    " OR NEW.hidden <> OLD.hidden" +
    " OR NEW.user_comment <> OLD.user_comment" +
    " OR NEW.is_temp <> OLD.is_temp" +
    " OR NEW.time_pending <> OLD.time_pending" +
    " OR NEW.moving_photo_effect_mode <> OLD.moving_photo_effect_mode)" +
    " )" +
    " ) AND OLD." + PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " <> " +
    to_string(static_cast<int32_t>(FileSourceTypes::TEMP_FILE_MANAGER)) +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( OLD.file_id, OLD.data, 3, 1, 0);" +
    " END;";

// Listening of album: insert
const std::string OPERATION_ALBUM_INSERT_TRIGGER = "operation_album_insert_trigger";
const std::string CREATE_OPERATION_ALBUM_INSERT_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_album_insert_trigger AFTER INSERT ON " +
    PhotoAlbumColumns::TABLE +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( NEW.album_id, NEW.lpath, 1, 2, 0);" +
    " END;";

// Listening of album: delete
const std::string OPERATION_ALBUM_DELETE_TRIGGER = "operation_album_delete_trigger";
const std::string CREATE_OPERATION_ALBUM_DELETE_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_album_delete_trigger AFTER DELETE ON " +
    PhotoAlbumColumns::TABLE +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( OLD.album_id, OLD.lpath, 2, 2, 0);" +
    " END;";

// Listening of album: update
const std::string OPERATION_ALBUM_UPDATE_TRIGGER = "operation_album_update_trigger";
const std::string CREATE_OPERATION_ALBUM_UPDATE_TRIGGER =
    "CREATE TRIGGER IF NOT EXISTS operation_album_update_trigger AFTER UPDATE ON " +
    PhotoAlbumColumns::TABLE + " FOR EACH ROW " +
    " WHEN " +
    " NEW.album_name <> OLD.album_name" +
    " OR NEW.lpath <> OLD.lpath" +
    " BEGIN " +
    " INSERT OR IGNORE INTO " + PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE +
    " (" + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
    OPT_TYPE + ", " + TYPE + ", " + IS_SENT +
    " ) VALUES ( OLD.album_id, OLD.lpath, 3, 2, 0);" +
    " END;";
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_OPERATION_RECORD_H