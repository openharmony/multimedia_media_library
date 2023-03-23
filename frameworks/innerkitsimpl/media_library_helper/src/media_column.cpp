/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "media_column.h"

#include <string>

namespace OHOS {
namespace Media {

const std::string MediaColumn::MEDIA_ID = "file_id";
const std::string MediaColumn::MEDIA_URI = "uri";
const std::string MediaColumn::MEDIA_FILE_PATH = "data";
const std::string MediaColumn::MEDIA_SIZE = "size";
const std::string MediaColumn::MEDIA_TITLE = "title";
const std::string MediaColumn::MEDIA_NAME = "display_name";
const std::string MediaColumn::MEDIA_TYPE = "media_type";
const std::string MediaColumn::MEDIA_MIME_TYPE = "mime_type";
const std::string MediaColumn::MEDIA_OWNER_PACKAGE = "owner_package";
const std::string MediaColumn::MEDIA_DEVICE_NAME = "device_name";
const std::string MediaColumn::MEDIA_THUMBNAIL = "thumbnail";
const std::string MediaColumn::MEDIA_DATE_MODIFIED = "date_modified";
const std::string MediaColumn::MEDIA_DATE_ADDED = "date_added";
const std::string MediaColumn::MEDIA_DATE_TAKEN = "date_taken";
const std::string MediaColumn::MEDIA_TIME_VISIT = "time_visit";
const std::string MediaColumn::MEDIA_DURATION = "duration";
const std::string MediaColumn::MEDIA_TIME_PENDING = "time_pending";
const std::string MediaColumn::MEDIA_IS_FAV = "is_favorite";
const std::string MediaColumn::MEDIA_DATE_TRASHED = "data_trashed";
const std::string MediaColumn::MEDIA_DATE_DELETED = "data_deleted";
const std::string MediaColumn::MEDIA_HIDDEN = "hidden";
const std::string MediaColumn::MEDIA_PARENT_ID = "parent";
const std::string MediaColumn::MEDIA_RELATIVE_PATH = "relative_path";

const std::string PhotoColumn::PHOTO_ORIENTATION = "orientation";
const std::string PhotoColumn::PHOTO_LATITUDE = "latitude";
const std::string PhotoColumn::PHOTO_LONGITUDE = "longitude";
const std::string PhotoColumn::PHOTO_LCD = "lcd";
const std::string PhotoColumn::PHOTO_HEIGHT = "height";
const std::string PhotoColumn::PHOTO_WIDTH = "width";
const std::string PhotoColumn::PHOTO_LCD_VISIT_TIME = "lcd_visit_time";

const std::string PhotoColumn::PHOTOS_TABLE = "Photos";

const std::string PhotoColumn::CREATE_PHOTO_TABLE = "CREATE TABLE IF NOT EXISTS " +
    PHOTOS_TABLE + " (" +
    MEDIA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    MEDIA_URI + " TEXT, " +
    MEDIA_FILE_PATH + " TEXT, " +
    MEDIA_SIZE + " BIGINT, " +
    MEDIA_TITLE + " TEXT, " +
    MEDIA_NAME + " TEXT, " +
    MEDIA_TYPE + " INT, " +
    MEDIA_MIME_TYPE + " TEXT, " +
    MEDIA_OWNER_PACKAGE + " TEXT, " +
    MEDIA_DEVICE_NAME + " TEXT, " +
    MEDIA_THUMBNAIL + " TEXT, " +
    MEDIA_DATE_ADDED + " BIGINT, " +
    MEDIA_DATE_MODIFIED + " BIGINT, " +
    MEDIA_DATE_TAKEN + " BIGINT DEFAULT 0, " +
    MEDIA_TIME_VISIT + " BIGINT DEFAULT 0, " +
    MEDIA_DURATION + " INT, " +
    MEDIA_TIME_PENDING + " BIGINT DEFAULT 0, " +
    MEDIA_IS_FAV + " INT DEFAULT 0, " +
    MEDIA_DATE_TRASHED + " BIGINT DEFAULT 0, " +
    MEDIA_DATE_DELETED + " BIGINT DEFAULT 0, " +
    MEDIA_HIDDEN + "INT DEFAULT 0, " +
    MEDIA_PARENT_ID + " INT DEFAULT 0, " +
    MEDIA_RELATIVE_PATH + " TEXT, " +
    PHOTO_ORIENTATION + " INT DEFAULT 0, " +
    PHOTO_LATITUDE + " DOUBLE DEFAULT 0, " +
    PHOTO_LONGITUDE + " DOUBLE DEFAULT 0, " +
    PHOTO_LCD + " TEXT, " +
    PHOTO_HEIGHT + " INT, " +
    PHOTO_WIDTH + " INT, " +
    PHOTO_LCD_VISIT_TIME + " BIGINT DEFAULT 0)";

const std::string AudioColumn::AUDIO_ALBUM = "audio_album";
const std::string AudioColumn::AUDIO_ARTIST = "artist";

const std::string AudioColumn::AUDIOS_TABLE = "Audios";

const std::string AudioColumn::CREATE_AUDIO_TABLE = "CREATE TABLE IF NOT EXISTS " +
    AUDIOS_TABLE + " (" +
    MEDIA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    MEDIA_URI + " TEXT, " +
    MEDIA_FILE_PATH + " TEXT, " +
    MEDIA_SIZE + " BIGINT, " +
    MEDIA_TITLE + " TEXT, " +
    MEDIA_NAME + " TEXT, " +
    MEDIA_TYPE + " INT, " +
    MEDIA_MIME_TYPE + " TEXT, " +
    MEDIA_OWNER_PACKAGE + " TEXT, " +
    MEDIA_DEVICE_NAME + " TEXT, " +
    MEDIA_THUMBNAIL + " TEXT, " +
    AUDIO_ARTIST + " TEXT, " +
    MEDIA_DATE_ADDED + " BIGINT, " +
    MEDIA_DATE_MODIFIED + " BIGINT, " +
    MEDIA_DATE_TAKEN + " BIGINT DEFAULT 0, " +
    MEDIA_TIME_VISIT + " BIGINT DEFAULT 0, " +
    MEDIA_DURATION + " INT, " +
    MEDIA_TIME_PENDING + " BIGINT DEFAULT 0, " +
    MEDIA_IS_FAV + " INT DEFAULT 0, " +
    MEDIA_DATE_TRASHED + " BIGINT DEFAULT 0, " +
    MEDIA_DATE_DELETED + " BIGINT DEFAULT 0, " +
    MEDIA_HIDDEN + "INT DEFAULT 0, " +
    MEDIA_PARENT_ID + " INT DEFAULT 0, " +
    MEDIA_RELATIVE_PATH + " TEXT, " +
    AUDIO_ALBUM + " TEXT)";

const std::string DocumentColumn::DOCUMENT_LCD = "lcd";
const std::string DocumentColumn::DOCUMENT_LCD_VISIT_TIME = "lcd_visit_time";

const std::string DocumentColumn::DOCUMENTS_TABLE = "Documents";

const std::string DocumentColumn::CREATE_DOCUMENT_TABLE = "CREATE TABLE IF NOT EXISTS " +
    DOCUMENTS_TABLE + " (" +
    MEDIA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    MEDIA_URI + " TEXT, " +
    MEDIA_FILE_PATH + " TEXT, " +
    MEDIA_SIZE + " BIGINT, " +
    MEDIA_TITLE + " TEXT, " +
    MEDIA_NAME + " TEXT, " +
    MEDIA_TYPE + " INT, " +
    MEDIA_MIME_TYPE + " TEXT, " +
    MEDIA_OWNER_PACKAGE + " TEXT, " +
    MEDIA_DEVICE_NAME + " TEXT, " +
    MEDIA_THUMBNAIL + " TEXT, " +
    MEDIA_DATE_ADDED + " BIGINT, " +
    MEDIA_DATE_MODIFIED + " BIGINT, " +
    MEDIA_DATE_TAKEN + " BIGINT DEFAULT 0, " +
    MEDIA_TIME_VISIT + " BIGINT DEFAULT 0, " +
    MEDIA_DURATION + " INT, " +
    MEDIA_TIME_PENDING + " BIGINT DEFAULT 0, " +
    MEDIA_IS_FAV + " INT DEFAULT 0, " +
    MEDIA_DATE_TRASHED + " BIGINT DEFAULT 0, " +
    MEDIA_DATE_DELETED + " BIGINT DEFAULT 0, " +
    MEDIA_HIDDEN + "INT DEFAULT 0, " +
    MEDIA_PARENT_ID + " INT DEFAULT 0, " +
    MEDIA_RELATIVE_PATH + " TEXT, " +
    DOCUMENT_LCD + " TEXT, " +
    DOCUMENT_LCD_VISIT_TIME + " BIGINT DEFAULT 0)";

// PhotoAlbumColumns table
const std::string PhotoAlbumColumns::TABLE = "PhotoAlbum";
const std::string PhotoAlbumColumns::ALBUM_ID = "album_id";
const std::string PhotoAlbumColumns::ALBUM_TYPE = "album_type";
const std::string PhotoAlbumColumns::ALBUM_SUBTYPE = "album_subtype";
const std::string PhotoAlbumColumns::ALBUM_URI = "album_uri";
const std::string PhotoAlbumColumns::ALBUM_NAME = "album_name";
const std::string PhotoAlbumColumns::ALBUM_COVER_URI = "cover_uri";
const std::string PhotoAlbumColumns::ALBUM_COUNT = "count";
// For api9 compatibility
const std::string PhotoAlbumColumns::ALBUM_RELATIVE_PATH = "relative_path";

const std::string PhotoAlbumColumns::ALBUM_URI_PREFIX = "file://media/album/";

const std::string PhotoAlbumColumns::CREATE_TABLE = "CREATE TABLE IF NOT EXISTS " +
    TABLE + " (" +
    ALBUM_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    ALBUM_TYPE + " INT, " +
    ALBUM_SUBTYPE + " INT, " +
    ALBUM_URI + " TEXT, " +
    ALBUM_NAME + " TEXT, " +
    ALBUM_COVER_URI + " TEXT, " +
    ALBUM_COUNT + " INT DEFAULT 0, " +
    ALBUM_RELATIVE_PATH + " TEXT)";

const std::string PhotoAlbumColumns::TRIGGER_UPDATE_ALBUM_URI =
    "CREATE TRIGGER IF NOT EXISTS photo_album_update_uri AFTER INSERT ON " + TABLE +
    " BEGIN " +
        "UPDATE " + TABLE + " SET " + ALBUM_URI + "='" + ALBUM_URI_PREFIX + "'||" + "LAST_INSERT_ROWID() " +
        "WHERE " + ALBUM_ID + "=" + "LAST_INSERT_ROWID();" +
    " END;";

// PhotoMap table
const std::string PhotoMap::TABLE = "PhotoMap";
const std::string PhotoMap::ALBUM_ID = "map_album";
const std::string PhotoMap::ASSET_ID = "map_asset";

const std::string PhotoMap::CREATE_TABLE = "CREATE TABLE IF NOT EXISTS " + TABLE +
    " (" +
    ALBUM_ID + " INT, " +
    ASSET_ID + " INT, " +
    "PRIMARY KEY (" + ALBUM_ID + "," + ASSET_ID + ")" +
    ")";

const std::string PhotoMap::INDEX_PRIMARY_KEY = "CREATE INDEX map_primary_key ON " + TABLE +
    " (" + ALBUM_ID + "," + ASSET_ID + ");";

const std::string PhotoAlbumColumns::TRIGGER_CLEAR_MAP =
    "CREATE TRIGGER IF NOT EXISTS photo_album_clear_map AFTER DELETE ON " + PhotoAlbumColumns::TABLE +
    " BEGIN " +
        "DELETE FROM " + PhotoMap::TABLE +
        " WHERE " + PhotoMap::ALBUM_ID + "=" + "OLD." + PhotoAlbumColumns::ALBUM_ID + ";" +
    " END;";

}  // namespace Media
}  // namespace OHOS
