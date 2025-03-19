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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIALIBRARY_DB_CONST_SQLS_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIALIBRARY_DB_CONST_SQLS_H

#include "location_db_sqls.h"
#include "media_category_smart_album_map_column.h"
#include "media_device_column.h"
#include "media_directory_type_column.h"
#include "media_error_column.h"
#include "media_refresh_album_column.h"
#include "media_remote_thumbnail_column.h"
#include "media_smart_album_column.h"
#include "media_smart_map_column.h"
#include "media_unique_number_column.h"
#include "medialibrary_db_const.h"
#include "vision_db_sqls_more.h"
#include "smart_album_column.h"

namespace OHOS {
namespace Media {

const std::string FILE_TABLE = "file";

const std::string CREATE_MEDIA_TABLE = "CREATE TABLE IF NOT EXISTS " + MEDIALIBRARY_TABLE + " (" +
                                       MEDIA_DATA_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                       MEDIA_DATA_DB_FILE_PATH + " TEXT, " +
                                       MEDIA_DATA_DB_SIZE + " BIGINT, " +
                                       MEDIA_DATA_DB_PARENT_ID + " INT DEFAULT 0, " +
                                       MEDIA_DATA_DB_DATE_ADDED + " BIGINT, " +
                                       MEDIA_DATA_DB_DATE_MODIFIED + " BIGINT, " +
                                       MEDIA_DATA_DB_MIME_TYPE + " TEXT, " +
                                       MEDIA_DATA_DB_TITLE + " TEXT, " +
                                       MEDIA_DATA_DB_DESCRIPTION + " TEXT, " +
                                       MEDIA_DATA_DB_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_ORIENTATION + " INT DEFAULT 0, " +
                                       MEDIA_DATA_DB_LATITUDE + " DOUBLE DEFAULT 0, " +
                                       MEDIA_DATA_DB_LONGITUDE + " DOUBLE DEFAULT 0, " +
                                       MEDIA_DATA_DB_DATE_TAKEN + " BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_THUMBNAIL + " TEXT, " +
                                       MEDIA_DATA_DB_LCD + " TEXT, " +
                                       MEDIA_DATA_DB_BUCKET_ID + " INT DEFAULT 0, " +
                                       MEDIA_DATA_DB_BUCKET_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_DURATION + " INT, " +
                                       MEDIA_DATA_DB_ARTIST + " TEXT, " +
                                       MEDIA_DATA_DB_AUDIO_ALBUM + " TEXT, " +
                                       MEDIA_DATA_DB_MEDIA_TYPE + " INT, " +
                                       MEDIA_DATA_DB_HEIGHT + " INT, " +
                                       MEDIA_DATA_DB_WIDTH + " INT, " +
                                       MEDIA_DATA_DB_IS_TRASH + " INT DEFAULT 0, " +
                                       MEDIA_DATA_DB_RECYCLE_PATH + " TEXT, " +
                                       MEDIA_DATA_DB_IS_FAV + " BOOL DEFAULT 0, " +
                                       MEDIA_DATA_DB_OWNER_PACKAGE + " TEXT, " +
                                       MEDIA_DATA_DB_OWNER_APPID + " TEXT, " +
                                       MEDIA_DATA_DB_PACKAGE_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_DEVICE_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_IS_PENDING + " BOOL DEFAULT 0, " +
                                       MEDIA_DATA_DB_TIME_PENDING + " BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_DATE_TRASHED + " BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_RELATIVE_PATH + " TEXT, " +
                                       MEDIA_DATA_DB_VOLUME_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_SELF_ID + " TEXT DEFAULT '1', " +
                                       MEDIA_DATA_DB_ALBUM_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_URI + " TEXT, " +
                                       MEDIA_DATA_DB_ALBUM + " TEXT, " +
                                       MEDIA_DATA_DB_CLOUD_ID + " TEXT, " +
                                       MEDIA_DATA_DB_DIRTY + " INT DEFAULT 1, " +
                                       MEDIA_DATA_DB_POSITION + " INT DEFAULT 1, " +
                                       MEDIA_DATA_DB_META_DATE_MODIFIED + "  BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_SYNC_STATUS + " INT DEFAULT 0)";

const std::string CREATE_BUNDLE_PREMISSION_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                      BUNDLE_PERMISSION_TABLE + " (" +
                                      PERMISSION_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                      PERMISSION_BUNDLE_NAME + " TEXT NOT NULL, " +
                                      PERMISSION_FILE_ID + " INT NOT NULL, " +
                                      PERMISSION_MODE + " TEXT NOT NULL, " +
                                      PERMISSION_TABLE_TYPE + " INT )";

const std::string CREATE_IMAGE_VIEW = "CREATE VIEW IF NOT EXISTS Image AS SELECT " +
                                      MEDIA_DATA_DB_ID + ", " +
                                      MEDIA_DATA_DB_FILE_PATH + ", " +
                                      MEDIA_DATA_DB_SIZE + ", " +
                                      MEDIA_DATA_DB_NAME + ", " +
                                      MEDIA_DATA_DB_TITLE + ", " +
                                      MEDIA_DATA_DB_DESCRIPTION + ", " +
                                      MEDIA_DATA_DB_DATE_ADDED + ", " +
                                      MEDIA_DATA_DB_DATE_MODIFIED + ", " +
                                      MEDIA_DATA_DB_DATE_TAKEN + ", " +
                                      MEDIA_DATA_DB_MIME_TYPE + ", " +
                                      MEDIA_DATA_DB_LATITUDE + ", " +
                                      MEDIA_DATA_DB_LONGITUDE + ", " +
                                      MEDIA_DATA_DB_ORIENTATION + ", " +
                                      MEDIA_DATA_DB_WIDTH + ", " +
                                      MEDIA_DATA_DB_HEIGHT + ", " +
                                      MEDIA_DATA_DB_BUCKET_ID + ", " +
                                      MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                      MEDIA_DATA_DB_THUMBNAIL + ", " +
                                      MEDIA_DATA_DB_LCD + ", " +
                                      MEDIA_DATA_DB_SELF_ID + " " +
                                      "FROM " + MEDIALIBRARY_TABLE + " WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 3";

const std::string CREATE_VIDEO_VIEW = "CREATE VIEW IF NOT EXISTS Video AS SELECT " +
                                      MEDIA_DATA_DB_ID + ", " +
                                      MEDIA_DATA_DB_FILE_PATH + ", " +
                                      MEDIA_DATA_DB_SIZE + ", " +
                                      MEDIA_DATA_DB_NAME + ", " +
                                      MEDIA_DATA_DB_TITLE + ", " +
                                      MEDIA_DATA_DB_DESCRIPTION + ", " +
                                      MEDIA_DATA_DB_DATE_ADDED + ", " +
                                      MEDIA_DATA_DB_DATE_MODIFIED + ", " +
                                      MEDIA_DATA_DB_MIME_TYPE + ", " +
                                      MEDIA_DATA_DB_ORIENTATION + ", " +
                                      MEDIA_DATA_DB_WIDTH + ", " +
                                      MEDIA_DATA_DB_HEIGHT + ", " +
                                      MEDIA_DATA_DB_DURATION + ", " +
                                      MEDIA_DATA_DB_BUCKET_ID + ", " +
                                      MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                      MEDIA_DATA_DB_THUMBNAIL + ", " +
                                      MEDIA_DATA_DB_SELF_ID + " " +
                                      "FROM " + MEDIALIBRARY_TABLE + " WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 4";

const std::string CREATE_AUDIO_VIEW = "CREATE VIEW IF NOT EXISTS Audio AS SELECT " +
                                      MEDIA_DATA_DB_ID + ", " +
                                      MEDIA_DATA_DB_FILE_PATH + ", " +
                                      MEDIA_DATA_DB_SIZE + ", " +
                                      MEDIA_DATA_DB_NAME + ", " +
                                      MEDIA_DATA_DB_TITLE + ", " +
                                      MEDIA_DATA_DB_DESCRIPTION + ", " +
                                      MEDIA_DATA_DB_DATE_ADDED + ", " +
                                      MEDIA_DATA_DB_DATE_MODIFIED + ", " +
                                      MEDIA_DATA_DB_MIME_TYPE + ", " +
                                      MEDIA_DATA_DB_ARTIST + ", " +
                                      MEDIA_DATA_DB_DURATION + ", " +
                                      MEDIA_DATA_DB_BUCKET_ID + ", " +
                                      MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                      MEDIA_DATA_DB_THUMBNAIL + ", " +
                                      MEDIA_DATA_DB_SELF_ID + " " +
                                      "FROM " + MEDIALIBRARY_TABLE + " WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 5";

const std::string CREATE_REMOTE_THUMBNAIL_TABLE = "CREATE TABLE IF NOT EXISTS " + REMOTE_THUMBNAIL_TABLE + " (" +
                                            REMOTE_THUMBNAIL_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            REMOTE_THUMBNAIL_DB_FILE_ID + " INT, " +
                                            REMOTE_THUMBNAIL_DB_UDID + " TEXT, " +
                                            MEDIA_DATA_DB_THUMBNAIL + " TEXT, " +
                                            MEDIA_DATA_DB_LCD + " TEXT) ";

const std::string DISTRIBUTED_ALBUM_COLUMNS = "SELECT count( " + FILE_TABLE + "." +
                                              MEDIA_DATA_DB_DATE_TRASHED + " = 0 OR NULL) AS " +
                                              MEDIA_DATA_DB_COUNT + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_RELATIVE_PATH + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_ID + " AS " +
                                              MEDIA_DATA_DB_BUCKET_ID + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_FILE_PATH + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_TITLE + " AS " +
                                              MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_TITLE + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_DESCRIPTION + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_DATE_ADDED + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_DATE_MODIFIED + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_THUMBNAIL + ", " +
                                              FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_SELF_ID + ", " +
                                              ALBUM_TABLE + "." + MEDIA_DATA_DB_IS_TRASH;

const std::string DISTRIBUTED_ALBUM_WHERE_AND_GROUPBY = " WHERE " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID + " = " +
                                                        ALBUM_TABLE + "." + MEDIA_DATA_DB_ID + " AND " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
                                                        std::to_string(MEDIA_TYPE_ALBUM) + " AND " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
                                                        std::to_string(MEDIA_TYPE_FILE) +
                                                        " GROUP BY " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID +", " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + ", " +
                                                        ALBUM_TABLE + "." + MEDIA_DATA_DB_SELF_ID;

const std::string CREATE_ALBUM_VIEW = "CREATE VIEW IF NOT EXISTS " + ALBUM_VIEW_NAME +
                                      " AS " + DISTRIBUTED_ALBUM_COLUMNS +
                                      " FROM " + MEDIALIBRARY_TABLE + " " + FILE_TABLE + ", " +
                                      MEDIALIBRARY_TABLE + " " + ALBUM_TABLE +
                                      DISTRIBUTED_ALBUM_WHERE_AND_GROUPBY;

const std::string CREATE_SMARTALBUM_TABLE = "CREATE TABLE IF NOT EXISTS " + SMARTALBUM_TABLE + " (" +
                                            SMARTALBUM_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            SMARTALBUM_DB_NAME + " TEXT, " +
                                            SMARTALBUM_DB_DESCRIPTION + " TEXT, " +
                                            SMARTALBUM_DB_ALBUM_TYPE + " INT, " +
                                            SMARTALBUM_DB_CAPACITY + " INT, " +
                                            SMARTALBUM_DB_LATITUDE + " DOUBLE DEFAULT 0, " +
                                            SMARTALBUM_DB_LONGITUDE + " DOUBLE DEFAULT 0, " +
                                            SMARTALBUM_DB_COVER_URI + " TEXT, " +
                                            SMARTALBUM_DB_EXPIRED_TIME + " INT DEFAULT 30, " +
                                            SMARTALBUM_DB_SELF_ID + " TEXT) ";

const std::string CREATE_SMARTALBUMMAP_TABLE = "CREATE TABLE IF NOT EXISTS " + SMARTALBUM_MAP_TABLE + " (" +
                                            SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            SMARTALBUMMAP_DB_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_CHILD_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_CHILD_ASSET_ID + " INT, " +
                                            SMARTALBUMMAP_DB_SELF_ID + " TEXT) ";

const std::string CREATE_CATEGORY_SMARTALBUMMAP_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                            CATEGORY_SMARTALBUM_MAP_TABLE + " (" +
                                            CATEGORY_SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_CATEGORY_ID + " INT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_CATEGORY_NAME + " TEXT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_SELF_ID + " TEXT) ";

const std::string CREATE_MEDIATYPE_DIRECTORY_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                            MEDIATYPE_DIRECTORY_TABLE + " (" +
                                            DIRECTORY_DB_DIRECTORY_TYPE + " INTEGER PRIMARY KEY, " +
                                            DIRECTORY_DB_MEDIA_TYPE + " TEXT, " +
                                            DIRECTORY_DB_DIRECTORY + " TEXT, " +
                                            DIRECTORY_DB_EXTENSION + " TEXT) ";

const std::string CREATE_DEVICE_TABLE = "CREATE TABLE IF NOT EXISTS " + DEVICE_TABLE + " (" +
                                            DEVICE_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            DEVICE_DB_UDID + " TEXT, " +
                                            DEVICE_DB_NETWORK_ID + " TEXT, " +
                                            DEVICE_DB_NAME + " TEXT, " +
                                            DEVICE_DB_IP + " TEXT DEFAULT '', " +
                                            DEVICE_DB_SYNC_STATUS + " INT DEFAULT 0, " +
                                            DEVICE_DB_PHOTO_SYNC_STATUS + " INT DEFAULT 0, " +
                                            DEVICE_DB_SELF_ID + " TEXT, " +
                                            DEVICE_DB_TYPE + " INT, " +
                                            DEVICE_DB_PREPATH + " TEXT, " +
                                            DEVICE_DB_DATE_ADDED + " BIGINT DEFAULT 0, " +
                                            DEVICE_DB_DATE_MODIFIED + " BIGINT DEFAULT 0) ";

const std::string CREATE_SMARTALBUMASSETS_VIEW = "CREATE VIEW IF NOT EXISTS " + SMARTALBUMASSETS_VIEW_NAME +
                        " AS SELECT COUNT(" +
                        MEDIALIBRARY_TABLE + "."+ MEDIA_DATA_DB_DATE_TRASHED + " = 0 OR (" +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + " = " +
                        std::to_string(TRASH_ALBUM_ID_VALUES) + " AND " +
                        MEDIALIBRARY_TABLE + "."+ MEDIA_DATA_DB_IS_TRASH + "<> 0)" +
                        " OR NULL ) AS " + SMARTALBUMASSETS_ALBUMCAPACITY + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_NAME + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_SELF_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_DESCRIPTION + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_EXPIRED_TIME + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_COVER_URI + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ALBUM_TYPE + ", " +
                        SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ID + ", " +
                        "a." + SMARTALBUMMAP_DB_ALBUM_ID + " AS " + SMARTABLUMASSETS_PARENTID +
                        " FROM " + SMARTALBUM_TABLE + " " + SMARTALBUM_TABLE_NAME +
                        " LEFT JOIN " + SMARTALBUM_MAP_TABLE +
                        " ON " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ALBUM_ID + " = " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID +
                        " LEFT JOIN " + MEDIALIBRARY_TABLE +
                        " ON " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_CHILD_ASSET_ID + " = " +
                        MEDIALIBRARY_TABLE + "." + MEDIA_DATA_DB_ID +
                        " LEFT JOIN " + SMARTALBUM_MAP_TABLE + " a " +
                        " ON a." + SMARTALBUMMAP_DB_CHILD_ALBUM_ID + " = " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID +
                        " GROUP BY IFNULL( " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ALBUM_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + " ), " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_SELF_ID;

const std::string CREATE_ASSETMAP_VIEW = "CREATE VIEW IF NOT EXISTS " + ASSETMAP_VIEW_NAME +
                        " AS SELECT * FROM " +
                        MEDIALIBRARY_TABLE + " a " + ", " +
                        SMARTALBUM_MAP_TABLE + " b " +
                        " WHERE " +
                        "a." + MEDIA_DATA_DB_ID + " = " +
                        "b." + SMARTALBUMMAP_DB_CHILD_ASSET_ID;

const std::string CREATE_FILES_DELETE_TRIGGER = "CREATE TRIGGER IF NOT EXISTS delete_trigger AFTER UPDATE ON " +
                        MEDIALIBRARY_TABLE + " FOR EACH ROW WHEN new.dirty = " +
                        std::to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)) +
                        " and OLD.position = 1 AND is_caller_self_func() = 'true'" +
                        " BEGIN " +
                        " DELETE FROM " + MEDIALIBRARY_TABLE + " WHERE file_id = old.file_id;" +
                        " END;";

const std::string CREATE_FILES_FDIRTY_TRIGGER = "CREATE TRIGGER IF NOT EXISTS fdirty_trigger AFTER UPDATE ON " +
                        MEDIALIBRARY_TABLE + " FOR EACH ROW WHEN OLD.position <> 1 AND" +
                        " new.date_modified <> old.date_modified AND is_caller_self_func() = 'true'" +
                        " BEGIN " +
                        " UPDATE " + MEDIALIBRARY_TABLE + " SET dirty = " +
                        std::to_string(static_cast<int32_t>(DirtyType::TYPE_FDIRTY)) +
                        " WHERE file_id = old.file_id;" +
                        " SELECT cloud_sync_func(); " +
                        " END;";

const std::string CREATE_FILES_MDIRTY_TRIGGER = "CREATE TRIGGER IF NOT EXISTS mdirty_trigger AFTER UPDATE ON " +
                        MEDIALIBRARY_TABLE + " FOR EACH ROW WHEN OLD.position <> 1" +
                        " AND new.date_modified = old.date_modified AND old.dirty = " +
                        std::to_string(static_cast<int32_t>(DirtyType::TYPE_SYNCED)) +
                        " AND new.dirty = old.dirty AND is_caller_self_func() = 'true'" +
                        " BEGIN " +
                        " UPDATE " + MEDIALIBRARY_TABLE + " SET dirty = " +
                        std::to_string(static_cast<int32_t>(DirtyType::TYPE_MDIRTY)) +
                        " WHERE file_id = old.file_id;" +
                        " SELECT cloud_sync_func(); " +
                        " END;";

const std::string CREATE_INSERT_CLOUD_SYNC_TRIGGER =
                        " CREATE TRIGGER IF NOT EXISTS insert_cloud_sync_trigger AFTER INSERT ON " +
                        MEDIALIBRARY_TABLE +
                        " BEGIN SELECT cloud_sync_func(); END;";

const std::string CREATE_MEDIALIBRARY_ERROR_TABLE = "CREATE TABLE IF NOT EXISTS " + MEDIALIBRARY_ERROR_TABLE + " ("
    + MEDIA_DATA_ERROR + " TEXT PRIMARY KEY)";

const std::string CREATE_ASSET_UNIQUE_NUMBER_TABLE = "CREATE TABLE IF NOT EXISTS " + ASSET_UNIQUE_NUMBER_TABLE + " (" +
    ASSET_MEDIA_TYPE + " TEXT, " + UNIQUE_NUMBER + " INT DEFAULT 0) ";

const std::string CREATE_ALBUM_REFRESH_TABLE = "CREATE TABLE IF NOT EXISTS " + ALBUM_REFRESH_TABLE + " ("
    + REFRESH_ALBUM_ID + " INT PRIMARY KEY)";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIALIBRARY_DB_CONST_SQLS_H