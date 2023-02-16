/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_DATA_ABILITY_CONST_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_DATA_ABILITY_CONST_H_

#include "medialibrary_type_const.h"
namespace OHOS {
namespace Media {
#ifdef RDB_UPGRADE_MOCK
const int32_t MEDIA_RDB_VERSION = 2;
#else
const int32_t MEDIA_RDB_VERSION = 1;
#endif
const std::string MEDIA_LIBRARY_VERSION = "1.0";

const int32_t DEVICE_SYNCSTATUSING = 0;
const int32_t DEVICE_SYNCSTATUS_COMPLETE = 1;

const std::string MEDIA_DATA_DEVICE_PATH = "local";
const std::string MEDIALIBRARY_TABLE = "Files";
const std::string SMARTALBUM_TABLE = "SmartAlbum";
const std::string SMARTALBUM_MAP_TABLE = "SmartAlbumMap";
const std::string CATEGORY_SMARTALBUM_MAP_TABLE = "CategorySmartAlbumMap";
const std::string MEDIATYPE_DIRECTORY_TABLE = "MediaTypeDirectory";
const std::string DEVICE_TABLE = "Device";
const std::string BUNDLE_PERMISSION_TABLE = "BundlePermission";
const std::string MEDIA_DATA_ABILITY_DB_NAME = "media_library.db";

const std::string BUNDLE_NAME = "com.ohos.medialibrary.medialibrarydata";

const std::string MEDIALIBRARY_DATA_ABILITY_PREFIX = "datashare://";
const std::string MEDIALIBRARY_DATA_URI_IDENTIFIER = "/media";
const std::string MEDIALIBRARY_MEDIA_PREFIX = MEDIALIBRARY_DATA_ABILITY_PREFIX +
                                                     MEDIALIBRARY_DATA_URI_IDENTIFIER;
const std::string MEDIALIBRARY_TYPE_AUDIO_URI = "/audio";
const std::string MEDIALIBRARY_TYPE_VIDEO_URI = "/video";
const std::string MEDIALIBRARY_TYPE_IMAGE_URI = "/image";
const std::string MEDIALIBRARY_TYPE_FILE_URI  =  "/file";
const std::string MEDIALIBRARY_TYPE_ALBUM_URI  =  "/album";
const std::string MEDIALIBRARY_TYPE_SMARTALBUM_CHANGE_URI  =  "/smartalbum";
const std::string MEDIALIBRARY_TYPE_DEVICE_URI  =  "/device";
const std::string MEDIALIBRARY_TYPE_SMART_URI = "/smart";

const std::string MEDIALIBRARY_DATA_URI = "datashare:///media";
const std::string MEDIALIBRARY_SMARTALBUM_URI = MEDIALIBRARY_DATA_URI + "/" + SMARTALBUM_TABLE;
const std::string MEDIALIBRARY_SMARTALBUM_MAP_URI = MEDIALIBRARY_DATA_URI + "/" + SMARTALBUM_MAP_TABLE;
const std::string MEDIALIBRARY_CATEGORY_SMARTALBUM_MAP_URI = MEDIALIBRARY_DATA_URI + "/"
                                                             + CATEGORY_SMARTALBUM_MAP_TABLE;
const std::string MEDIALIBRARY_DIRECTORY_URI = MEDIALIBRARY_DATA_URI + "/" + MEDIATYPE_DIRECTORY_TABLE;
const std::string MEDIALIBRARY_BUNDLEPERM_URI = MEDIALIBRARY_DATA_URI + "/" + BUNDLE_PERMISSION_TABLE;

const std::string MEDIALIBRARY_AUDIO_URI = MEDIALIBRARY_DATA_URI + '/' + "audio";
const std::string MEDIALIBRARY_VIDEO_URI = MEDIALIBRARY_DATA_URI + '/' + "video";
const std::string MEDIALIBRARY_IMAGE_URI = MEDIALIBRARY_DATA_URI + '/' + "image";
const std::string MEDIALIBRARY_FILE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "file";
const std::string MEDIALIBRARY_ALBUM_URI  =  MEDIALIBRARY_DATA_URI + '/' + "album";
const std::string MEDIALIBRARY_SMARTALBUM_CHANGE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "smartalbum";
const std::string MEDIALIBRARY_DEVICE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "device";
const std::string MEDIALIBRARY_SMART_URI = MEDIALIBRARY_DATA_URI + '/' + "smart";
const std::string MEDIALIBRARY_REMOTEFILE_URI = MEDIALIBRARY_DATA_URI + '/' + "remotfile";

const std::string MEDIA_DATA_DB_ID = "file_id";
const std::string MEDIA_DATA_DB_URI = "uri";
const std::string MEDIA_DATA_DB_FILE_PATH = "data";
const std::string MEDIA_DATA_DB_SIZE = "size";
const std::string MEDIA_DATA_DB_PARENT_ID = "parent";
const std::string MEDIA_DATA_DB_DATE_MODIFIED = "date_modified";
const std::string MEDIA_DATA_DB_DATE_ADDED = "date_added";
const std::string MEDIA_DATA_DB_MIME_TYPE = "mime_type";
const std::string MEDIA_DATA_DB_TITLE = "title";
const std::string MEDIA_DATA_DB_DESCRIPTION = "description";
const std::string MEDIA_DATA_DB_NAME = "display_name";
const std::string MEDIA_DATA_DB_ORIENTATION = "orientation";
const std::string MEDIA_DATA_DB_LATITUDE = "latitude";
const std::string MEDIA_DATA_DB_LONGITUDE = "longitude";
const std::string MEDIA_DATA_DB_DATE_TAKEN = "date_taken";
const std::string MEDIA_DATA_DB_THUMBNAIL = "thumbnail";
const std::string MEDIA_DATA_DB_CONTENT_CREATE_TIME = "content_create_time";

const std::string MEDIA_DATA_DB_LCD = "lcd";
const std::string MEDIA_DATA_DB_TIME_VISIT = "time_visit";
const std::string MEDIA_DATA_DB_BUCKET_ID = "bucket_id";
const std::string MEDIA_DATA_DB_BUCKET_NAME = "bucket_display_name";
const std::string MEDIA_DATA_DB_DURATION = "duration";
const std::string MEDIA_DATA_DB_ARTIST = "artist";

const std::string MEDIA_DATA_DB_AUDIO_ALBUM = "audio_album";
const std::string MEDIA_DATA_DB_MEDIA_TYPE = "media_type";

const std::string MEDIA_DATA_DB_HEIGHT = "height";
const std::string MEDIA_DATA_DB_WIDTH = "width";
const std::string MEDIA_DATA_DB_OWNER_PACKAGE = "owner_package";

const std::string MEDIA_DATA_DB_IS_FAV = "is_favorite";
const std::string MEDIA_DATA_DB_IS_TRASH = "is_trash";
const std::string MEDIA_DATA_DB_RECYCLE_PATH = "recycle_path";
const std::string MEDIA_DATA_DB_DATE_TRASHED = "date_trashed";
const std::string MEDIA_DATA_DB_IS_PENDING = "is_pending";
const std::string MEDIA_DATA_DB_TIME_PENDING = "time_pending";
const std::string MEDIA_DATA_DB_RELATIVE_PATH = "relative_path";
const std::string MEDIA_DATA_DB_VOLUME_NAME = "volume_name";
const std::string MEDIA_DATA_DB_SELF_ID = "self_id";

const std::string MEDIA_DATA_DB_ALBUM = "album";
const std::string MEDIA_DATA_DB_ALBUM_ID = "album_id";
const std::string MEDIA_DATA_DB_ALBUM_NAME = "album_name";
const std::string MEDIA_DATA_DB_COUNT = "count";

// ringtone uri constants
const std::string MEDIA_DATA_DB_RINGTONE_URI = "ringtone_uri";
const std::string MEDIA_DATA_DB_ALARM_URI = "alarm_uri";
const std::string MEDIA_DATA_DB_NOTIFICATION_URI = "notification_uri";
const std::string MEDIA_DATA_DB_RINGTONE_TYPE = "ringtone_type";

const std::string MEDIA_DATA_IMAGE_BITS_PER_SAMPLE = "BitsPerSample";
const std::string MEDIA_DATA_IMAGE_ORIENTATION = "Orientation";
const std::string MEDIA_DATA_IMAGE_IMAGE_LENGTH = "ImageLength";
const std::string MEDIA_DATA_IMAGE_IMAGE_WIDTH = "ImageWidth";
const std::string MEDIA_DATA_IMAGE_GPS_LATITUDE = "GPSLatitude";
const std::string MEDIA_DATA_IMAGE_GPS_LONGITUDE = "GPSLongitude";
const std::string MEDIA_DATA_IMAGE_GPS_LATITUDE_REF = "GPSLatitudeRef";
const std::string MEDIA_DATA_IMAGE_GPS_LONGITUDE_REF = "GPSLongitudeRef";
const std::string MEDIA_DATA_IMAGE_DATE_TIME_ORIGINAL = "DateTimeOriginalForMedia";
const std::string MEDIA_DATA_IMAGE_EXPOSURE_TIME = "ExposureTime";
const std::string MEDIA_DATA_IMAGE_F_NUMBER = "FNumber";
const std::string MEDIA_DATA_IMAGE_ISO_SPEED_RATINGS = "ISOSpeedRatings";
const std::string MEDIA_DATA_IMAGE_SCENE_TYPE = "SceneType";

const std::string PERMISSION_ID = "id";
const std::string PERMISSION_BUNDLE_NAME = "bundle_name";
const std::string PERMISSION_FILE_ID = "file_id";
const std::string PERMISSION_MODE = "mode";

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
                                       MEDIA_DATA_DB_TIME_VISIT + " BIGINT DEFAULT 0, " +
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
                                       MEDIA_DATA_DB_IS_PENDING + " BOOL DEFAULT 0, " +
                                       MEDIA_DATA_DB_TIME_PENDING + " BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_DATE_TRASHED + " BIGINT DEFAULT 0, " +
                                       MEDIA_DATA_DB_RELATIVE_PATH + " TEXT, " +
                                       MEDIA_DATA_DB_VOLUME_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_SELF_ID + " TEXT DEFAULT '1', " +
                                       MEDIA_DATA_DB_ALBUM_NAME + " TEXT, " +
                                       MEDIA_DATA_DB_URI + " TEXT, " +
                                       MEDIA_DATA_DB_ALBUM + " TEXT)";

const std::string CREATE_BUNDLE_PREMISSION_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                      BUNDLE_PERMISSION_TABLE + " (" +
                                      PERMISSION_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                      PERMISSION_BUNDLE_NAME + " TEXT NOT NULL, " +
                                      PERMISSION_FILE_ID + " INT NOT NULL, " +
                                      PERMISSION_MODE + " TEXT NOT NULL)";

const std::string CREATE_IMAGE_VIEW = "CREATE VIEW Image AS SELECT " +
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
                                      "FROM Files WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 3";

const std::string CREATE_VIDEO_VIEW = "CREATE VIEW Video AS SELECT " +
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
                                      "FROM Files WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 4";

const std::string CREATE_AUDIO_VIEW = "CREATE VIEW Audio AS SELECT " +
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
                                      "FROM Files WHERE " +
                                      MEDIA_DATA_DB_MEDIA_TYPE + " = 5";

const std::string REMOTE_THUMBNAIL_TABLE = "RemoteThumbnailMap";
const std::string REMOTE_THUMBNAIL_DB_ID = "id";
const std::string REMOTE_THUMBNAIL_DB_FILE_ID = "file_id";
const std::string REMOTE_THUMBNAIL_DB_UDID = "udid";
const std::string CREATE_REMOTE_THUMBNAIL_TABLE = "CREATE TABLE IF NOT EXISTS " + REMOTE_THUMBNAIL_TABLE + " (" +
                                            REMOTE_THUMBNAIL_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            REMOTE_THUMBNAIL_DB_FILE_ID + " INT, " +
                                            REMOTE_THUMBNAIL_DB_UDID + " TEXT, " +
                                            MEDIA_DATA_DB_THUMBNAIL + " TEXT, " +
                                            MEDIA_DATA_DB_LCD + " TEXT, " +
                                            MEDIA_DATA_DB_TIME_VISIT + " BIGINT DEFAULT 0) ";
const std::string FILE_TABLE = "file";
const std::string ABLUM_TABLE = "album";
const std::string ABLUM_VIEW_NAME = "Album";
const std::string DISTRIBUTED_ABLUM_COLUMNS = "SELECT count( " + FILE_TABLE + "." +
                                              MEDIA_DATA_DB_DATE_TRASHED + " = 0 OR NULL) AS " +
                                              MEDIA_DATA_DB_COUNT + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_RELATIVE_PATH + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_ID + " AS " +
                                              MEDIA_DATA_DB_BUCKET_ID + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_FILE_PATH + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_TITLE + " AS " +
                                              MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_TITLE + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_DESCRIPTION + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_DATE_ADDED + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_DATE_MODIFIED + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_THUMBNAIL + ", " +
                                              FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_SELF_ID + ", " +
                                              ABLUM_TABLE + "." + MEDIA_DATA_DB_IS_TRASH;
const std::string DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY = " WHERE " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID + " = " +
                                                        ABLUM_TABLE + "." + MEDIA_DATA_DB_ID + " AND " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
                                                        std::to_string(MEDIA_TYPE_ALBUM) + " AND " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
                                                        std::to_string(MEDIA_TYPE_FILE) +
                                                        " GROUP BY " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID +", " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_NAME + ", " +
                                                        FILE_TABLE + "." + MEDIA_DATA_DB_MEDIA_TYPE + ", " +
                                                        ABLUM_TABLE + "." + MEDIA_DATA_DB_SELF_ID;
const std::string CREATE_ABLUM_VIEW = "CREATE VIEW " + ABLUM_VIEW_NAME +
                                      " AS " + DISTRIBUTED_ABLUM_COLUMNS +
                                      " FROM Files " + FILE_TABLE + ", " +
                                      " Files " + ABLUM_TABLE +
                                      DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY;
const std::string SMARTALBUM_DB_ID = "album_id";
const std::string SMARTALBUM_DB_ALBUM_TYPE = "album_type";
const std::string SMARTALBUM_DB_NAME = "album_name";
const std::string SMARTALBUM_DB_DESCRIPTION = "description";
const std::string SMARTALBUM_DB_CAPACITY = "capacity";
const std::string SMARTALBUM_DB_LATITUDE = "latitude";
const std::string SMARTALBUM_DB_LONGITUDE = "longitude";
const std::string SMARTALBUM_DB_COVER_URI = "cover_uri";
const std::string SMARTALBUM_DB_EXPIRED_TIME = "expired_id";
const std::string SMARTALBUM_DB_SELF_ID = "self_id";
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

const std::string SMARTALBUMMAP_DB_ID = "map_id";
const std::string SMARTALBUMMAP_DB_ALBUM_ID = "album_id";
const std::string SMARTALBUMMAP_DB_CHILD_ALBUM_ID = "child_album_id";
const std::string SMARTALBUMMAP_DB_CHILD_ASSET_ID = "child_asset_id";
const std::string SMARTALBUMMAP_DB_SELF_ID = "self_id";
const std::string CREATE_SMARTALBUMMAP_TABLE = "CREATE TABLE IF NOT EXISTS " + SMARTALBUM_MAP_TABLE + " (" +
                                            SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            SMARTALBUMMAP_DB_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_CHILD_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_CHILD_ASSET_ID + " INT, " +
                                            SMARTALBUMMAP_DB_SELF_ID + " TEXT) ";
const std::string CATEGORY_SMARTALBUMMAP_DB_ID = "category_map_id";
const std::string CATEGORY_SMARTALBUMMAP_DB_CATEGORY_ID = "category_id";
const std::string CATEGORY_SMARTALBUMMAP_DB_CATEGORY_NAME = "category_name";
const std::string CATEGORY_SMARTALBUMMAP_DB_ALBUM_ID = "album_id";
const std::string CATEGORY_SMARTALBUMMAP_DB_SELF_ID = "self_id";
const std::string CREATE_CATEGORY_SMARTALBUMMAP_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                            CATEGORY_SMARTALBUM_MAP_TABLE + " (" +
                                            CATEGORY_SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_CATEGORY_ID + " INT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_CATEGORY_NAME + " TEXT, " +
                                            CATEGORY_SMARTALBUMMAP_DB_ALBUM_ID + " INT, " +
                                            SMARTALBUMMAP_DB_SELF_ID + " TEXT) ";
const std::string CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE = "directory_type";
const std::string CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE = "media_type";
const std::string CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY = "directory";
const std::string CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION = "extension";
const std::string CREATE_MEDIATYPE_DIRECTORY_TABLE = "CREATE TABLE IF NOT EXISTS " +
                                            MEDIATYPE_DIRECTORY_TABLE + " (" +
                                            CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE + " INTEGER PRIMARY KEY, " +
                                            CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE + " TEXT, " +
                                            CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY + " TEXT, " +
                                            CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION + " TEXT) ";

const std::string DEVICE_DB_ID = "id";
const std::string DEVICE_DB_UDID = "device_udid";
const std::string DEVICE_DB_NETWORK_ID = "network_id";
const std::string DEVICE_DB_NAME = "device_name";
const std::string DEVICE_DB_IP = "device_ip";
const std::string DEVICE_DB_SYNC_STATUS = "sync_status";
const std::string DEVICE_DB_SELF_ID = "self_id";
const std::string DEVICE_DB_TYPE = "device_type";
const std::string DEVICE_DB_PREPATH = "pre_path";
const std::string DEVICE_DB_DATE_ADDED = "date_added";
const std::string DEVICE_DB_DATE_MODIFIED = "date_modified";
const std::string CREATE_DEVICE_TABLE = "CREATE TABLE IF NOT EXISTS " + DEVICE_TABLE + " (" +
                                            DEVICE_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                            DEVICE_DB_UDID + " TEXT, " +
                                            DEVICE_DB_NETWORK_ID + " TEXT, " +
                                            DEVICE_DB_NAME + " TEXT, " +
                                            DEVICE_DB_IP + " TEXT DEFAULT '', " +
                                            DEVICE_DB_SYNC_STATUS + " INT DEFAULT 0, " +
                                            DEVICE_DB_SELF_ID + " TEXT, " +
                                            DEVICE_DB_TYPE + " INT, " +
                                            DEVICE_DB_PREPATH + " TEXT, " +
                                            DEVICE_DB_DATE_ADDED + " BIGINT DEFAULT 0, " +
                                            DEVICE_DB_DATE_MODIFIED + " BIGINT DEFAULT 0) ";
const std::string SMARTALBUM_TABLE_NAME = "smartalbum";
const std::string SMARTALBUMMAP_TABLE_NAME = "smartAlbumMap";
const std::string CATEGORY_SMARTALBUMMAP_TABLE_NAME = "categorySmartAlbumMap";
const std::string SMARTABLUMASSETS_VIEW_NAME = "SmartAlbumAssets";
const std::string SMARTABLUMASSETS_ALBUMCAPACITY = "albumCapacity";
const std::string CREATE_SMARTABLUMASSETS_VIEW = "CREATE VIEW " + SMARTABLUMASSETS_VIEW_NAME +
                        " AS SELECT COUNT(" +
                        MEDIALIBRARY_TABLE + "."+ MEDIA_DATA_DB_DATE_TRASHED + " = 0 OR (" +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + " = " +
                        std::to_string(TRASH_ALBUM_ID_VALUES) + " AND " +
                        MEDIALIBRARY_TABLE + "."+ MEDIA_DATA_DB_IS_TRASH + "<> 0)" +
                        " OR NULL ) AS " + SMARTABLUMASSETS_ALBUMCAPACITY + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_NAME + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_SELF_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ALBUM_TYPE + ", " +
                        SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ID +
                        " FROM " + SMARTALBUM_TABLE +" "+SMARTALBUM_TABLE_NAME +
                        " LEFT JOIN " + SMARTALBUM_MAP_TABLE +
                        " ON " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ALBUM_ID + " = " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID +
                        " LEFT JOIN " + MEDIALIBRARY_TABLE +
                        " ON " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_CHILD_ASSET_ID + " = " +
                        MEDIALIBRARY_TABLE + "." + MEDIA_DATA_DB_ID +
                        " GROUP BY IFNULL( " + SMARTALBUM_MAP_TABLE + "." + SMARTALBUMMAP_DB_ALBUM_ID + ", " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_ID + " ), " +
                        SMARTALBUM_TABLE_NAME + "." + SMARTALBUM_DB_SELF_ID;
const std::string ASSETMAP_VIEW_NAME = "AssetMap";
const std::string CREATE_ASSETMAP_VIEW = "CREATE VIEW " + ASSETMAP_VIEW_NAME +
                        " AS SELECT * FROM " +
                        MEDIALIBRARY_TABLE + " a " + ", " +
                        SMARTALBUM_MAP_TABLE + " b " +
                        " WHERE " +
                        "a." + MEDIA_DATA_DB_ID + " = " +
                        "b." + SMARTALBUMMAP_DB_CHILD_ASSET_ID;

const std::string QUERY_MEDIA_VOLUME = "SELECT sum(" + MEDIA_DATA_DB_SIZE + ") AS " +
                        MEDIA_DATA_DB_SIZE + "," +
                        MEDIA_DATA_DB_MEDIA_TYPE + " FROM " +
                        MEDIALIBRARY_TABLE + " WHERE " +
                        MEDIA_DATA_DB_MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_FILE) + " OR " +
                        MEDIA_DATA_DB_MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_IMAGE) + " OR " +
                        MEDIA_DATA_DB_MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_VIDEO) + " OR " +
                        MEDIA_DATA_DB_MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_AUDIO) + " AND " +
                        MEDIA_DATA_DB_DATE_TRASHED + " = 0" +
                        " GROUP BY " + MEDIA_DATA_DB_MEDIA_TYPE;

// File operations constants
const std::string MEDIA_OPERN_KEYWORD = "operation";
const std::string MEDIA_FILEOPRN = "file_operation";
const std::string MEDIA_ALBUMOPRN = "album_operation";
const std::string MEDIA_DIROPRN = "dir_operation";
const std::string MEDIA_QUERYOPRN = "query_operation";
const std::string MEDIA_SMARTALBUMOPRN = "albumsmart_operation";
const std::string MEDIA_SMARTALBUMMAPOPRN = "smartalbummap_operation";
const std::string MEDIA_FILEOPRN_CREATEASSET = "create_asset";
const std::string MEDIA_FILEOPRN_MODIFYASSET = "modify_asset";
const std::string MEDIA_FILEOPRN_DELETEASSET = "delete_asset";
const std::string MEDIA_FILEOPRN_TRASHASSET = "trash_asset";
const std::string MEDIA_FILEOPRN_GETALBUMCAPACITY = "get_album_capacity";
const std::string MEDIA_FILEOPRN_OPENASSET = "open_asset";
const std::string MEDIA_FILEOPRN_CLOSEASSET = "close_asset";
const std::string MEDIA_FILEOPRN_ISDIRECTORY = "isdirectory_asset";

// BoardCast operation
const std::string MEDIA_BOARDCASTOPRN = "boardcast";
const std::string MEDIA_SCAN_OPERATION = "boardcast_scan";

const std::string THU_OPRN_GENERATES = "thumbnail_generate_operation";
const std::string THU_OPRN_AGING = "thumbnail_aging_operation";
const std::string DISTRIBUTE_THU_OPRN_GENERATES = "thumbnail_distribute_generate_operation";
const std::string DISTRIBUTE_THU_OPRN_AGING = "thumbnail_distribute_aging_operation";
const std::string DISTRIBUTE_THU_OPRN_CREATE = "thumbnail_distribute_create_operation";
const std::string BUNDLE_PERMISSION_INSERT = "bundle_permission_insert_operation";

const std::string MEDIA_ALBUMOPRN_CREATEALBUM = "create_album";
const std::string MEDIA_ALBUMOPRN_MODIFYALBUM = "modify_album";
const std::string MEDIA_ALBUMOPRN_DELETEALBUM = "delete_album";
const std::string MEDIA_ALBUMOPRN_QUERYALBUM = "query_album";
const std::string MEDIA_SMARTALBUMOPRN_CREATEALBUM = "create_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_MODIFYALBUM = "modify_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_DELETEALBUM = "delete_smartalbum";
const std::string MEDIA_DIROPRN_DELETEDIR = "delete_dir";
const std::string MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION = "check_dir_and_extension";
const std::string MEDIA_DIROPRN_FMS_CREATEDIR = "fms_create_dir";
const std::string MEDIA_DIROPRN_FMS_DELETEDIR = "fms_delete_dir";
const std::string MEDIA_DIROPRN_FMS_TRASHDIR = "fms_trash_dir";
const std::string MEDIA_QUERYOPRN_QUERYVOLUME = "query_media_volume";
const std::string MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM = "add_smartalbum_map";
const std::string MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM = "remove_smartalbum_map";
const std::string MEDIA_SMARTALBUMMAPOPRN_AGEINGSMARTALBUM = "ageing_smartalbum_map";
const std::string MEDIA_FILEMODE = "mode";

const std::string MEDIA_DEVICE_QUERYALLDEVICE = "query_all_device";
const std::string MEDIA_DEVICE_QUERYACTIVEDEVICE = "query_active_device";
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_DATA_ABILITY_CONST_H_
