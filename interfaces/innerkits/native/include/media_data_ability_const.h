/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_DATA_ABILITY_CONST_H
#define MEDIA_DATA_ABILITY_CONST_H

namespace OHOS {
namespace Media {
const int32_t DATA_ABILITY_SUCCESS = 0;
const int32_t DATA_ABILITY_FAIL = -1;
const int32_t ALBUM_OPERATION_ERR = -1;
const int32_t FILE_OPERATION_ERR = -1;
const int32_t MEDIA_RDB_VERSION = 1;
const int32_t MEDIA_SMARTALBUM_RDB_VERSION = 1;
const int32_t MEDIA_SMARTALBUMMAP_RDB_VERSION = 1;

const std::string MEDIA_DATA_DB_Path = "/data/media/";

const std::string MEDIALIBRARY_TABLE = "Files";
const std::string SMARTALBUM_TABLE = "SmartAlbum";
const std::string SMARTALBUM_MAP_TABLE = "SmartAlbumMap";
const std::string DEVICE_TABLE = "Device";

const std::string MEDIA_DATA_ABILITY_DB_NAME = MEDIA_DATA_DB_Path + "media_library.db";

const std::string MEDIALIBRARY_DATA_URI = "dataability:///com.ohos.medialibrary.MediaLibraryDataAbility";
const std::string MEDIALIBRARY_SMARTALBUM_URI = MEDIALIBRARY_DATA_URI + "." + SMARTALBUM_TABLE;
const std::string MEDIALIBRARY_SMARTALBUM_MAP_URI = MEDIALIBRARY_DATA_URI + "." + SMARTALBUM_MAP_TABLE;

const std::string MEDIALIBRARY_AUDIO_URI = MEDIALIBRARY_DATA_URI + '/' + "audio";
const std::string MEDIALIBRARY_VIDEO_URI = MEDIALIBRARY_DATA_URI + '/' + "video";
const std::string MEDIALIBRARY_IMAGE_URI = MEDIALIBRARY_DATA_URI + '/' + "image";
const std::string MEDIALIBRARY_FILE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "file";
const std::string MEDIALIBRARY_ALBUM_URI  =  MEDIALIBRARY_DATA_URI + '/' + "album";
const std::string MEDIALIBRARY_SMARTALBUM_CHANGE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "smartalbum";
const std::string MEDIALIBRARY_DEVICE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "device";

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

const std::string MEDIA_DATA_DB_LCD = "lcd";
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

const std::string CREATE_MEDIA_TABLE = "CREATE TABLE IF NOT EXISTS " + MEDIALIBRARY_TABLE + " ("
                                       + MEDIA_DATA_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                                       + MEDIA_DATA_DB_FILE_PATH + " TEXT, "
                                       + MEDIA_DATA_DB_SIZE + " BIGINT, "
                                       + MEDIA_DATA_DB_PARENT_ID + " INT DEFAULT 0, "
                                       + MEDIA_DATA_DB_DATE_ADDED + " BIGINT, "
                                       + MEDIA_DATA_DB_DATE_MODIFIED + " BIGINT, "
                                       + MEDIA_DATA_DB_MIME_TYPE + " TEXT, "
                                       + MEDIA_DATA_DB_TITLE + " TEXT, "
                                       + MEDIA_DATA_DB_DESCRIPTION + " TEXT, "
                                       + MEDIA_DATA_DB_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_ORIENTATION + " INT, "
                                       + MEDIA_DATA_DB_LATITUDE + " DOUBLE DEFAULT 0, "
                                       + MEDIA_DATA_DB_LONGITUDE + " DOUBLE DEFAULT 0, "
                                       + MEDIA_DATA_DB_DATE_TAKEN + " BIGINT DEFAULT 0, "
                                       + MEDIA_DATA_DB_THUMBNAIL + " TEXT, "
                                       + MEDIA_DATA_DB_LCD + " TEXT, "
                                       + MEDIA_DATA_DB_BUCKET_ID + " INT DEFAULT 0, "
                                       + MEDIA_DATA_DB_BUCKET_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_DURATION + " INT, "
                                       + MEDIA_DATA_DB_ARTIST + " TEXT, "
                                       + MEDIA_DATA_DB_AUDIO_ALBUM + " TEXT, "
                                       + MEDIA_DATA_DB_MEDIA_TYPE + " INT, "
                                       + MEDIA_DATA_DB_HEIGHT + " INT, "
                                       + MEDIA_DATA_DB_WIDTH + " INT, "
                                       + MEDIA_DATA_DB_IS_FAV + " BOOL DEFAULT 0, "
                                       + MEDIA_DATA_DB_OWNER_PACKAGE + " TEXT, "
                                       + MEDIA_DATA_DB_IS_PENDING + " BOOL DEFAULT 0, "
                                       + MEDIA_DATA_DB_TIME_PENDING + " BIGINT DEFAULT 0, "
                                       + MEDIA_DATA_DB_DATE_TRASHED + " BIGINT DEFAULT 0, "
                                       + MEDIA_DATA_DB_RELATIVE_PATH + " TEXT, "
                                       + MEDIA_DATA_DB_VOLUME_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_SELF_ID + " INT DEFAULT 0, "
                                       + MEDIA_DATA_DB_ALBUM_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_URI + " TEXT, "
                                       + MEDIA_DATA_DB_ALBUM + " TEXT)";

const std::string CREATE_IMAGE_VIEW = "CREATE VIEW Image AS SELECT "
                                      + MEDIA_DATA_DB_ID + ", "
                                      + MEDIA_DATA_DB_FILE_PATH + ", "
                                      + MEDIA_DATA_DB_SIZE + ", "
                                      + MEDIA_DATA_DB_NAME + ", "
                                      + MEDIA_DATA_DB_TITLE + ", "
                                      + MEDIA_DATA_DB_DESCRIPTION + ", "
                                      + MEDIA_DATA_DB_DATE_ADDED + ", "
                                      + MEDIA_DATA_DB_DATE_MODIFIED + ", "
                                      + MEDIA_DATA_DB_DATE_TAKEN + ", "
                                      + MEDIA_DATA_DB_MIME_TYPE + ", "
                                      + MEDIA_DATA_DB_LATITUDE + ", "
                                      + MEDIA_DATA_DB_LONGITUDE + ", "
                                      + MEDIA_DATA_DB_ORIENTATION + ", "
                                      + MEDIA_DATA_DB_WIDTH + ", "
                                      + MEDIA_DATA_DB_HEIGHT + ", "
                                      + MEDIA_DATA_DB_BUCKET_ID + ", "
                                      + MEDIA_DATA_DB_BUCKET_NAME + ", "
                                      + MEDIA_DATA_DB_THUMBNAIL + ", "
                                      + MEDIA_DATA_DB_LCD + ", "
                                      + MEDIA_DATA_DB_SELF_ID + " "
                                      + "FROM Files WHERE "
                                      + MEDIA_DATA_DB_MEDIA_TYPE + " = 3";

const std::string CREATE_VIDEO_VIEW = "CREATE VIEW Video AS SELECT "
                                      + MEDIA_DATA_DB_ID + ", "
                                      + MEDIA_DATA_DB_FILE_PATH + ", "
                                      + MEDIA_DATA_DB_SIZE + ", "
                                      + MEDIA_DATA_DB_NAME + ", "
                                      + MEDIA_DATA_DB_TITLE + ", "
                                      + MEDIA_DATA_DB_DESCRIPTION + ", "
                                      + MEDIA_DATA_DB_DATE_ADDED + ", "
                                      + MEDIA_DATA_DB_DATE_MODIFIED + ", "
                                      + MEDIA_DATA_DB_MIME_TYPE + ", "
                                      + MEDIA_DATA_DB_ORIENTATION + ", "
                                      + MEDIA_DATA_DB_WIDTH + ", "
                                      + MEDIA_DATA_DB_HEIGHT + ", "
                                      + MEDIA_DATA_DB_DURATION + ", "
                                      + MEDIA_DATA_DB_BUCKET_ID + ", "
                                      + MEDIA_DATA_DB_BUCKET_NAME + ", "
                                      + MEDIA_DATA_DB_THUMBNAIL + ", "
                                      + MEDIA_DATA_DB_SELF_ID + " "
                                      + "FROM Files WHERE "
                                      + MEDIA_DATA_DB_MEDIA_TYPE + " = 4";

const std::string CREATE_AUDIO_VIEW = "CREATE VIEW Audio AS SELECT "
                                      + MEDIA_DATA_DB_ID + ", "
                                      + MEDIA_DATA_DB_FILE_PATH + ", "
                                      + MEDIA_DATA_DB_SIZE + ", "
                                      + MEDIA_DATA_DB_NAME + ", "
                                      + MEDIA_DATA_DB_TITLE + ", "
                                      + MEDIA_DATA_DB_DESCRIPTION + ", "
                                      + MEDIA_DATA_DB_DATE_ADDED + ", "
                                      + MEDIA_DATA_DB_DATE_MODIFIED + ", "
                                      + MEDIA_DATA_DB_MIME_TYPE + ", "
                                      + MEDIA_DATA_DB_ARTIST + ", "
                                      + MEDIA_DATA_DB_DURATION + ", "
                                      + MEDIA_DATA_DB_BUCKET_ID + ", "
                                      + MEDIA_DATA_DB_BUCKET_NAME + ", "
                                      + MEDIA_DATA_DB_THUMBNAIL + ", "
                                      + MEDIA_DATA_DB_SELF_ID + " "
                                      + "FROM Files WHERE "
                                      + MEDIA_DATA_DB_MEDIA_TYPE + " = 5";

const std::string FILE_TABLE = "file";
const std::string ABLUM_TABLE = "album";
const std::string ABLUM_VIEW_NAME = "Album";
const std::string CREATE_ABLUM_VIEW = "CREATE VIEW " + ABLUM_VIEW_NAME
                                      + " AS SELECT count(*) AS "+ MEDIA_DATA_DB_COUNT + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_RELATIVE_PATH + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_ID + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_FILE_PATH + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_NAME + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_TITLE + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_DESCRIPTION + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_DATE_ADDED + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_DATE_MODIFIED + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_DATE_TAKEN + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_MIME_TYPE + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_ARTIST + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_DURATION + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_THUMBNAIL + ", "
                                      + ABLUM_TABLE + "." + MEDIA_DATA_DB_SELF_ID
                                      + " FROM Files "+ FILE_TABLE + ", "
                                      + " Files " + ABLUM_TABLE
                                      + " WHERE "
                                      + FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID + " = "
                                      + ABLUM_TABLE + "."+ MEDIA_DATA_DB_ID
                                      + " GROUP BY "
                                      + FILE_TABLE + "." + MEDIA_DATA_DB_BUCKET_ID +", "
                                      + FILE_TABLE + "." +MEDIA_DATA_DB_BUCKET_NAME;

const std::string SMARTALBUM_DB_ID = "album_id";
const std::string SMARTALBUM_DB_CAPACITY = "capacity";
const std::string SMARTALBUM_DB_NAME = "name";
const std::string SMARTALBUM_DB_TAG = "tag";
const std::string SMARTALBUM_DB_CATEGORYID = "category_id";
const std::string SMARTALBUM_DB_CATEGORYNAME = "category_name";
const std::string SMARTALBUM_DB_COVERURI = "cover_uri";
const std::string SMARTALBUM_DB_SELF_ID = "self_id";
const std::string CREATE_SMARTALBUM_TABLE = "CREATE TABLE IF NOT EXISTS " + SMARTALBUM_TABLE + " ("
                                            + SMARTALBUM_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            + SMARTALBUM_DB_CAPACITY + " TEXT, "
                                            + SMARTALBUM_DB_NAME + " TEXT, "
                                            + SMARTALBUM_DB_TAG + " TEXT, "
                                            + SMARTALBUM_DB_CATEGORYID + " INT, "
                                            + SMARTALBUM_DB_CATEGORYNAME + " TEXT, "
                                            + SMARTALBUM_DB_COVERURI + " TEXT, "
                                            + SMARTALBUM_DB_SELF_ID + " TEXT) ";

const std::string SMARTALBUMMAP_DB_ID = "map_id";
const std::string SMARTALBUMMAP_DB_ALBUM_ID = "id";
const std::string SMARTALBUMMAP_DB_SUB_ALBUM_ID = "album_id";
const std::string SMARTALBUMMAP_DB_ASSET_ID = "asset_id";
const std::string SMARTALBUMMAP_DB_SELF_ID = "self_id";
const std::string CREATE_SMARTALBUMMAP_TABLE = "CREATE TABLE IF NOT EXISTS " + SMARTALBUM_MAP_TABLE + " ("
                                            + SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            + SMARTALBUMMAP_DB_ALBUM_ID + " INT, "
                                            + SMARTALBUMMAP_DB_ASSET_ID + " INT, "
                                            + SMARTALBUMMAP_DB_SELF_ID + " TEXT) ";

const std::string DEVICE_DB_ID = "device_id";
const std::string DEVICE_DB_NAME = "device_name";
const std::string DEVICE_DB_IP = "device_ip";
const std::string DEVICE_DB_SYNC_STATUS = "sync_status";
const std::string DEVICE_DB_SELF_ID = "self_id";
const std::string DEVICE_DB_TYPE = "device_type";
const std::string DEVICE_DB_PREPATH = "pre_path";
const std::string DEVICE_DB_DATE_ADDED = "date_added";
const std::string DEVICE_DB_DATE_MODIFIED = "date_modified";
const std::string CREATE_DEVICE_TABLE = "CREATE TABLE IF NOT EXISTS " + DEVICE_TABLE + " ("
                                            + SMARTALBUMMAP_DB_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            + DEVICE_DB_NAME + " TEXT, "
                                            + DEVICE_DB_IP + " TEXT, "
                                            + DEVICE_DB_SYNC_STATUS + " TEXT, "
                                            + DEVICE_DB_SELF_ID + " TEXT, "
                                            + DEVICE_DB_TYPE + " TEXT, "
                                            + DEVICE_DB_PREPATH + " TEXT, "
                                            + DEVICE_DB_DATE_ADDED + " BIGINT, "
                                            + DEVICE_DB_DATE_MODIFIED + " BIGINT) ";

// File operations constants
const std::string MEDIA_OPERN_KEYWORD = "operation";
const std::string MEDIA_FILEOPRN = "file_operation";
const std::string MEDIA_ALBUMOPRN = "album_operation";
const std::string MEDIA_SMARTALBUMOPRN = "albumsmart_operation";
const std::string MEDIA_SMARTALBUMMAPOPRN = "smartalbummap_operation";
const std::string MEDIA_FILEOPRN_CREATEASSET = "create_asset";
const std::string MEDIA_FILEOPRN_MODIFYASSET = "modify_asset";
const std::string MEDIA_FILEOPRN_DELETEASSET = "delete_asset";
const std::string MEDIA_FILEOPRN_OPENASSET = "open_asset";
const std::string MEDIA_FILEOPRN_CLOSEASSET = "close_asset";
const std::string MEDIA_FILEOPRN_ISDIRECTORY = "isdirectory_asset";

const std::string MEDIA_ALBUMOPRN_CREATEALBUM = "create_album";
const std::string MEDIA_ALBUMOPRN_MODIFYALBUM = "modify_album";
const std::string MEDIA_ALBUMOPRN_DELETEALBUM = "delete_album";
const std::string MEDIA_ALBUMOPRN_QUERYALBUM = "query_album";
const std::string MEDIA_SMARTALBUMOPRN_CREATEALBUM = "create_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_MODIFYALBUM = "modify_smartalbum";
const std::string MEDIA_SMARTALBUMOPRN_DELETEALBUM = "delete_smartalbum";
const std::string MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM = "add_smartalbum_map";
const std::string MEDIA_FILEMODE = "mode";
const std::string MEDIA_FILEDESCRIPTOR = "fd";
const std::string MEDIA_FILEMODE_READONLY = "r";
const std::string MEDIA_FILEMODE_WRITEONLY = "w";
const std::string MEDIA_FILEMODE_READWRITE = "rw";
const std::string MEDIA_FILEMODE_WRITETRUNCATE = "wt";
const std::string MEDIA_FILEMODE_WRITEAPPEND = "wa";
const std::string MEDIA_FILEMODE_READWRITETRUNCATE = "rwt";

const std::string ALBUM_DB_COND = MEDIA_DATA_DB_ID + " = ?";
} // namespace OHOS
} // namespace Media
#endif // MEDIA_DATA_ABILITY_CONST_H
