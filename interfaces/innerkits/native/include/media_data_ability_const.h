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
const int32_t MEDIA_RDB_VERSION = 1;

const std::string MEDIA_DATA_DB_Path = "/data/media/";
const std::string MEDIALIBRARY_TABLE = "Files";
const std::string MEDIA_DATA_ABILITY_DB_NAME = MEDIA_DATA_DB_Path + "media_library.db";
const std::string MEDIALIBRARY_DATA_URI = "dataability:///com.ohos.medialibrary.MediaLibraryDataAbility";
const std::string MEDIALIBRARY_AUDIO_URI = MEDIALIBRARY_DATA_URI + '/' + "audio";
const std::string MEDIALIBRARY_VIDEO_URI = MEDIALIBRARY_DATA_URI + '/' + "video";
const std::string MEDIALIBRARY_IMAGE_URI = MEDIALIBRARY_DATA_URI + '/' + "image";
const std::string MEDIALIBRARY_FILE_URI  =  MEDIALIBRARY_DATA_URI + '/' + "file";
const std::string MEDIALIBRARY_ALBUM_URI  =  MEDIALIBRARY_DATA_URI + '/' + "album";

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
const std::string MEDIA_DATA_DB_RELATIVE_PATH = "relative_path";
const std::string MEDIA_DATA_DB_VOLUME_NAME = "volume_name";
const std::string MEDIA_DATA_DB_SELF_ID = "self_id";

const std::string MEDIA_DATA_DB_ALBUM = "album";
const std::string MEDIA_DATA_DB_ALBUM_ID = "album_id";
const std::string MEDIA_DATA_DB_ALBUM_NAME = "album_name";

const std::string CREATE_MEDIA_TABLE = "CREATE TABLE IF NOT EXISTS Files ("
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
                                       + MEDIA_DATA_DB_DATE_TRASHED + " BIGINT DEFAULT 0, "
                                       + MEDIA_DATA_DB_RELATIVE_PATH + " TEXT, "
                                       + MEDIA_DATA_DB_VOLUME_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_SELF_ID + " INT DEFAULT 0, "
                                       + MEDIA_DATA_DB_ALBUM_NAME + " TEXT, "
                                       + MEDIA_DATA_DB_URI + " TEXT, "
                                       + MEDIA_DATA_DB_ALBUM + " TEXT)";

// File operations constants
const std::string MEDIA_OPERN_KEYWORD = "operation";
const std::string MEDIA_FILEOPRN = "file_operation";
const std::string MEDIA_ALBUMOPRN = "album_operation";
const std::string MEDIA_FILEOPRN_CREATEASSET = "create_asset";
const std::string MEDIA_FILEOPRN_MODIFYASSET = "modify_asset";
const std::string MEDIA_FILEOPRN_DELETEASSET = "delete_asset";
const std::string MEDIA_FILEOPRN_OPENASSET = "open_asset";
const std::string MEDIA_FILEOPRN_CLOSEASSET = "close_asset";

const std::string MEDIA_ALBUMOPRN_CREATEALBUM = "create_album";
const std::string MEDIA_ALBUMOPRN_MODIFYALBUM = "modify_album";
const std::string MEDIA_ALBUMOPRN_DELETEALBUM = "delete_album";
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
