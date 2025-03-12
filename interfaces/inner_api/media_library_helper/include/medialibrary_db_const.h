/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include <map>

#include "medialibrary_type_const.h"
#include "media_column.h"
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {

const int32_t MEDIA_RDB_VERSION = 151;

enum {
    VERSION_ADD_CLOUD = 2,
    VERSION_ADD_META_MODIFED = 3,
    VERSION_MODIFY_SYNC_STATUS = 4,
    VERSION_ADD_API10_TABLE = 5,
    VERSION_MODIFY_DELETE_TRIGGER = 6,
    VERSION_ADD_CLOUD_VERSION = 7,
    VERSION_UPDATE_CLOUD_PATH = 8,
    VERSION_UPDATE_API10_TABLE = 9,
    VERSION_ADD_TABLE_TYPE = 10,
    VERSION_ADD_PACKAGE_NAME = 11,
    VERSION_ADD_CLOUD_ALBUM = 12,
    VERSION_ADD_CAMERA_SHOT_KEY = 13,
    /**
     * Remove album count triggers for batch operation performance,
     * update PhotoAlbum.count by a query and an update(in a single transaction of course)
     * if number of assets in an album changes.
     */
    VERSION_REMOVE_ALBUM_COUNT_TRIGGER = 14,
    VERSION_ADD_ALL_EXIF = 15,
    VERSION_ADD_UPDATE_CLOUD_SYNC_TRIGGER = 16,
    VERSION_ADD_YEAR_MONTH_DAY = 17,
    VERSION_UPDATE_YEAR_MONTH_DAY = 18,
    VERSION_ADD_PHOTO_EDIT_TIME = 21,
    VERSION_ADD_VISION_TABLE = 22,
    VERSION_FIX_INDEX_ORDER = 23,
    VERSION_ADD_SHOOTING_MODE = 24,
    VERSION_ADD_HIDDEN_VIEW_COLUMNS = 25,
    VERSION_ADD_HIDDEN_TIME = 26,
    VERSION_ADD_LAST_VISIT_TIME = 27,
    VERSION_ADD_LOCATION_TABLE = 29,
    VERSION_ADD_ALBUM_ORDER = 30,
    VERSION_ADD_FACE_TABLE = 31,
    VERSION_ADD_VISION_ALBUM = 32,
    VERSION_ADD_SOURCE_ALBUM_TRIGGER = 33,
    VERSION_FIX_DOCS_PATH = 34,
    VERSION_ADD_SEARCH_TABLE = 35,
    VERSION_ADD_FORM_MAP = 36,
    VERSION_ADD_IMAGE_VIDEO_COUNT = 37,
    VERSION_ADD_PHOTO_CLEAN_FLAG_AND_THUMB_STATUS = 38,
    VERSION_ADD_AESTHETIC_COMPOSITION_TABLE = 39,
    VERSION_ADD_SCHPT_HIDDEN_TIME_INDEX = 40,
    VERSION_ADD_SALIENCY_TABLE = 41,
    VERSION_CLEAR_LABEL_DATA = 42,
    VERSION_REOMOVE_SOURCE_ALBUM_TO_ANALYSIS = 43,
    VERSION_ADD_SHOOTING_MODE_TAG = 44,
    VERSION_ADD_PORTRAIT_IN_ALBUM = 45,
    VERSION_UPDATE_GEO_TABLE = 46,
    VERSION_ADD_MULTISTAGES_CAPTURE = 47,
    VERSION_UPDATE_DATE_TO_MILLISECOND = 48,
    VERSION_ADD_ADDRESS_DESCRIPTION = 49,
    VERSION_ADD_HAS_ASTC = 50,
    VERSION_UPDATE_SPEC_FOR_ADD_SCREENSHOT = 51,
    VERSION_MOVE_SOURCE_ALBUM_TO_PHOTO_ALBUM_AND_ADD_COLUMNS = 52,
    VERSION_ADD_CLOUD_ID_INDEX = 54,
    VERSION_UPDATE_PHOTOS_MDIRTY_TRIGGER = 55,
    VERSION_ALBUM_REFRESH = 56,
    VERSION_ADD_FAVORITE_INDEX = 57,
    VERSION_MODIFY_SOURCE_ALBUM_TRIGGERS = 58,
    VERSION_ADD_MISSING_UPDATES = 59,
    VERSION_ADD_IS_LOCAL_ALBUM = 60,
    VERSION_ADD_HEAD_AND_POSE_TABLE = 61,
    VERSION_UPDATE_SEARCH_INDEX = 62,
    VERSION_ADD_SEGMENTATION_COLUMNS = 63,
    VERSION_ADD_STOYR_TABLE = 64,
    VERSION_UPDATE_MDIRTY_TRIGGER_FOR_SDIRTY = 65,
    VERSION_SHOOTING_MODE_CLOUD = 66,
    VERSION_ADD_OWNER_APPID = 67,
    VERSION_ADD_VIDEO_LABEL_TABEL = 68,
    VERSION_CREATE_PHOTOS_EXT_TABLE = 69,
    VERSION_ADD_IS_COVER_SATISFIED_COLUMN = 70,
    VERSION_UPDATE_VIDEO_LABEL_TABEL = 71,
    VERSION_MOVE_KVDB = 72,
    VERSION_ADD_DYNAMIC_RANGE_TYPE = 73,
    VERSION_UPDATE_PHOTO_ALBUM_BUNDLENAME = 74,
    VERSION_UPDATE_PHOTO_ALBUM_TIGGER = 75,
    VERSION_ADD_THUMB_LCD_SIZE_COLUMN = 76,
    VERSION_UPDATE_HIGHLIGHT_TABLE_PRIMARY_KEY = 77,
    VERSION_UPDATE_VISION_TRIGGER_FOR_VIDEO_LABEL = 78,
    VERSION_ADD_FACE_OCCLUSION_AND_POSE_TYPE_COLUMN = 79,
    VERSION_ADD_MOVING_PHOTO_EFFECT_MODE = 80,
    VERSION_ADD_IS_TEMP = 81,
    VERSION_ADD_OWNER_APPID_TO_FILES_TABLE = 82,
    VERSION_ADD_IS_TEMP_TO_TRIGGER = 83,
    VERSION_UPDATE_PHOTO_THUMBNAIL_READY = 84,
    PHOTOS_CREATE_DISPLAYNAME_INDEX = 85,
    VERSION_UPDATE_ANALYSIS_TABLES = 86,
    VERSION_ADD_COVER_POSITION = 87,
    VERSION_ADD_SCHPT_READY_INEDX = 88,
    VERSION_UPDATE_SOURCE_ALBUM_AND_ALBUM_BUNDLENAME_TRIGGERS = 89,
    VERSION_ADD_FRONT_CAMERA_TYPE = 90,
    VERSION_UPDATE_PHOTO_INDEX_FOR_ALBUM_COUNT_COVER = 91,
    VERSION_ADD_BURST_COVER_LEVEL_AND_BURST_KEY = 92,
    VERSION_CREATE_BURSTKEY_INDEX = 93,
    VERSION_PORTRAIT_COVER_SELECTION_ADD_COLUMNS = 94,
    VERSION_UPDATE_DATA_ADDED_INDEX = 95,
    VERSION_ADD_APP_URI_PERMISSION_INFO = 96,
    VERSION_UPGRADE_THUMBNAIL = 97,
    VERSION_UPDATE_SEARCH_INDEX_TRIGGER = 98,
    VERSION_UPDATE_MULTI_CROP_INFO = 99,
    VERSION_UDAPTE_DATA_UNIQUE = 100,
    VERSION_UPDATE_BURST_DIRTY = 101,
    VERSION_ADD_ORIGINAL_SUBTYPE = 102,
    VERSION_CLOUD_ENAHCNEMENT = 103,
    VERSION_UPDATE_MDIRTY_TRIGGER_FOR_UPLOADING_MOVING_PHOTO = 104,
    VERSION_ADD_INDEX_FOR_FILEID = 105,
    VERSION_MOVE_AUDIOS = 106,
    VERSION_FIX_PHOTO_SCHPT_MEDIA_TYPE_INDEX = 107,
    VERSION_ADD_OWNER_ALBUM_ID = 108,
    VERSION_ADD_THUMBNAIL_VISIBLE = 130,
    VERSION_ADD_DETAIL_TIME = 131,
    VERSION_COMPAT_LIVE_PHOTO = 132,
    VERSION_ADD_CLOUD_ENHANCEMENT_ALBUM = 133,
    VERSION_ADD_THUMBNAIL_VISIBLE_FIX = 134,
    VERSION_ADD_HIGHLIGHT_MAP_TABLES = 135,
    VERSION_UPDATE_SEARCH_INDEX_TRIGGER_FOR_CLEAN_FLAG = 136,
    VERSION_CREATE_TAB_OLD_PHOTOS = 137,
    VERSION_HDR_AND_CLOUD_ENAHCNEMENT_FIX = 138,
    VERSION_THUMBNAIL_READY_FIX = 139,
    VERSION_UPDATE_AOI = 140,
    VERSION_UPDATE_SOURCE_PHOTO_ALBUM_TRIGGER = 141,
    VERSION_ADD_READY_COUNT_INDEX = 142,
    VERSION_UPDATE_DATETAKEN_AND_DETAILTIME = 143,
    VERSION_ADD_SUPPORTED_WATERMARK_TYPE = 144,
    VERSION_FIX_DATE_ADDED_INDEX = 145,
    VERSION_REVERT_FIX_DATE_ADDED_INDEX = 146,
    VERSION_FIX_PICTURE_LCD_SIZE = 147,
    VERSION_UPDATE_PHOTOS_DATE_AND_IDX = 148,
    VERSION_ADD_CHECK_FLAG = 149,
    VERSION_UPDATE_MEDIA_TYPE_AND_THUMBNAIL_READY_IDX = 150,
    VERSION_ADD_IS_AUTO = 151,
};

enum {
    MEDIA_API_VERSION_DEFAULT = 8,
    MEDIA_API_VERSION_V9,
    MEDIA_API_VERSION_V10,
};

const std::vector<std::string> CAMERA_BUNDLE_NAMES = {
    "com.huawei.hmos.camera"
};

enum CloudFilePosition {
    POSITION_LOCAL = 1 << 0,
    POSITION_CLOUD = 1 << 1,
};

const std::string MEDIA_LIBRARY_VERSION = "1.0";

const int32_t DEVICE_SYNCSTATUSING = 0;
const int32_t DEVICE_SYNCSTATUS_COMPLETE = 1;

const std::string MEDIA_DATA_DEVICE_PATH = "local";
const std::string MEDIALIBRARY_TABLE = "Files";
const std::string SMARTALBUM_TABLE = "SmartAlbum";
const std::string SMARTALBUM_MAP_TABLE = "SmartMap";
const std::string CATEGORY_SMARTALBUM_MAP_TABLE = "CategorySmartAlbumMap";
const std::string MEDIATYPE_DIRECTORY_TABLE = "MediaTypeDirectory";
const std::string DEVICE_TABLE = "Device";
const std::string BUNDLE_PERMISSION_TABLE = "BundlePermission";
const std::string MEDIA_DATA_ABILITY_DB_NAME = "media_library.db";

const std::string BUNDLE_NAME = "com.ohos.medialibrary.medialibrarydata";

const std::string ML_FILE_SCHEME = "file";
const std::string ML_FILE_PREFIX = "file://";
const std::string ML_FILE_URI_PREFIX = "file://media";
const std::string ML_URI_NETWORKID = "networkid";
const std::string ML_URI_NETWORKID_EQUAL = "?networkid=";
const std::string ML_URI_TIME_ID = "&time_id=";
const std::string ML_URI_OFFSET = "&offset=";
const std::string ML_URI_DATE_ADDED = "date_added";
const std::string ML_URI_DATE_TAKEN = "date_taken";
const std::string ML_URI_AUTHORITY = "media";
const std::string ML_DATA_SHARE_SCHEME = "datashare";
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
const std::string MEDIALIBRARY_TYPE_HIGHLIGHT_URI = "/highlight";

const std::string AUDIO_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_AUDIO_URI;
const std::string VIDEO_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_VIDEO_URI;
const std::string IMAGE_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_IMAGE_URI;
const std::string FILE_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_FILE_URI;
const std::string ALBUM_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_ALBUM_URI;
const std::string HIGHLIGHT_URI_PREFIX = ML_FILE_URI_PREFIX + MEDIALIBRARY_TYPE_HIGHLIGHT_URI;

const std::string URI_TYPE_PHOTO = "Photo";
const std::string URI_TYPE_AUDIO_V10 = "Audio";
const std::string URI_TYPE_PHOTO_ALBUM = "PhotoAlbum";
constexpr int64_t AGING_TIME = 30LL * 60 * 60 * 24 * 1000;

const std::string MEDIALIBRARY_SMARTALBUM_URI = MEDIALIBRARY_DATA_URI + "/" + SMARTALBUM_TABLE;
const std::string MEDIALIBRARY_SMARTALBUM_MAP_URI = MEDIALIBRARY_DATA_URI + "/" + SMARTALBUM_MAP_TABLE;
const std::string MEDIALIBRARY_CATEGORY_SMARTALBUM_MAP_URI = MEDIALIBRARY_DATA_URI + "/"
                                                             + CATEGORY_SMARTALBUM_MAP_TABLE;
const std::string MEDIALIBRARY_DIRECTORY_URI = MEDIALIBRARY_DATA_URI + "/" + MEDIATYPE_DIRECTORY_TABLE;
const std::string MEDIALIBRARY_BUNDLEPERM_URI = MEDIALIBRARY_DATA_URI + "/" + BUNDLE_PERMISSION_INSERT;

const std::string MEDIALIBRARY_CHECK_URIPERM_URI = MEDIALIBRARY_DATA_URI + "/" + CHECK_URI_PERMISSION;
const std::string MEDIALIBRARY_GRANT_URIPERM_URI = MEDIALIBRARY_DATA_URI + "/" + GRANT_URI_PERMISSION;

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
const std::string MEDIA_DATA_DB_DATE_MODIFIED_S = "date_modified_s";
const std::string MEDIA_DATA_DB_DATE_MODIFIED_MS = "date_modified_ms";
const std::string MEDIA_DATA_DB_DATE_MODIFIED_TO_SECOND = "CAST(date_modified / 1000 AS BIGINT) AS date_modified_s";
const std::string MEDIA_DATA_DB_DATE_ADDED = "date_added";
const std::string MEDIA_DATA_DB_DATE_ADDED_S = "date_added_s";
const std::string MEDIA_DATA_DB_DATE_ADDED_MS = "date_added_ms";
const std::string MEDIA_DATA_DB_DATE_ADDED_TO_SECOND = "CAST(date_added / 1000 AS BIGINT) AS date_added_s";
const std::string MEDIA_DATA_DB_MIME_TYPE = "mime_type";
const std::string MEDIA_DATA_DB_TITLE = "title";
const std::string MEDIA_DATA_DB_DESCRIPTION = "description";
const std::string MEDIA_DATA_DB_NAME = "display_name";
const std::string MEDIA_DATA_DB_ORIENTATION = "orientation";
const std::string MEDIA_DATA_DB_LATITUDE = "latitude";
const std::string MEDIA_DATA_DB_LONGITUDE = "longitude";
const std::string MEDIA_DATA_DB_DATE_TAKEN = "date_taken";
const std::string MEDIA_DATA_DB_DATE_TAKEN_S = "date_taken_s";
const std::string MEDIA_DATA_DB_DATE_TAKEN_MS = "date_taken_ms";
const std::string MEDIA_DATA_DB_DATE_TAKEN_TO_SECOND = "CAST(date_taken / 1000 AS BIGINT) AS date_taken_s";
const std::string MEDIA_DATA_DB_THUMBNAIL = "thumbnail";
const std::string MEDIA_DATA_DB_THUMB_ASTC = "astc";
const std::string MEDIA_DATA_DB_HAS_ASTC = "has_astc"; // This attribute has been replaced by "thumbnail_ready"
const std::string MEDIA_DATA_DB_CONTENT_CREATE_TIME = "content_create_time";
const std::string MEDIA_DATA_DB_POSITION = "position";
const std::string MEDIA_DATA_DB_DIRTY = "dirty";
const std::string MEDIA_DATA_DB_CLOUD_ID = "cloud_id";
const std::string MEDIA_DATA_DB_META_DATE_MODIFIED = "meta_date_modified";
const std::string MEDIA_DATA_DB_SYNC_STATUS = "sync_status";
const std::string MEDIA_DATA_DB_THUMBNAIL_READY = "thumbnail_ready";

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
const std::string MEDIA_DATA_DB_OWNER_APPID = "owner_appid";
const std::string MEDIA_DATA_DB_PACKAGE_NAME = "package_name";

const std::string MEDIA_DATA_DB_IS_FAV = "is_favorite";
const std::string MEDIA_DATA_DB_IS_TRASH = "is_trash";
const std::string MEDIA_DATA_DB_RECYCLE_PATH = "recycle_path";
const std::string MEDIA_DATA_DB_DATE_TRASHED = "date_trashed";
const std::string MEDIA_DATA_DB_DATE_TRASHED_S = "date_trashed_s";
const std::string MEDIA_DATA_DB_DATE_TRASHED_MS = "date_trashed_ms";
const std::string MEDIA_DATA_DB_DATE_TRASHED_TO_SECOND = "CAST(date_trashed / 1000 AS BIGINT) AS date_trashed_s";
const std::string MEDIA_DATA_DB_IS_PENDING = "is_pending";
const std::string MEDIA_DATA_DB_TIME_PENDING = "time_pending";
const std::string MEDIA_DATA_DB_RELATIVE_PATH = "relative_path";
const std::string MEDIA_DATA_DB_VOLUME_NAME = "volume_name";
const std::string MEDIA_DATA_DB_SELF_ID = "self_id";
const std::string MEDIA_DATA_DB_DEVICE_NAME = "device_name";

const std::string MEDIA_DATA_DB_ALBUM = "album";
const std::string MEDIA_DATA_DB_ALBUM_ID = "album_id";
const std::string MEDIA_DATA_DB_REFERENCE_ALBUM_ID = "reference_album_id";
const std::string MEDIA_DATA_DB_ALBUM_NAME = "album_name";
const std::string MEDIA_DATA_DB_COUNT = "count";
const std::string MEDIA_DATA_BUNDLENAME = "bundle_name";
const std::string MEDIA_DATA_DB_IS_LOCAL = "is_local";
const std::string MEDIA_DATA_DB_HIGHLIGHT = "highlight";

const std::string MEDIA_DATA_CALLING_UID = "calling_uid";

const std::map<std::string, std::string> DATE_TRANSITION_MAP = {
    { MEDIA_DATA_DB_DATE_MODIFIED_MS, MEDIA_DATA_DB_DATE_MODIFIED },
    { MEDIA_DATA_DB_DATE_ADDED_MS, MEDIA_DATA_DB_DATE_ADDED },
    { MEDIA_DATA_DB_DATE_TRASHED_MS, MEDIA_DATA_DB_DATE_TRASHED },
    { MEDIA_DATA_DB_DATE_TAKEN_MS, MEDIA_DATA_DB_DATE_TAKEN },
};

// ringtone uri constants
const std::string MEDIA_DATA_DB_RINGTONE_URI = "ringtone_uri";
const std::string MEDIA_DATA_DB_ALARM_URI = "alarm_uri";
const std::string MEDIA_DATA_DB_NOTIFICATION_URI = "notification_uri";
const std::string MEDIA_DATA_DB_RINGTONE_TYPE = "ringtone_type";

const std::string MEDIA_DATA_DB_PHOTO_ID = "photo_id";
const std::string MEDIA_DATA_DB_PHOTO_QUALITY = "photo_quality";
const std::string MEDIA_DATA_DB_FIRST_VISIT_TIME = "first_visit_time";
const std::string MEDIA_DATA_DB_DEFERRED_PROC_TYPE = "deferred_proc_type";

const std::string MEDIA_COLUMN_COUNT = "count(*)";
const std::string MEDIA_COLUMN_COUNT_1 = "count(1)";
const std::string MEDIA_COLUMN_COUNT_DISTINCT_FILE_ID = "count(distinct file_id)";

const std::string PHOTO_INDEX = "photo_index";

const std::string PERMISSION_ID = "id";
const std::string PERMISSION_BUNDLE_NAME = "bundle_name";
const std::string PERMISSION_FILE_ID = "file_id";
const std::string PERMISSION_MODE = "mode";
const std::string PERMISSION_TABLE_TYPE = "table_type";

const std::string FILE_TABLE = "file";
const std::string ALBUM_TABLE = "album";
const std::string ALBUM_VIEW_NAME = "Album";

const std::string SMARTALBUMMAP_TABLE_NAME = "smartAlbumMap";
const std::string SMARTALBUMASSETS_VIEW_NAME = "SmartAsset";
const std::string SMARTALBUMASSETS_ALBUMCAPACITY = "size";
const std::string SMARTABLUMASSETS_PARENTID = "parentid";

const std::string ASSETMAP_VIEW_NAME = "AssetMap";

const std::string IMAGE_ASSET_TYPE = "image";
const std::string VIDEO_ASSET_TYPE = "video";
const std::string AUDIO_ASSET_TYPE = "audio";

// Caution: Keep same definition as MediaColumn! Only for where clause check in API9 getAlbums and album.getFileAssets
const std::string COMPAT_ALBUM_SUBTYPE = "album_subtype";
const std::string COMPAT_HIDDEN = "hidden";
const std::string COMPAT_PHOTO_SYNC_STATUS = "sync_status";
const std::string COMPAT_FILE_SUBTYPE = "subtype";
const std::string COMPAT_CAMERA_SHOT_KEY = "camera_shot_key";

// system relativePath and albumName, use for API9 compatible API10
const std::string CAMERA_PATH = "Camera/";
const std::string SCREEN_SHOT_PATH = "Pictures/Screenshots/";
const std::string SCREEN_RECORD_PATH = "Videos/ScreenRecordings/";

const std::string CAMERA_ALBUM_NAME = "Camera";
const std::string SCREEN_SHOT_ALBUM_NAME = "Screenshots";
const std::string SCREEN_RECORD_ALBUM_NAME = "ScreenRecordings";

// extension
const std::string ASSET_EXTENTION = "extention";

// delete_tool
const std::string DELETE_TOOL_ONLY_DATABASE = "only_db";

// edit param
const std::string EDIT_DATA_REQUEST = "edit_data_request";  // MEDIA_OPERN_KEYWORD=EDIT_DATA_REQUEST
const std::string SOURCE_REQUEST = "source_request";        // MEDIA_OPERN_KEYWORD=SOURCE_REQUEST
const std::string COMMIT_REQUEST = "commit_request";        // MEDIA_OPERN_KEYWORD=COMMIT_REQUEST
const std::string EDIT_DATA = "edit_data";
const std::string COMPATIBLE_FORMAT = "compatible_format";
const std::string FORMAT_VERSION = "format_version";
const std::string APP_ID = "app_id";

// write cache
const std::string CACHE_FILE_NAME = "cache_file_name";
const std::string CACHE_MOVING_PHOTO_VIDEO_NAME = "cache_moving_photo_video_name";

// moving photo param
const std::string OPEN_MOVING_PHOTO_VIDEO = "open_video"; // MEDIA_MOVING_PHOTO_OPRN_KEYWORD=OPEN_MOVING_PHOTO_VIDEO
const std::string OPEN_PRIVATE_LIVE_PHOTO = "open_private_live_photo";

// db sandbox directory
const std::string MEDIA_DB_DIR = "/data/medialibrary/database";

// slave medialibrary db file path
const std::string MEDIA_DB_FILE_SLAVE = "/data/storage/el2/database/rdb/media_library_slave.db";
const std::string MEDIA_DB_FILE_SLAVE_SHM = "/data/storage/el2/database/rdb/media_library_slave.db-shm";
const std::string MEDIA_DB_FILE_SLAVE_WAL = "/data/storage/el2/database/rdb/media_library_slave.db-wal";

// requestId for generating thumbnail in batches
const std::string THUMBNAIL_BATCH_GENERATE_REQUEST_ID = "thumbnail_request_id";
const std::string IMAGE_FILE_TYPE = "image_file_type";

} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_DATA_ABILITY_CONST_H_
