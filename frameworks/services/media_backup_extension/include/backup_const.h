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

#ifndef OHOS_MEDIA_BACKUP_DEFINES_H
#define OHOS_MEDIA_BACKUP_DEFINES_H

#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

#include "photo_album_column.h"
#include "photo_map_column.h"
#include "vision_column.h"

namespace OHOS {
namespace Media {
constexpr int32_t QUERY_COUNT = 200;
constexpr int32_t PRE_CLONE_PHOTO_BATCH_COUNT = 100;
constexpr int32_t CONNECT_SIZE = 10;
constexpr int32_t MILLISECONDS = 1000;
constexpr int32_t GALLERY_HIDDEN_ID = -4;
constexpr int32_t UPGRADE_RESTORE_ID = 0;
constexpr int32_t DUAL_FRAME_CLONE_RESTORE_ID = 1;
constexpr int32_t CLONE_RESTORE_ID = 2;
constexpr int32_t GARBLE_LOW_LENGTH = 3;
constexpr int32_t GARBLE_MID_LENGTH = 10;
constexpr int32_t GARBLE_HIGH_LENGTH = 20;
constexpr int32_t RETRY_TIME = 5;
constexpr int32_t SLEEP_INTERVAL = 1;
constexpr int32_t GARBAGE_PHOTO_SIZE = 2048;

const std::string BACKUP_RESTORE_DIR = "/data/storage/el2/backup/restore";
const std::string RESTORE_CLOUD_DIR = "/storage/cloud/files/Photo";
const std::string RESTORE_AUDIO_CLOUD_DIR = "/storage/cloud/files/Audio";
const std::string RESTORE_LOCAL_DIR = "/storage/media/local/files/Photo";
const std::string RESTORE_AUDIO_LOCAL_DIR = "/storage/media/local/files/Audio";
const std::string UPGRADE_FILE_DIR = "/storage/media/local/files/data";
const std::string GARBLE_DUAL_FRAME_CLONE_DIR = "/storage/media/local/files/data/storage/emulated";
const std::string GARBLE_CLONE_DIR = "/data/storage/el2/backup/restore/storage/media/local/files";
const std::string GARBLE = "***";

// DB field for update scene
const std::string GALLERY_ID = "_id";
const std::string GALLERY_LOCAL_MEDIA_ID = "local_media_id";
const std::string GALLERY_FILE_DATA = "_data";
const std::string GALLERY_TITLE = "title";
const std::string GALLERY_DISPLAY_NAME = "_display_name";
const std::string GALLERY_DESCRIPTION = "description";
const std::string GALLERY_IS_FAVORITE = "is_hw_favorite";
const std::string GALLERY_RECYCLED_TIME = "recycledTime";
const std::string GALLERY_FILE_SIZE = "_size";
const std::string GALLERY_DURATION = "duration";
const std::string GALLERY_MEDIA_TYPE = "media_type";
const std::string GALLERY_SHOW_DATE_TOKEN = "showDateToken";
const std::string GALLERY_HEIGHT = "height";
const std::string GALLERY_WIDTH = "width";
const std::string GALLERY_ORIENTATION = "orientation";

// external column
const std::string EXTERNAL_IS_FAVORITE = "is_favorite";
const std::string EXTERNAL_DATE_MODIFIED = "date_modified";
const std::string EXTERNAL_DATE_ADDED = "date_added";
const std::string EXTERNAL_FILE_DATA = "_data";
const std::string EXTERNAL_TITLE = "title";
const std::string EXTERNAL_DISPLAY_NAME = "_display_name";
const std::string EXTERNAL_FILE_SIZE = "_size";
const std::string EXTERNAL_DURATION = "duration";
const std::string EXTERNAL_MEDIA_TYPE = "media_type";

// custom column
const std::string CUSTOM_COUNT = "count";
const std::string UNIQUE_NUMBER = "unique_number";
const std::string CUSTOM_MAX_ID = "max_id";
const std::string PRAGMA_TABLE_NAME = "name";
const std::string PRAGMA_TABLE_TYPE = "type";

// audio column
const std::string AUDIO_DATA = "_data";
const std::string AUDIO_DATE_MODIFIED = "date_modified";
const std::string AUDIO_DATE_TAKEN = "datetaken";

const std::string GALLERY_DB_NAME = "gallery.db";
const std::string EXTERNAL_DB_NAME = "external.db";
const std::string AUDIO_DB_NAME = "audio_MediaInfo.db";

constexpr int32_t INDEX_TYPE = 0;
constexpr int32_t INDEX_CACHE_DIR = 1;
constexpr int32_t INDEX_NICK_DIR = 2;
constexpr int32_t INDEX_NICK_NAME = 3;

constexpr int32_t NICK = 0;
constexpr int32_t CACHE = 1;

constexpr int32_t DEFAULT_AREA_VERSION = -1;

enum SourceType {
    GALLERY = 0,
    EXTERNAL_CAMERA,
    EXTERNAL_OTHERS,
    PHOTOS,
    AUDIOS,
};

enum class PrefixType {
    CLOUD = 0,
    LOCAL,
    CLOUD_EDIT_DATA,
    LOCAL_EDIT_DATA,
};

enum DUAL_MEDIA_TYPE {
    IMAGE_TYPE = 1,
    AUDIO_TYPE,
    VIDEO_TYPE,
};

const std::unordered_map<PrefixType, std::string> PREFIX_MAP = {
    { PrefixType::CLOUD, "/storage/cloud/files" },
    { PrefixType::LOCAL, "/storage/media/local/files" },
    { PrefixType::CLOUD_EDIT_DATA, "/storage/cloud/files/.editData" },
    { PrefixType::LOCAL_EDIT_DATA, "/storage/media/local/files/.editData" },
};

const std::vector<std::vector<std::string>> CLONE_TABLE_LISTS_AUDIO = {
    { AudioColumn::AUDIOS_TABLE },
};

const std::vector<std::vector<std::string>> CLONE_TABLE_LISTS_PHOTO = {
    { PhotoColumn::PHOTOS_TABLE },
    { PhotoAlbumColumns::TABLE, PhotoMap::TABLE },
    { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE },
};

struct FileInfo {
    std::string filePath;
    std::string displayName;
    std::string title;
    std::string userComment;
    std::string relativePath;
    std::string cloudPath;
    int32_t fileIdOld {-1};
    int32_t fileIdNew {-1};
    int64_t fileSize {0};
    int64_t duration {0};
    int64_t recycledTime {0};
    int32_t hidden {0};
    int32_t isFavorite {0};
    int32_t fileType {0};
    int64_t showDateToken {0};
    int32_t height {0};
    int32_t width {0};
    int64_t dateAdded {0};
    int32_t orientation {0};
    int64_t dateModified {0};
    bool isNew {true};
    std::unordered_map<std::string, std::variant<int32_t, int64_t, double, std::string>> valMap;
    std::unordered_map<std::string, std::unordered_set<int32_t>> tableAlbumSetMap;
};

struct AlbumInfo {
    int32_t albumIdOld {-1};
    int32_t albumIdNew {-1};
    std::string albumName;
    PhotoAlbumType albumType;
    PhotoAlbumSubType albumSubType;
    std::unordered_map<std::string, std::variant<int32_t, int64_t, double, std::string>> valMap;
};

struct MapInfo {
    int32_t albumId {-1};
    int32_t fileId {-1};
};

// sql for external
const std::string QUERY_FILE_COLUMN = "SELECT _id, " + GALLERY_FILE_DATA + ", " + GALLERY_DISPLAY_NAME + ", " +
    EXTERNAL_IS_FAVORITE + ", " + GALLERY_FILE_SIZE + ", " + GALLERY_DURATION + ", " + GALLERY_MEDIA_TYPE + ", " +
    EXTERNAL_DATE_MODIFIED + ", " + GALLERY_HEIGHT + ", " + GALLERY_WIDTH + ", " + GALLERY_TITLE + ", " +
    GALLERY_ORIENTATION + ", " + EXTERNAL_DATE_ADDED + " FROM files WHERE ";

const std::string IN_CAMERA = " bucket_id IN (-1739773001, 0, 1028075469, 0) AND (is_pending = 0)";

const std::string NOT_IN_CAMERA = " bucket_id NOT IN (-1739773001, 0, 1028075469, 0 ) AND is_pending = 0";

const std::string QUERY_NOT_SYNC = " _id < 1000000000 AND media_type IN (1, 3) AND _size > 0 ";

const std::string COMPARE_ID = " _id > ";

const std::string QUERY_COUNT_FROM_FILES = "SELECT count(1) AS count FROM files WHERE";

// sql for gallery
const std::string QUERY_GARBAGE_ALBUM = "SELECT type, cache_dir, nick_dir, nick_name FROM garbage_album";

const std::string QUERY_MAX_ID_CAMERA_SCREENSHOT = "SELECT max(local_media_id) AS max_id FROM gallery_media \
    WHERE local_media_id > 0 AND bucket_id IN (-1739773001, 0, 1028075469, 0) AND \
    (recycleFlag NOT IN (2, -1, 1, -2, -4) OR recycleFlag IS NULL) AND \
    (storage_id IN (0, 65537) or storage_id IS NULL) AND _size > 0 ";

const std::string QUERY_MAX_ID_OTHERS = "SELECT max(local_media_id) AS max_id FROM gallery_media \
    WHERE local_media_id > 0 AND bucket_id NOT IN (-1739773001, 0, 1028075469, 0) AND \
    (recycleFlag NOT IN (2, -1, 1, -2, -4) OR recycleFlag IS NULL) AND \
    (storage_id IN (0, 65537) or storage_id IS NULL) AND _size > 0 ";

const std::string QUERY_GALLERY_COUNT = "SELECT count(1) AS count FROM gallery_media \
    WHERE (local_media_id != -1) AND (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN ( \
    SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1) AND _size > 0";

const std::string QUERY_ALL_PHOTOS = "SELECT " + GALLERY_LOCAL_MEDIA_ID + "," + GALLERY_FILE_DATA + "," +
    GALLERY_DISPLAY_NAME + "," + GALLERY_DESCRIPTION + "," + GALLERY_IS_FAVORITE + "," + GALLERY_RECYCLED_TIME +
    "," + GALLERY_FILE_SIZE + "," + GALLERY_DURATION + "," + GALLERY_MEDIA_TYPE + "," + GALLERY_SHOW_DATE_TOKEN + "," +
    GALLERY_HEIGHT + "," + GALLERY_WIDTH + "," + GALLERY_TITLE + ", " + GALLERY_ORIENTATION + ", " +
    EXTERNAL_DATE_MODIFIED +
    " FROM gallery_media WHERE (local_media_id != -1) AND (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN ( \
    SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1) AND _size > 0 ORDER BY showDateToken ASC ";

const std::string QUERY_MAX_ID = "SELECT max(local_media_id) AS max_id FROM gallery_media \
    WHERE local_media_id > 0 AND (recycleFlag NOT IN (2, -1, 1, -2, -4) OR recycleFlag IS NULL) AND \
    (storage_id IN (0, 65537) or storage_id IS NULL) AND _size > 0 ";

const std::string QUERY_AUDIO_COUNT = "SELECT count(1) as count FROM files WHERE media_type = 2 AND _size > 0 \
    AND _data LIKE '/storage/emulated/0/Music%'";

const std::string QUERY_ALL_AUDIOS_FROM_EXTERNAL = "SELECT " + EXTERNAL_IS_FAVORITE + "," + EXTERNAL_DATE_MODIFIED +
    "," + EXTERNAL_DATE_ADDED + "," + EXTERNAL_FILE_DATA + "," + EXTERNAL_TITLE + "," + EXTERNAL_DISPLAY_NAME + "," +
    EXTERNAL_FILE_SIZE + "," + EXTERNAL_DURATION + "," + EXTERNAL_MEDIA_TYPE + " FROM files WHERE media_type = 2 AND \
    _size > 0 AND _data LIKE '/storage/emulated/0/Music%'";

const std::string QUERY_ALL_AUDIOS_FROM_AUDIODB = "SELECT " + AUDIO_DATA + "," + AUDIO_DATE_MODIFIED + "," +
    AUDIO_DATE_TAKEN + " FROM mediainfo WHERE _data LIKE '/storage/emulated/0/Music%'";

const std::string QUERY_DUAL_CLONE_AUDIO_COUNT = "SELECT count(1) as count FROM mediainfo WHERE \
    _data LIKE '/storage/emulated/0/Music%'";
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BACKUP_DEFINES_H
