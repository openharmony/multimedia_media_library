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

#ifndef BACKUP_CONST_COLUMN_H
#define BACKUP_CONST_COLUMN_H

#include "backup_const.h"
#include "media_smart_album_column.h"

namespace OHOS {
namespace Media {
const int32_t IS_LOCAL_TRUE = 1;
const int32_t RENAME_OPERATION_RENAMED = 1;
const std::string DEFAULT_BACKUP_VERSION = "backup1.0";
const std::string GALLERY_TABLE_MERGE_FACE = "merge_face";
const std::string GALLERY_TABLE_MERGE_TAG = "merge_tag";
const std::string GALLERY_TABLE_MEDIA = "gallery_media";
const std::string GALLERY_TABLE_FACE = "face";
const std::string GALLERY_TAG_ID = "tag_id";
const std::string GALLERY_FACE_ID = "face_id";
const std::string GALLERY_GROUP_TAG = "merge_tag.group_tag";
const std::string GALLERY_TAG_NAME = "merge_tag.tag_name";
const std::string GALLERY_USER_OPERATION = "merge_tag.user_operation";
const std::string GALLERY_RENAME_OPERATION = "merge_tag.rename_operation";
const std::string GALLERY_SCALE_X = "merge_face.scale_x";
const std::string GALLERY_SCALE_Y = "merge_face.scale_y";
const std::string GALLERY_SCALE_WIDTH = "merge_face.scale_width";
const std::string GALLERY_SCALE_HEIGHT = "merge_face.scale_height";
const std::string GALLERY_PITCH = "merge_face.pitch";
const std::string GALLERY_YAW = "merge_face.yaw";
const std::string GALLERY_ROLL = "merge_face.roll";
const std::string GALLERY_PROB = "face.prob";
const std::string GALLERY_TOTAL_FACE = "merge_face.total_face";
const std::string GALLERY_LANDMARKS = "merge_face.landmarks";
const std::string GALLERY_MERGE_FACE_HASH = GALLERY_TABLE_MERGE_FACE + "." + GALLERY_HASH;
const std::string GALLERY_MERGE_FACE_TAG_ID = GALLERY_TABLE_MERGE_FACE + "." + GALLERY_TAG_ID;
const std::string GALLERY_MERGE_TAG_TAG_ID = GALLERY_TABLE_MERGE_TAG + "." + GALLERY_TAG_ID;
const std::string GALLERY_MEDIA_ID = GALLERY_TABLE_MEDIA + "." + GALLERY_ID;
const std::string GALLERY_MEDIA_HASH = GALLERY_TABLE_MEDIA + "." + GALLERY_HASH;
const std::string GALLERY_FACE_HASH = GALLERY_TABLE_FACE + "." + GALLERY_HASH;
const std::string GALLERY_MERGE_FACE_FACE_ID = GALLERY_TABLE_MERGE_FACE + "." + GALLERY_FACE_ID;
const std::string GALLERY_FACE_FACE_ID = GALLERY_TABLE_FACE + "." + GALLERY_FACE_ID;
const std::string E_VERSION = "-1";
const std::string TAG_ID_PREFIX = "ser_";
const std::string TAG_ID_UNPROCESSED = "-1";

/* AnalysisAlbum TBL COL_NAME */
const std::string ANALYSIS_COL_ALBUM_ID = "album_id";
const std::string ANALYSIS_COL_ALBUM_TYPE = "album_type";
const std::string ANALYSIS_COL_ALBUM_SUBTYPE = "album_subtype";
const std::string ANALYSIS_COL_ALBUM_NAME = "album_name";
const std::string ANALYSIS_COL_COVER_URI = "cover_uri";
const std::string ANALYSIS_COL_COUNT = "count";
const std::string ANALYSIS_COL_DATE_MODIFIED = "date_modified";
const std::string ANALYSIS_COL_RANK = "rank";
const std::string ANALYSIS_COL_TAG_ID = "tag_id";
const std::string ANALYSIS_COL_USER_OPERATION = "user_operation";
const std::string ANALYSIS_COL_GROUP_TAG = "group_tag";
const std::string ANALYSIS_COL_USER_DISPLAY_LEVEL = "user_display_level";
const std::string ANALYSIS_COL_IS_ME = "is_me";
const std::string ANALYSIS_COL_IS_REMOVED = "is_removed";
const std::string ANALYSIS_COL_RENAME_OPERATION = "rename_operation";
const std::string ANALYSIS_COL_IS_LOCAL = "is_local";
const std::string ANALYSIS_COL_IS_COVER_SATISFIED = "is_cover_satisfied";

/* FaceTag TBL COL_NAME */
const std::string FACE_TAG_COL_ID = "id";
const std::string FACE_TAG_COL_TAG_ID = "tag_id";
const std::string FACE_TAG_COL_TAG_NAME = "tag_name";
const std::string FACE_TAG_COL_USER_OPERATION = "user_operation";
const std::string FACE_TAG_COL_GROUP_TAG = "group_tag";
const std::string FACE_TAG_COL_RENAME_OPERATION = "rename_operation";
const std::string FACE_TAG_COL_CENTER_FEATURES = "center_features";
const std::string FACE_TAG_COL_TAG_VERSION = "tag_version";
const std::string FACE_TAG_COL_USER_DISPLAY_LEVEL = "user_display_level";
const std::string FACE_TAG_COL_TAG_ORDER = "tag_order";
const std::string FACE_TAG_COL_IS_ME = "is_me";
const std::string FACE_TAG_COL_COVER_URI = "cover_uri";
const std::string FACE_TAG_COL_COUNT = "count";
const std::string FACE_TAG_COL_DATE_MODIFY = "date_modify";
const std::string FACE_TAG_COL_ALBUM_TYPE = "album_type";
const std::string FACE_TAG_COL_IS_REMOVED = "is_removed";
const std::string FACE_TAG_COL_ANALYSIS_VERSION = "analysis_version";

// image_face_tbl COL_NAME
const std::string IMAGE_FACE_COL_ID = "id";
const std::string IMAGE_FACE_COL_FILE_ID = "file_id";
const std::string IMAGE_FACE_COL_FACE_ID = "face_id";
const std::string IMAGE_FACE_COL_TAG_ID = "tag_id";
const std::string IMAGE_FACE_COL_SCALE_X = "scale_x";
const std::string IMAGE_FACE_COL_SCALE_Y = "scale_y";
const std::string IMAGE_FACE_COL_SCALE_WIDTH = "scale_width";
const std::string IMAGE_FACE_COL_SCALE_HEIGHT = "scale_height";
const std::string IMAGE_FACE_COL_LANDMARKS = "landmarks";
const std::string IMAGE_FACE_COL_PITCH = "pitch";
const std::string IMAGE_FACE_COL_YAW = "yaw";
const std::string IMAGE_FACE_COL_ROLL = "roll";
const std::string IMAGE_FACE_COL_PROB = "prob";
const std::string IMAGE_FACE_COL_TOTAL_FACES = "total_faces";
const std::string IMAGE_FACE_COL_FACE_VERSION = "face_version";
const std::string IMAGE_FACE_COL_FEATURES_VERSION = "features_version";
const std::string IMAGE_FACE_COL_FEATURES = "features";
const std::string IMAGE_FACE_COL_FACE_OCCLUSION = "face_occlusion";
const std::string IMAGE_FACE_COL_ANALYSIS_VERSION = "analysis_version";
const std::string IMAGE_FACE_COL_BEAUTY_BOUNDER_X = "beauty_bounder_x";
const std::string IMAGE_FACE_COL_BEAUTY_BOUNDER_Y = "beauty_bounder_y";
const std::string IMAGE_FACE_COL_BEAUTY_BOUNDER_WIDTH = "beauty_bounder_width";
const std::string IMAGE_FACE_COL_BEAUTY_BOUNDER_HEIGHT = "beauty_bounder_height";
const std::string IMAGE_FACE_COL_AESTHETICS_SCORE = "aesthetics_score";
const std::string IMAGE_FACE_COL_BEAUTY_BOUNDER_VERSION = "beauty_bounder_version";
const std::string IMAGE_FACE_COL_IS_EXCLUDED = "is_excluded";
const std::string ANALYSIS_ALBUM_SUBTYPE = "album_subtype";

const std::string QUERY_FACE_TAG_COUNT = "SELECT count(1) AS count FROM " + VISION_FACE_TAG_TABLE;
const std::string QUERY_IMAGE_FACE_COUNT = "SELECT count(1) AS count FROM " + VISION_IMAGE_FACE_TABLE;

const std::string GALLERY_TAG_NAME_NOT_NULL_OR_EMPTY = GALLERY_TAG_NAME + " IS NOT NULL AND " + GALLERY_TAG_NAME +
    " != ''";
const std::string GALLERY_TAG_WITH_PHOTOS = "EXISTS (SELECT 1 FROM " + GALLERY_TABLE_MERGE_FACE + " INNER JOIN \
    gallery_media ON " + GALLERY_MERGE_FACE_HASH + " = gallery_media.hash WHERE " + ALL_PHOTOS_WHERE_CLAUSE + " AND " +
    GALLERY_MERGE_FACE_TAG_ID + " = " + GALLERY_MERGE_TAG_TAG_ID + " AND " + GALLERY_LANDMARKS + " != 0)";
const std::string GALLERY_PORTRAIT_ALBUM_TABLE = GALLERY_TABLE_MERGE_TAG + " WHERE " +
    GALLERY_TAG_NAME_NOT_NULL_OR_EMPTY + " AND " + GALLERY_TAG_WITH_PHOTOS;
const std::string QUERY_GALLERY_PORTRAIT_ALBUM_COUNT = "SELECT count(1) as count FROM " + GALLERY_PORTRAIT_ALBUM_TABLE;
const std::string GALLERY_FACE_TABLE_JOIN_TAG = GALLERY_TABLE_MERGE_FACE + " INNER JOIN " + GALLERY_TABLE_MERGE_TAG +
    " ON " + GALLERY_MERGE_FACE_TAG_ID + " = " + GALLERY_MERGE_TAG_TAG_ID + " INNER JOIN " + GALLERY_TABLE_MEDIA +
    " ON " + GALLERY_MERGE_FACE_HASH + " = " + GALLERY_MEDIA_HASH + " GROUP BY " + GALLERY_MERGE_FACE_HASH + ", " +
    GALLERY_FACE_ID;
const std::string GALLERY_FACE_TABLE_FULL = GALLERY_TABLE_MERGE_FACE + " INNER JOIN " + GALLERY_TABLE_FACE + " ON " +
    GALLERY_MERGE_FACE_HASH + " = " + GALLERY_FACE_HASH + " AND " + GALLERY_MERGE_FACE_FACE_ID + " = " +
    GALLERY_FACE_FACE_ID + " WHERE " + GALLERY_LANDMARKS + " != 0 ";

// Path related
const std::string INTERNAL_PREFIX = "/storage/emulated";
const std::string APP_TWIN_DATA_PREFIX = "/AppTwinData";
const std::string CLONE_STAT_EDIT_DATA_DIR = "/storage/media/local/files/.editData/";
const std::string CLONE_STAT_RDB_DIR = "/data/storage/el2/database/rdb/";
const std::string CLONE_STAT_KVDB_DIR = "/data/storage/el2/database/kvdb/";
} // namespace Media
} // namespace OHOS

#endif  // BACKUP_CONST_COLUMN_H