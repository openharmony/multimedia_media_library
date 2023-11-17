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

#ifndef MEDIALIBRARY_VISION_COLUMN_H
#define MEDIALIBRARY_VISION_COLUMN_H

#include "media_column.h"
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {
// table name
const std::string VISION_OCR_TABLE = "tab_analysis_ocr";
const std::string VISION_LABEL_TABLE = "tab_analysis_label";
const std::string VISION_AESTHETICS_TABLE = "tab_analysis_aesthetics_score";
const std::string VISION_SALIENCY_TABLE = "tab_analysis_saliency_detect";
const std::string VISION_OBJECT_TABLE = "tab_analysis_object";
const std::string VISION_RECOMMENDATION_TABLE = "tab_analysis_recommendation";
const std::string VISION_SEGMENTATION_TABLE = "tab_analysis_segmentation";
const std::string VISION_COMPOSITION_TABLE = "tab_analysis_composition";
const std::string VISION_TOTAL_TABLE = "tab_analysis_total";
const std::string VISION_SHIELD_TABLE = "tab_application_shield";
const std::string VISION_IMAGE_FACE_TABLE = "tab_analysis_image_face";
const std::string VISION_FACE_TAG_TABLE = "tab_analysis_face_tag";
const std::string ANALYSIS_ALBUM_TABLE = "AnalysisAlbum";
const std::string ANALYSIS_PHOTO_MAP_TABLE = "AnalysisPhotoMap";

// create vision table
const std::string ID = "id";
const std::string FILE_ID = "file_id";
const std::string OCR_TEXT = "ocr_text";
const std::string OCR_VERSION = "ocr_version";
const std::string OCR_TEXT_MSG = "ocr_text_msg";
const std::string OCR_WIDTH = "width";
const std::string OCR_HEIGHT = "height";
const std::string OCR_PRE_MSG = "ocr_pre_msg";
const std::string CREATE_TAB_ANALYSIS_OCR = "CREATE TABLE IF NOT EXISTS " + VISION_OCR_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    OCR_TEXT + " TEXT, " +
    OCR_VERSION + " TEXT, " +
    OCR_TEXT_MSG + " TEXT, " +
    OCR_WIDTH + " INT, " +
    OCR_HEIGHT + " INT)";

const std::string CATEGORY_ID = "category_id";
const std::string SUB_LABEL = "sub_label";
const std::string PROB = "prob";
const std::string LABEL_VERSION = "label_version";
const std::string FEATURE = "feature";
const std::string SIM_RESULT = "sim_result";
const std::string CREATE_TAB_ANALYSIS_LABEL = "CREATE TABLE IF NOT EXISTS " + VISION_LABEL_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    CATEGORY_ID + " INT, " +
    SUB_LABEL + " TEXT, " +
    PROB + " REAL, " +
    FEATURE + " TEXT, " +
    SIM_RESULT + " TEXT, " +
    LABEL_VERSION + " TEXT) ";

const std::string AESTHETICS_SCORE = "aesthetics_score";
const std::string AESTHETICS_VERSION = "aesthetics_version";
const std::string CREATE_TAB_ANALYSIS_AESTHETICS = "CREATE TABLE IF NOT EXISTS " + VISION_AESTHETICS_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    AESTHETICS_SCORE + " INT, " +
    AESTHETICS_VERSION + " TEXT, " +
    PROB + " REAL) ";

const std::string SALIENCY_X = "saliency_x";
const std::string SALIENCY_Y = "saliency_y";
const std::string SALIENCY_VERSION = "saliency_version";
const std::string CREATE_TAB_ANALYSIS_SALIENCY_DETECT = "CREATE TABLE IF NOT EXISTS " + VISION_SALIENCY_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    SALIENCY_X + " REAL, " +
    SALIENCY_Y + " REAL, " +
    SALIENCY_VERSION + " TEXT) ";

const std::string OBJECT_ID = "object_id";
const std::string OBJECT_LABEL = "object_label";
const std::string OBJECT_SCALE_X = "object_scale_x";
const std::string OBJECT_SCALE_Y = "object_scale_y";
const std::string OBJECT_SCALE_WIDTH = "object_scale_width";
const std::string OBJECT_SCALE_HEIGHT = "object_scale_height";
const std::string OBJECT_VERSION = "object_version";
const std::string CREATE_TAB_ANALYSIS_OBJECT = "CREATE TABLE IF NOT EXISTS " + VISION_OBJECT_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT, " +
    OBJECT_ID + " INT, " +
    OBJECT_LABEL + " INT, " +
    OBJECT_SCALE_X + " INT, " +
    OBJECT_SCALE_Y + " INT, " +
    OBJECT_SCALE_WIDTH + " INT, " +
    OBJECT_SCALE_HEIGHT + " INT, " +
    OBJECT_VERSION + " TEXT) ";

const std::string RECOMMENDATION_ID = "recommendation_id";
const std::string RECOMMENDATION_RESOLUTION = "recommendation_resolution";
const std::string RECOMMENDATION_SCALE_X = "recommendation_scale_x";
const std::string RECOMMENDATION_SCALE_Y = "recommendation_scale_y";
const std::string RECOMMENDATION_SCALE_WIDTH = "recommendation_scale_width";
const std::string RECOMMENDATION_SCALE_HEIGHT = "recommendation_scale_height";
const std::string RECOMMENDATION_VERSION = "recommendation_version";
const std::string CREATE_TAB_ANALYSIS_RECOMMENDATION = "CREATE TABLE IF NOT EXISTS " + VISION_RECOMMENDATION_TABLE +
    " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT, " +
    RECOMMENDATION_ID + " INT, " +
    RECOMMENDATION_RESOLUTION + " TEXT, " +
    RECOMMENDATION_SCALE_X + " INT, " +
    RECOMMENDATION_SCALE_Y + " INT, " +
    RECOMMENDATION_SCALE_WIDTH + " INT, " +
    RECOMMENDATION_SCALE_HEIGHT + " INT, " +
    RECOMMENDATION_VERSION + " TEXT) ";

const std::string SEGMENTATION_AREA = "segmentation_area";
const std::string SEGMENTATION_VERSION = "segmentation_version";
const std::string CREATE_TAB_ANALYSIS_SEGMENTATION = "CREATE TABLE IF NOT EXISTS " + VISION_SEGMENTATION_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    SEGMENTATION_AREA + " TEXT, " +
    SEGMENTATION_VERSION + " TEXT) ";

const std::string COMPOSITION_ID = "composition_id";
const std::string COMPOSITION_RESOLUTION = "composition_resolution";
const std::string CLOCK_STYLE = "clock_style";
const std::string CLOCK_LOCATION_X = "clock_location_x";
const std::string CLOCK_LOCATION_Y = "clock_location_y";
const std::string CLOCK_COLOUR = "clock_colour";
const std::string COMPOSITION_SCALE_X = "composition_scale_x";
const std::string COMPOSITION_SCALE_Y = "composition_scale_y";
const std::string COMPOSITION_SCALE_WIDTH = "composition_scale_width";
const std::string COMPOSITION_SCALE_HEIGHT = "composition_iscale_height";
const std::string COMPOSITION_VERSION = "composition_version";
const std::string CREATE_TAB_ANALYSIS_COMPOSITION = "CREATE TABLE IF NOT EXISTS " + VISION_COMPOSITION_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT, " +
    COMPOSITION_ID + " INT, " +
    COMPOSITION_RESOLUTION + " TEXT, " +
    CLOCK_STYLE + " INT, " +
    CLOCK_LOCATION_X + " INT, " +
    CLOCK_LOCATION_Y + " INT, " +
    CLOCK_COLOUR + " TEXT, " +
    COMPOSITION_SCALE_X + " INT, " +
    COMPOSITION_SCALE_Y + " INT, " +
    COMPOSITION_SCALE_WIDTH + " INT, " +
    COMPOSITION_SCALE_HEIGHT + " INT, " +
    COMPOSITION_VERSION + " TEXT) ";

const std::string STATUS = "status";
const std::string OCR = "ocr";
const std::string LABEL = "label";
const std::string SALIENCY = "saliency";
const std::string OBJECT = "object";
const std::string RECOMMENDATION = "recommendation";
const std::string SEGMENTATION = "segmentation";
const std::string COMPOSITION = "composition";
const std::string FACE = "face";
const std::string CREATE_TAB_ANALYSIS_TOTAL = "CREATE TABLE IF NOT EXISTS " + VISION_TOTAL_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    STATUS + " INT, " +
    OCR + " INT, " +
    LABEL + " INT, " +
    AESTHETICS_SCORE + " INT, " +
    SALIENCY + " INT, " +
    FACE + " INT, " +
    OBJECT + " INT, " +
    RECOMMENDATION + " INT, " +
    SEGMENTATION + " INT, " +
    COMPOSITION + " INT) ";

const std::string CREATE_TAB_ANALYSIS_TOTAL_FOR_ONCREATE = "CREATE TABLE IF NOT EXISTS " + VISION_TOTAL_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    STATUS + " INT, " +
    OCR + " INT, " +
    LABEL + " INT, " +
    AESTHETICS_SCORE + " INT, " +
    FACE + " INT) ";

const std::string SHIELD_KEY = "shield_key";
const std::string SHIELD_VALUE = "shield_value";
const std::string CREATE_TAB_APPLICATION_SHIELD = "CREATE TABLE IF NOT EXISTS " + VISION_SHIELD_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    SHIELD_KEY + " TEXT, " +
    SHIELD_VALUE + " TEXT) ";

const std::string FACE_ID = "face_id";
const std::string TAG_ID = "tag_id";
const std::string SCALE_X = "scale_x";
const std::string SCALE_Y = "scale_y";
const std::string SCALE_WIDTH = "scale_width";
const std::string SCALE_HEIGHT = "scale_height";
const std::string LANDMARKS = "landmarks";
const std::string PITCH = "pitch";
const std::string YAW = "yaw";
const std::string ROLL = "roll";
const std::string TOTAL_FACES = "total_faces";
const std::string FEATURES = "features";
const std::string IMAGE_FACE_VERSION = "face_version";
const std::string IMAGE_FEATURES_VERSION = "features_version";
const std::string CREATE_TAB_IMAGE_FACE = "CREATE TABLE IF NOT EXISTS " + VISION_IMAGE_FACE_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INTEGER, " +
    FACE_ID + " TEXT, " +
    TAG_ID +  " TEXT, " +
    SCALE_X + " REAL, " +
    SCALE_Y + " REAL, " +
    SCALE_WIDTH + " REAL, " +
    SCALE_HEIGHT + " REAL, " +
    LANDMARKS + " BLOB, " +
    PITCH + " REAL, " +
    YAW + " REAL, " +
    ROLL + " REAL, " +
    PROB + " REAL, " +
    TOTAL_FACES + " INTEGER, " +
    IMAGE_FACE_VERSION + " TEXT, " +
    IMAGE_FEATURES_VERSION + " TEXT, " +
    FEATURES + " BLOB) ";

const std::string TAG_NAME = "tag_name";
const std::string GROUP_TAG = "group_tag";
const std::string RENAME_OPERATION = "rename_operation";
const std::string CENTER_FEATURES = "center_features";
const std::string TAG_VERSION = "tag_version";
const std::string USER_DISPLAY_LEVEL = "user_display_level";
const std::string TAG_ORDER = "tag_order";
const std::string IS_ME = "is_me";
const std::string COVER_URI = "cover_uri";
const std::string COUNT = "count";
const std::string DATE_MODIFY = "date_modify";
const std::string ALBUM_TYPE = "album_type";
const std::string IS_REMOVED = "is_removed";
const std::string USER_OPERATION = "user_operation";
const std::string CREATE_TAB_FACE_TAG = "CREATE TABLE IF NOT EXISTS " + VISION_FACE_TAG_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    TAG_ID +  " TEXT UNIQUE, " +
    TAG_NAME +  " TEXT, " +
    USER_OPERATION + " INTEGER, " +
    GROUP_TAG +  " TEXT, " +
    RENAME_OPERATION + " INTEGER, " +
    CENTER_FEATURES + " BLOB, " +
    TAG_VERSION + " TEXT, " +
    USER_DISPLAY_LEVEL + " INTEGER, " +
    TAG_ORDER + " INTEGER, " +
    IS_ME + " INTEGER, " +
    COVER_URI +  " TEXT, " +
    COUNT + " INTEGER, " +
    DATE_MODIFY + " BIGINT, " +
    ALBUM_TYPE + " INTEGER, " +
    IS_REMOVED + " INTEGER) ";


const std::string ALBUM_ID = "album_id";

const std::string ALBUM_SUBTYPE = "album_subtype";
const std::string ALBUM_NAME = "album_name";
const std::string DATE_MODIFIED = "date_modified";
const std::string RANK = "rank";
const std::string CREATE_ANALYSIS_ALBUM = "CREATE TABLE IF NOT EXISTS " + ANALYSIS_ALBUM_TABLE + " (" +
    ALBUM_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    ALBUM_TYPE + " INT, " +
    ALBUM_SUBTYPE + " INT, " +
    ALBUM_NAME + " TEXT, " +
    COVER_URI + " TEXT, " +
    COUNT + " INT, " +
    DATE_MODIFIED + " BIGINT, " +
    RANK + " INT) ";

const std::string MAP_ALBUM = "map_album";
const std::string MAP_ASSET = "map_asset";
const std::string CREATE_ANALYSIS_ALBUM_MAP = "CREATE TABLE IF NOT EXISTS " + ANALYSIS_PHOTO_MAP_TABLE + " (" +
    MAP_ALBUM + " INT, " +
    MAP_ASSET + " INT, " +
    "PRIMARY KEY (" + MAP_ALBUM + "," + MAP_ASSET + ")) ";

const std::string INIT_TAB_ANALYSIS_TOTAL = "INSERT INTO " + VISION_TOTAL_TABLE + " (" +
    FILE_ID + ", " +
    STATUS + ", " +
    OCR + ", " +
    AESTHETICS_SCORE + ", " +
    LABEL + ", " +
    FACE + ", " +
    SALIENCY + ", " +
    OBJECT + ", " +
    RECOMMENDATION + ", " +
    SEGMENTATION + ", " +
    COMPOSITION + ") " +
    "SELECT " + FILE_ID +
    ", CASE WHEN date_trashed > 0 THEN 2 ELSE 0 END," +
    " 0," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END," +
    " CASE WHEN subtype = 1 THEN -1 ELSE 0 END" +
    " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE MEDIA_TYPE = 1";

// trigger
const std::string CREATE_VISION_DELETE_TRIGGER = "CREATE TRIGGER IF NOT EXISTS delete_vision_trigger AFTER DELETE ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " BEGIN " +
    " UPDATE " + VISION_TOTAL_TABLE +
    " SET " + STATUS + " = -1 " +
    " WHERE " + FILE_ID +
    " = OLD.file_id;" +
    " END;";

const std::string CREATE_VISION_UPDATE_TRIGGER = "CREATE TRIGGER IF NOT EXISTS update_vision_trigger AFTER UPDATE ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN ((NEW.date_trashed > 0 AND OLD.date_trashed = 0)" +
    " OR (NEW.date_trashed = 0 AND OLD.date_trashed > 0))" +
    " AND NEW.MEDIA_TYPE = 1" +
    " BEGIN " +
    " UPDATE " + VISION_TOTAL_TABLE +
    " SET " + STATUS + " = " +
    " (CASE WHEN NEW.date_trashed > 0 THEN 2 ELSE 0 END)" +
    " WHERE file_id = OLD.file_id;" +
    " END;";

const std::string CREATE_VISION_INSERT_TRIGGER = "CREATE TRIGGER IF NOT EXISTS insert_vision_trigger AFTER INSERT ON " +
    PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN NEW.MEDIA_TYPE = 1" +
    " BEGIN " +
    " INSERT INTO " + VISION_TOTAL_TABLE +" (" +
    FILE_ID + ", " +
    STATUS + ", " +
    OCR + ", " +
    AESTHETICS_SCORE + ", " +
    LABEL + ", " +
    FACE + ", " +
    SALIENCY + ", " +
    OBJECT + ", " +
    RECOMMENDATION + ", " +
    SEGMENTATION + ", " +
    COMPOSITION + ")" +
    " VALUES (" +
    " NEW.file_id, 0, 0," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END));" +
    " END;";

const std::string URI_OCR = MEDIALIBRARY_DATA_URI + "/" + VISION_OCR_TABLE;
const std::string URI_LABEL = MEDIALIBRARY_DATA_URI + "/" + VISION_LABEL_TABLE;
const std::string URI_AESTHETICS = MEDIALIBRARY_DATA_URI + "/" + VISION_AESTHETICS_TABLE;
const std::string URI_OBJECT = MEDIALIBRARY_DATA_URI + "/" + VISION_OBJECT_TABLE;
const std::string URI_RECOMMENDATION = MEDIALIBRARY_DATA_URI + "/" + VISION_RECOMMENDATION_TABLE;
const std::string URI_SEGMENTATION = MEDIALIBRARY_DATA_URI + "/" + VISION_SEGMENTATION_TABLE;
const std::string URI_COMPOSITION = MEDIALIBRARY_DATA_URI + "/" + VISION_COMPOSITION_TABLE;
const std::string URI_TOTAL = MEDIALIBRARY_DATA_URI + "/" + VISION_TOTAL_TABLE;
const std::string URI_SHIELD = MEDIALIBRARY_DATA_URI + "/" + VISION_SHIELD_TABLE;
const std::string URI_SALIENCY = MEDIALIBRARY_DATA_URI + "/" + VISION_SALIENCY_TABLE;
const std::string URI_IMAGE_FACE = MEDIALIBRARY_DATA_URI + "/" + VISION_IMAGE_FACE_TABLE;
const std::string URI_FACE_TAG = MEDIALIBRARY_DATA_URI + "/" + VISION_FACE_TAG_TABLE;

const std::string ADD_FACE_STATUS_COLUMN = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " + FACE + " INT";
const std::string UPDATE_TOTAL_VALUE = "UPDATE " + VISION_TOTAL_TABLE + " SET " + STATUS + " = 0, " + FACE +
    " = 0 WHERE " + FILE_ID + " IN (SELECT " + FILE_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE subtype != 1)";
const std::string UPDATE_NOT_SUPPORT_VALUE = "UPDATE " + VISION_TOTAL_TABLE + " SET " + FACE +
    " = -1 WHERE " + FACE + " IS NULL";
const std::string DROP_INSERT_VISION_TRIGGER = "DROP TRIGGER IF EXISTS insert_vision_trigger";
const std::string CREATE_NEW_INSERT_VISION_TRIGGER = std::string("CREATE TRIGGER IF NOT EXISTS insert_vision_trigger") +
    " AFTER INSERT ON " + PhotoColumn::PHOTOS_TABLE + " FOR EACH ROW " +
    " WHEN NEW.MEDIA_TYPE = 1" +
    " BEGIN " +
    " INSERT INTO " + VISION_TOTAL_TABLE +
    " (" + FILE_ID + ", " + STATUS + ", " + OCR + ", " + AESTHETICS_SCORE + ", " + LABEL + ", " + FACE + ") " +
    " VALUES (" +
    " NEW.file_id, 0, 0," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END));" +
    " END;";

const std::string IMAGE_FACE_INDEX = "image_face_index";
const std::string CREATE_IMAGE_FACE_INDEX = "CREATE UNIQUE INDEX " + IMAGE_FACE_INDEX + " ON " +
    VISION_IMAGE_FACE_TABLE + " (" + FILE_ID + "," + FACE_ID + ")";

const std::string ADD_SALIENCY_STATUS_COLUMN = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " + SALIENCY + " INT";
const std::string UPDATE_SALIENCY_TOTAL_VALUE = "UPDATE " + VISION_TOTAL_TABLE +
    " SET " + STATUS + " = 0, " + SALIENCY + " = 0 WHERE " +
    FILE_ID + " IN (SELECT " + FILE_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE subtype != 1)";
const std::string UPDATE_SALIENCY_NOT_SUPPORT_VALUE = "UPDATE " + VISION_TOTAL_TABLE + " SET " + SALIENCY +
    " = -1 WHERE " + SALIENCY + " IS NULL";

const std::string OBJECT_INDEX = "object_index";
const std::string CREATE_OBJECT_INDEX = "CREATE UNIQUE INDEX " + OBJECT_INDEX + " ON " +
    VISION_OBJECT_TABLE + " (" + FILE_ID + "," + OBJECT_ID + ")";
const std::string RECOMMENDATION_INDEX = "recommendation_index";
const std::string CREATE_RECOMMENDATION_INDEX = "CREATE UNIQUE INDEX " + RECOMMENDATION_INDEX + " ON " +
    VISION_RECOMMENDATION_TABLE + " (" + FILE_ID + "," + RECOMMENDATION_ID + ")";
const std::string COMPOSITION_INDEX = "composition_index";
const std::string CREATE_COMPOSITION_INDEX = "CREATE UNIQUE INDEX " + COMPOSITION_INDEX + " ON " +
    VISION_COMPOSITION_TABLE + " (" + FILE_ID + "," + COMPOSITION_ID + ")";

const std::string AC_ADD_OBJECT_COLUMN_FOR_TOTAL = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " +
    OBJECT + " INT";
const std::string AC_ADD_RECOMMENDATION_COLUMN_FOR_TOTAL = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " +
    RECOMMENDATION + " INT";
const std::string AC_ADD_SEGMENTATION_COLUMN_FOR_TOTAL = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " +
    SEGMENTATION + " INT";
const std::string AC_ADD_COMPOSITION_COLUMN_FOR_TOTAL = "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " +
    COMPOSITION + " INT";
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_VISION_COLUMN_H