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
const std::string VISION_TOTAL_TABLE = "tab_analysis_total";
const std::string VISION_SHIELD_TABLE = "tab_application_shield";

// create vision table
const std::string ID = "id";
const std::string FILE_ID = "file_id";
const std::string OCR_TEXT = "ocr_text";
const std::string OCR_VERSION = "ocr_version";
const std::string OCR_TEXT_MSG = "ocr_text_msg";
const std::string CREATE_TAB_ANALYSIS_OCR = "CREATE TABLE IF NOT EXISTS " + VISION_OCR_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    OCR_TEXT + " TEXT, " +
    OCR_VERSION + " TEXT, " +
    OCR_TEXT_MSG + " TEXT) ";

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

const std::string STATUS = "status";
const std::string OCR = "ocr";
const std::string LABEL = "label";
const std::string CREATE_TAB_ANALYSIS_TOTAL = "CREATE TABLE IF NOT EXISTS " + VISION_TOTAL_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    FILE_ID + " INT UNIQUE, " +
    STATUS + " INT, " +
    OCR + " INT, " +
    LABEL + " INT, " +
    AESTHETICS_SCORE + " INT) ";

const std::string SHIELD_KEY = "shield_key";
const std::string SHIELD_VALUE = "shield_value";
const std::string CREATE_TAB_APPLICATION_SHIELD = "CREATE TABLE IF NOT EXISTS " + VISION_SHIELD_TABLE + " (" +
    ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    SHIELD_KEY + " TEXT, " +
    SHIELD_VALUE + " TEXT) ";

const std::string INIT_TAB_ANALYSIS_TOTAL = "INSERT INTO " + VISION_TOTAL_TABLE + " (" +
    FILE_ID + ", " + STATUS + ", " + OCR + ", " + AESTHETICS_SCORE + ", " + LABEL + ") " +
    "SELECT " + FILE_ID +
    ", CASE WHEN date_trashed > 0 THEN 2 ELSE 0 END," +
    " 0," +
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
    " INSERT INTO " + VISION_TOTAL_TABLE +
    " (" + FILE_ID + ", " + STATUS + ", " + OCR + ", " +
    AESTHETICS_SCORE + ", " + LABEL + ")" +
    " VALUES (" +
    " NEW.file_id, 0, 0," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END)," +
    " (CASE WHEN NEW.subtype = 1 THEN -1 ELSE 0 END));" +
    " END;";

const std::string URI_OCR = MEDIALIBRARY_DATA_URI + "/" + VISION_OCR_TABLE;
const std::string URI_LABEL = MEDIALIBRARY_DATA_URI + "/" + VISION_LABEL_TABLE;
const std::string URI_AESTHETICS = MEDIALIBRARY_DATA_URI + "/" + VISION_AESTHETICS_TABLE;
const std::string URI_TOTAL = MEDIALIBRARY_DATA_URI + "/" + VISION_TOTAL_TABLE;
const std::string URI_SHIELD = MEDIALIBRARY_DATA_URI + "/" + VISION_SHIELD_TABLE;
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_VISION_COLUMN_H