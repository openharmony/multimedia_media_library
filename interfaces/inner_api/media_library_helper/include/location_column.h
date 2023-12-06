
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LOCATION_COLUMN_H
#define LOCATION_COLUMN_H

#include "base_column.h"
#include "media_column.h"
#include "userfilemgr_uri.h"
#include "userfile_manager_types.h"
#include "vision_column.h"

namespace OHOS {
namespace Media {
// location table name
const std::string GEO_DICTIONARY_TABLE = "tab_analysis_geo_dictionary";
const std::string GEO_KNOWLEDGE_TABLE = "tab_analysis_geo_knowledge";

// create location table
const std::string LATITUDE = "latitude";
const std::string LONGITUDE = "longitude";
const std::string LOCATION_KEY = "location_key";
const std::string LANGUAGE = "language";
const std::string COUNTRY = "country";
const std::string ADMIN_AREA = "admin_area";
const std::string SUB_ADMIN_AREA = "sub_admin_area";
const std::string LOCALITY = "locality";
const std::string SUB_LOCALITY = "sub_locality";
const std::string THOROUGHFARE = "thoroughfare";
const std::string SUB_THOROUGHFARE = "sub_thoroughfare";
const std::string FEATURE_NAME = "feature_name";
const std::string CITY_ID = "city_id";
const std::string CITY_NAME = "city_name";
const std::string DICTIONARY_INDEX = "dictionary_index";
const std::string KNOWLEDG_INDEX = "knowledge_index";
const std::string LOCATION_CITY_NAME_INDEX = "idx_city_name_index";
const std::string LOCATION_LOCATION_KEY_INDEX = "idx_location_key_index";

const std::string CREATE_GEO_KNOWLEDGE_TABLE =
    "CREATE TABLE IF NOT EXISTS " + GEO_KNOWLEDGE_TABLE + " ( " +
    LATITUDE + " DOUBLE, " +
    LONGITUDE + " DOUBLE, " +
    LOCATION_KEY + " INTEGER, " +
    CITY_ID + " TEXT, " +
    LANGUAGE + " TEXT NOT NULL, " +
    COUNTRY + " TEXT, " +
    ADMIN_AREA + " TEXT, " +
    SUB_ADMIN_AREA + " TEXT, " +
    LOCALITY + " TEXT, " +
    SUB_LOCALITY + " TEXT, " +
    THOROUGHFARE + " TEXT, " +
    SUB_THOROUGHFARE + " TEXT, " +
    FEATURE_NAME + " TEXT) ";

const std::string CREATE_GEO_DICTIONARY_TABLE =
    "CREATE TABLE IF NOT EXISTS " + GEO_DICTIONARY_TABLE + " ( " +
    CITY_ID + " TEXT NOT NULL, " +
    LANGUAGE + " TEXT, " +
    CITY_NAME + " TEXT) ";

const std::string URI_GEO_DICTIONARY = MEDIALIBRARY_DATA_URI + "/" + GEO_DICTIONARY_TABLE;
const std::string URI_GEO_KEOWLEDGE = MEDIALIBRARY_DATA_URI + "/" + GEO_KNOWLEDGE_TABLE;

const std::string CREATE_CITY_NAME_INDEX =
    BaseColumn::CreateIndex() + LOCATION_CITY_NAME_INDEX + " ON " + GEO_DICTIONARY_TABLE +
    " (" + LANGUAGE + " DESC," + CITY_NAME + " ASC)";

const std::string CREATE_LOCATION_KEY_INDEX =
    BaseColumn::CreateIndex() + LOCATION_LOCATION_KEY_INDEX + " ON " + GEO_KNOWLEDGE_TABLE +
    " (" + LOCATION_KEY + " DESC," + LANGUAGE + " DESC)";

const std::string CREATE_DICTIONARY_INDEX = "CREATE UNIQUE INDEX " + DICTIONARY_INDEX + " ON " +
    GEO_DICTIONARY_TABLE + " (" + CITY_ID + "," + LANGUAGE + ")";

const std::string CREATE_KNOWLEDGE_INDEX = "CREATE UNIQUE INDEX " + KNOWLEDG_INDEX + " ON " +
    GEO_KNOWLEDGE_TABLE + " (" +  LATITUDE + "," + LONGITUDE + "," + LANGUAGE + ")";

// location album param
const std::string START_LATITUDE = "startLatitude";
const std::string END_LATITUDE = "endLatitude";
const std::string START_LONGITUDE = "startLongitude";
const std::string END_LONGITUDE = "endLongitude";
const std::string DIAMETER = "diameter";

// location album result
const std::string LOCATION_ALBUM_ID = MediaColumn::MEDIA_ID + " AS " + ALBUM_ID;
const std::string LOCATION_ALBUM_NAME = LATITUDE + "||'_'||" + LONGITUDE + " AS " + ALBUM_NAME;
const std::string LOCATION_ALBUM_TYPE = std::to_string(PhotoAlbumType::SMART) + " AS " + ALBUM_TYPE;
const std::string LOCATION_ALBUM_SUBTYPE = std::to_string(PhotoAlbumSubType::GEOGRAPHY_LOCATION) +
    " AS " + ALBUM_SUBTYPE;
const std::string LOCATION_COUNT = "COUNT(*) AS " + COUNT;
const std::string LOCATION_DATE_MODIFIED = "MAX(date_modified) AS " + DATE_MODIFIED;
const std::string CITY_ALBUM_NAME =  CITY_NAME + " AS " + ALBUM_NAME;
const std::string LOCATION_COVER_URI =
    " (SELECT '" + PhotoColumn::PHOTO_URI_PREFIX + "'||" + MediaColumn::MEDIA_ID + "||" +
    "(SELECT SUBSTR(" + MediaColumn::MEDIA_FILE_PATH +
    ", (SELECT LENGTH(" + MediaColumn::MEDIA_FILE_PATH +
    ") - INSTR(reverseStr, '/') + 1) , (SELECT (SELECT LENGTH(" +
    MediaColumn::MEDIA_FILE_PATH + ") - INSTR(reverseStr, '.')) - (SELECT LENGTH(" +
    MediaColumn::MEDIA_FILE_PATH + ") - INSTR(reverseStr, '/')))) from (select " +
    " (WITH RECURSIVE reverse_string(str, revstr) AS ( SELECT " +
    MediaColumn::MEDIA_FILE_PATH + ", '' UNION ALL SELECT SUBSTR(str, 1, LENGTH(str) - 1), " +
    "revstr || SUBSTR(str, LENGTH(str), 1) FROM reverse_string WHERE LENGTH(str) > 1 ) " +
    " SELECT revstr || str FROM reverse_string WHERE LENGTH(str) = 1) as reverseStr)) ||'/'||" +
    MediaColumn::MEDIA_NAME + ") AS " + COVER_URI;
} // namespace Media
} // namespace OHOS
#endif