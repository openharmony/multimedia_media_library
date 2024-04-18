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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_LOCATION_DB_SQLS_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_LOCATION_DB_SQLS_H

#include "location_column.h"

namespace OHOS {
namespace Media {
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
    FEATURE_NAME + " TEXT, " +
    CITY_NAME + " TEXT, " +
    ADDRESS_DESCRIPTION + " TEXT, " +
    LOCATION_TYPE + " TEXT) ";

const std::string CREATE_GEO_DICTIONARY_TABLE =
    "CREATE TABLE IF NOT EXISTS " + GEO_DICTIONARY_TABLE + " ( " +
    CITY_ID + " TEXT NOT NULL, " +
    LANGUAGE + " TEXT, " +
    CITY_NAME + " TEXT) ";

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
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_LOCATION_DB_SQLS_H