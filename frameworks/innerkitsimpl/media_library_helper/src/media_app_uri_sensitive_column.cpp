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

#include "media_app_uri_sensitive_column.h"
#include "media_column.h"
#include "base_column.h"

namespace OHOS {
namespace Media {

const std::string AppUriSensitiveColumn::ID = "id";
const std::string AppUriSensitiveColumn::APP_ID = "appid";
const std::string AppUriSensitiveColumn::FILE_ID = "file_id";
const std::string AppUriSensitiveColumn::URI_TYPE = "uri_type";
const std::string AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE = "sensitive_type";
const std::string AppUriSensitiveColumn::DATE_MODIFIED = "date_modified";

const int AppUriSensitiveColumn::URI_PHOTO = 1;
const int AppUriSensitiveColumn::URI_AUDIO = 2;
const std::set<int> AppUriSensitiveColumn::URI_TYPES_ALL = {
    AppUriSensitiveColumn::URI_PHOTO, AppUriSensitiveColumn::URI_AUDIO};

const int AppUriSensitiveColumn::SENSITIVE_ALL_DESENSITIZE = 0;
const int AppUriSensitiveColumn::SENSITIVE_GEOGRAPHIC_LOCATION_DESENSITIZE = 1;
const int AppUriSensitiveColumn::SENSITIVE_SHOOTING_PARAM_DESENSITIZE = 2;
const int AppUriSensitiveColumn::SENSITIVE_NO_DESENSITIZE = 3;
const std::set<int> AppUriSensitiveColumn::SENSITIVE_TYPES_ALL = {
    AppUriSensitiveColumn::SENSITIVE_ALL_DESENSITIZE,
    AppUriSensitiveColumn::SENSITIVE_GEOGRAPHIC_LOCATION_DESENSITIZE,
    AppUriSensitiveColumn::SENSITIVE_SHOOTING_PARAM_DESENSITIZE,
    AppUriSensitiveColumn::SENSITIVE_NO_DESENSITIZE};

const std::string AppUriSensitiveColumn::URI_URITYPE_APPID_INDEX = "uri_uritype_appid_index";

const std::string AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE = "UriSensitive";

const std::set<std::string> AppUriSensitiveColumn::DEFAULT_FETCH_COLUMNS = {AppUriSensitiveColumn::ID};

const std::string AppUriSensitiveColumn::CREATE_APP_URI_SENSITIVE_TABLE =
    "CREATE TABLE IF NOT EXISTS " + AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE + "(" +
    AppUriSensitiveColumn::ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    AppUriSensitiveColumn::APP_ID + " TEXT, " + AppUriSensitiveColumn::FILE_ID + " INTEGER, " +
    AppUriSensitiveColumn::URI_TYPE + " INTEGER, " + AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE + " INTEGER, " +
    AppUriSensitiveColumn::DATE_MODIFIED + " BIGINT)";

const std::string AppUriSensitiveColumn::CREATE_URI_URITYPE_APPID_INDEX = BaseColumn::CreateIndex() +
    AppUriSensitiveColumn::URI_URITYPE_APPID_INDEX + " ON " +
    AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE + " (" +
    AppUriSensitiveColumn::FILE_ID + " DESC," +
    AppUriSensitiveColumn::URI_TYPE + "," +
    AppUriSensitiveColumn::APP_ID + " DESC)";

const std::string AppUriSensitiveColumn::DELETE_APP_URI_SENSITIVE_TABLE =
    "DELETE FROM " + AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE;

const std::set<std::string> AppUriSensitiveColumn::ALL_COLUMNS = {
    AppUriSensitiveColumn::ID, AppUriSensitiveColumn::APP_ID, AppUriSensitiveColumn::FILE_ID,
    AppUriSensitiveColumn::URI_TYPE, AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE,
    AppUriSensitiveColumn::DATE_MODIFIED
};
} // namespace Media
} // namespace OHOS