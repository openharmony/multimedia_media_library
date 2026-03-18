/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "media_compatible_info_column.h"

namespace OHOS::Media {
using namespace std;
using namespace NativeRdb;

const string TabCompatibleInfoColumn::TOKEN_ID = "token_id";
const string TabCompatibleInfoColumn::BUNDLE_NAME = "bundle_name";
const string TabCompatibleInfoColumn::HIGH_RESOLUTION = "high_resolution";
const string TabCompatibleInfoColumn::ENCODINGS = "encodings";

const string TabCompatibleInfoColumn::TABLE = "tab_compatible_info";

const string TabCompatibleInfoColumn::CREATE_TABLE = "\
    CREATE TABLE IF NOT EXISTS tab_compatible_info ( \
        bundle_name TEXT NOT NULL PRIMARY KEY, \
        high_resolution INT NOT NULL DEFAULT 0, \
        encodings TEXT \
    );";
const string TabCompatibleInfoColumn::DROP_TABLE =
    "DROP TABLE tab_compatible_info;";

const string TabCompatibleInfoColumn::CREATE_TABLE_NEW = "\
    CREATE TABLE IF NOT EXISTS tab_compatible_info ( \
        token_id INTEGER NOT NULL PRIMARY KEY, \
        high_resolution INT NOT NULL DEFAULT 0, \
        encodings TEXT \
    );";
}