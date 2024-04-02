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

#include "medialibrary_business_record_column.h"

namespace OHOS::Media {
using namespace std;

// MedialibraryBusinessRecordColumn table
const string MedialibraryBusinessRecordColumn::TABLE = "tab_medialibrary_business_record";
const string MedialibraryBusinessRecordColumn::BUSINESS_TYPE = "business_type";
const string MedialibraryBusinessRecordColumn::KEY = "key";
const string MedialibraryBusinessRecordColumn::VALUE = "value";

// index name
const string MedialibraryBusinessRecordColumn::BUSINESS_TYPE_INDEX = "business_key_index";

// Create tables
const string MedialibraryBusinessRecordColumn::CREATE_TABLE = CreateTable() +
    TABLE + " (" +
    BUSINESS_TYPE + " TEXT, " +
    KEY + " TEXT, " +
    VALUE + " TEXT)";

const string MedialibraryBusinessRecordColumn::CREATE_BUSINESS_KEY_INDEX = "CREATE UNIQUE INDEX IF NOT EXISTS " +
    BUSINESS_TYPE_INDEX + " ON " +
    TABLE + " (" + BUSINESS_TYPE + "," + KEY + "," + VALUE + ")";
} // namespace OHOS::Media