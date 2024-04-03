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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIALIBRARY_BUSINESS_RECORD_COLUMN_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIALIBRARY_BUSINESS_RECORD_COLUMN_H

#include <string>

#include "base_column.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MedialibraryBusinessRecordColumn : BaseColumn {
public:
    // columns only in PhotoAlbumTable
    static const std::string BUSINESS_TYPE EXPORT;
    static const std::string KEY EXPORT;
    static const std::string VALUE EXPORT;

    // table name
    static const std::string TABLE EXPORT;
    // create table sql
    static const std::string CREATE_TABLE EXPORT;

    // index name
    static const std::string BUSINESS_TYPE_INDEX EXPORT;

    //create unique index
    static const std::string CREATE_BUSINESS_KEY_INDEX EXPORT;
};
} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIALIBRARY_BUSINESS_RECORD_COLUMN_H