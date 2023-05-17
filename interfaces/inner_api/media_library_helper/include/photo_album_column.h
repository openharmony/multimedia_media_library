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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ALBUM_COLUMN_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ALBUM_COLUMN_H

#include <set>
#include <string>

#include "base_column.h"

namespace OHOS::Media {
class PhotoAlbumColumns : BaseColumn {
public:
    // columns only in PhotoAlbumTable
    static const std::string ALBUM_ID;
    static const std::string ALBUM_TYPE;
    static const std::string ALBUM_SUBTYPE;
    static const std::string ALBUM_NAME;
    static const std::string ALBUM_COVER_URI;
    static const std::string ALBUM_COUNT;
    static const std::string ALBUM_DATE_MODIFIED;

    // For api9 compatibility
    static const std::string ALBUM_RELATIVE_PATH;
    // default fetch columns
    static const std::set<std::string> DEFAULT_FETCH_COLUMNS;

    // table name
    static const std::string TABLE;
    // create PhotoAlbumTable sql
    static const std::string CREATE_TABLE;

    // create indexes for PhotoAlbum
    static const std::string INDEX_ALBUM_TYPES;

    // util constants
    static const std::string ALBUM_URI_PREFIX;

    static bool IsPhotoAlbumColumn(const std::string &columnName);
};
} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ALBUM_COLUMN_H
