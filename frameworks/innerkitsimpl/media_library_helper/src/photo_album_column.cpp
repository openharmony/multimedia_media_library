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

#include "photo_album_column.h"

#include "photo_map_column.h"

namespace OHOS::Media {
// PhotoAlbum table
const std::string PhotoAlbumColumns::TABLE = "PhotoAlbum";
const std::string PhotoAlbumColumns::ALBUM_ID = "album_id";
const std::string PhotoAlbumColumns::ALBUM_TYPE = "album_type";
const std::string PhotoAlbumColumns::ALBUM_SUBTYPE = "album_subtype";
const std::string PhotoAlbumColumns::ALBUM_NAME = "album_name";
const std::string PhotoAlbumColumns::ALBUM_COVER_URI = "cover_uri";
const std::string PhotoAlbumColumns::ALBUM_COUNT = "count";
// For api9 compatibility
const std::string PhotoAlbumColumns::ALBUM_RELATIVE_PATH = "relative_path";

const std::string PhotoAlbumColumns::ALBUM_URI_PREFIX = "file://media/album/";

// Create tables
const std::string PhotoAlbumColumns::CREATE_TABLE = CreateTable() +
    TABLE + " (" +
    ALBUM_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    ALBUM_TYPE + " INT, " +
    ALBUM_SUBTYPE + " INT, " +
    ALBUM_NAME + " TEXT, " +
    ALBUM_COVER_URI + " TEXT, " +
    ALBUM_COUNT + " INT DEFAULT 0, " +
    ALBUM_RELATIVE_PATH + " TEXT)";

// Create indexes
const std::string PhotoAlbumColumns::INDEX_ALBUM_TYPES = CreateIndex() + "photo_album_types" + " ON " + TABLE +
    " (" + ALBUM_TYPE + "," + ALBUM_SUBTYPE + ");";
} // namespace OHOS::Media
