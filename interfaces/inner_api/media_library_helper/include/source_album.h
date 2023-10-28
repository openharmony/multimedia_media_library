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

#ifndef SOURCE_ALBUM_H
#define SOURCE_ALBUM_H

#include "media_column.h"
#include "photo_album_column.h"
#include "photo_map_column.h"

namespace OHOS {
namespace Media {

const std::string DROP_INSERT_SOURCE_ALBUM_TRIGGER = "DROP TRIGGER IF EXISTS insert_source_album";

const std::string DROP_UPDATE_SOURCE_ALBUM_TRIGGER = "DROP TRIGGER IF EXISTS update_source_album";

const std::string INSERT_SOURCE_ALBUM =
    "CREATE TRIGGER insert_source_album AFTER INSERT ON " + PhotoColumn::PHOTOS_TABLE +

    " WHEN ( SELECT COUNT(*) FROM " + PhotoAlbumColumns::TABLE +
    " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumType::SYSTEM) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE) + " ) = 0 " +

    " BEGIN INSERT INTO " + PhotoAlbumColumns::TABLE + "(" + PhotoAlbumColumns::ALBUM_TYPE +
    " , " + PhotoAlbumColumns::ALBUM_SUBTYPE + " , " + PhotoAlbumColumns::ALBUM_NAME +
    " ) VALUES ( " + std::to_string(OHOS::Media::PhotoAlbumType::SYSTEM) + " , " + std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE) + " , NEW." +
    MediaColumn::MEDIA_PACKAGE_NAME + ");" +
    "INSERT INTO " + PhotoMap::TABLE + "(" + PhotoMap::ALBUM_ID + " , " + PhotoMap::ASSET_ID +
    " ) VALUES ( ( SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
    " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumType::SYSTEM) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE) + "), NEW." +
    MediaColumn::MEDIA_ID + " ); END;";

const std::string UPDATE_SOURCE_ALBUM =
    "CREATE TRIGGER update_source_album AFTER INSERT ON " + PhotoColumn::PHOTOS_TABLE +
    
    " WHEN ( SELECT COUNT(*) FROM " + PhotoAlbumColumns::TABLE +
    " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumType::SYSTEM) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE) + " ) > 0 " +

    " BEGIN INSERT INTO " + PhotoMap::TABLE + "(" + PhotoMap::ALBUM_ID + " , " + PhotoMap::ASSET_ID +
    " ) VALUES ( ( SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
    " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " = NEW." + MediaColumn::MEDIA_PACKAGE_NAME + " AND " +
    PhotoAlbumColumns::ALBUM_TYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumType::SYSTEM) + " AND " +
    PhotoAlbumColumns::ALBUM_SUBTYPE + " = "+ std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE) + "), NEW." +
    MediaColumn::MEDIA_ID + " ); END;";

} // namespace Media
} // namespace OHOS


#endif // SOURCE_ALBUM_H