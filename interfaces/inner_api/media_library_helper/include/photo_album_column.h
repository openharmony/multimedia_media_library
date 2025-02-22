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
#include "rdb_predicates.h"
#include "userfile_manager_types.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class PhotoAlbumColumns : BaseColumn {
public:
    // columns only in PhotoAlbumTable
    static const std::string ALBUM_ID EXPORT;
    static const std::string ALBUM_TYPE EXPORT;
    static const std::string ALBUM_SUBTYPE EXPORT;
    static const std::string ALBUM_NAME EXPORT;
    static const std::string ALBUM_COVER_URI EXPORT;
    static const std::string ALBUM_COUNT EXPORT;
    static const std::string ALBUM_DATE_MODIFIED EXPORT;
    static const std::string ALBUM_DIRTY EXPORT;
    static const std::string ALBUM_CLOUD_ID EXPORT;
    static const std::string ALBUM_IMAGE_COUNT EXPORT;
    static const std::string ALBUM_VIDEO_COUNT EXPORT;
    static const std::string ALBUM_LATITUDE EXPORT;
    static const std::string ALBUM_LONGITUDE EXPORT;
    static const std::string ALBUM_BUNDLE_NAME EXPORT;
    static const std::string ALBUM_LOCAL_LANGUAGE EXPORT;
    static const std::string ALBUM_IS_LOCAL EXPORT;
    static const std::string ALBUM_DATE_ADDED EXPORT;
    static const std::string ALBUM_PRIORITY EXPORT;
    static const std::string ALBUM_LPATH EXPORT;
    static const std::string ALBUM_CHECK_FLAG EXPORT;
    // For api9 compatibility
    static const std::string ALBUM_RELATIVE_PATH EXPORT;

    static const std::string CONTAINS_HIDDEN EXPORT;
    static const std::string HIDDEN_COUNT EXPORT;
    static const std::string HIDDEN_COVER EXPORT;

    // For sorting albums
    static const std::string ALBUM_ORDER EXPORT;
    static const std::string REFERENCE_ALBUM_ID EXPORT;
    // default fetch columns
    static const std::set<std::string> DEFAULT_FETCH_COLUMNS EXPORT;
    static const std::vector<std::string> LOCATION_DEFAULT_FETCH_COLUMNS EXPORT;
    static const std::vector<std::string> CITY_DEFAULT_FETCH_COLUMNS EXPORT;

    // table name
    static const std::string TABLE EXPORT;
    // create PhotoAlbumTable sql
    static const std::string CREATE_TABLE EXPORT;

    // create indexes for PhotoAlbum
    static const std::string INDEX_ALBUM_TYPES EXPORT;

    // create triggers
    static const std::string CREATE_ALBUM_INSERT_TRIGGER EXPORT;
    static const std::string CREATE_ALBUM_MDIRTY_TRIGGER EXPORT;
    static const std::string CREATE_ALBUM_DELETE_TRIGGER EXPORT;
    static const std::string ALBUM_DELETE_ORDER_TRIGGER EXPORT;
    static const std::string ALBUM_INSERT_ORDER_TRIGGER EXPORT;

    // util constants
    static const std::string ALBUM_URI_PREFIX EXPORT;
    static const std::string DEFAULT_PHOTO_ALBUM_URI EXPORT;
    static const std::string HIDDEN_ALBUM_URI_PREFIX EXPORT;
    static const std::string DEFAULT_HIDDEN_ALBUM_URI EXPORT;
    static const std::string ANALYSIS_ALBUM_URI_PREFIX EXPORT;

    // cloud sync uri
    static const std::string ALBUM_CLOUD_URI_PREFIX EXPORT;
    static const std::string ALBUM_GALLERY_CLOUD_URI_PREFIX EXPORT;
    static const std::string PHOTO_GALLERY_CLOUD_SYNC_INFO_URI_PREFIX EXPORT;

    EXPORT static bool IsPhotoAlbumColumn(const std::string &columnName);

    EXPORT static void GetUserAlbumPredicates(const int32_t albumId, NativeRdb::RdbPredicates &predicates,
        const bool hiddenState);
    EXPORT static void GetSystemAlbumPredicates(const PhotoAlbumSubType subType, NativeRdb::RdbPredicates &predicates,
        const bool hiddenState);
    EXPORT static void GetAnalysisAlbumPredicates(const int32_t albumId, NativeRdb::RdbPredicates &predicates,
        const bool hiddenState);
    EXPORT static void GetPortraitAlbumPredicates(const int32_t albumId, NativeRdb::RdbPredicates &predicates,
        const bool hiddenState);
    EXPORT static void GetSourceAlbumPredicates(const int32_t albumId, NativeRdb::RdbPredicates &predicates,
        const bool hiddenState);
    EXPORT static std::string CheckUploadPhotoAlbumColumns();
};
} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ALBUM_COLUMN_H
