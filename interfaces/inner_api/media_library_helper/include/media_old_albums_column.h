/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_OLD_ALBUMS_COLUMNS_H
#define FRAMEWORKS_SERVICES_MEDIA_OLD_ALBUMS_COLUMNS_H


#include <string>
#include <set>

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))

namespace TabOldAlbumsColumn {
    static const std::string MEDIA_URI = "file://media";
    static const std::string ALBUM_ANALYSIS_TAB = "AnalysisAlbum";
    static const std::string ALBUM_PHOTO_TAB = "PhotoAlbum";
    static const std::string PHOTO_ALBUM_PREFIX =  MEDIA_URI + "/" + ALBUM_PHOTO_TAB + "/";
    static const std::string ANALYSIS_ALBUM_PREFIX = MEDIA_URI + "/" + ALBUM_ANALYSIS_TAB + "/";

    // table name
    static const std::string OLD_ALBUM_TABLE = "tab_old_albums";

    static const std::string OLD_ALBUM_ID = "old_album_id";
    static const std::string ALBUM_ID = "album_id";
    static const std::string ALBUM_TYPE = "album_type";
    static const std::string ALBUM_SUBTYPE = "album_subtype";
    static const std::string CLONE_SEQUENCE = "clone_sequence";
    static const char IS_ANALYSIS_TABLE = '4';

    struct RawData {
        int32_t old_album_id;
        int32_t album_id;
        int32_t album_type;
        int32_t album_subtype;
        int32_t clone_sequence;
        std::string inputAlbumName;
        bool IsNotFound = false;
    };
}


} // namespace Media
} // namespace OHOS
#endif