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

#ifndef ALBUM_SCAN_INFO_COLUMN_H
#define ALBUM_SCAN_INFO_COLUMN_H

#include <string>

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))

class AlbumScanInfoColumn {
public:
    static const std::string TABLE EXPORT;
    static const std::string ID EXPORT;
    static const std::string ALBUM_ID EXPORT;
    static const std::string STORAGE_PATH EXPORT;
    static const std::string FOLDER_DATE_MODIFIED EXPORT;

    static const std::string CREATE_TABLE EXPORT;
    static const std::string CREATE_INDEX_ON_ALBUM_ID_STORAGE_PATH EXPORT;
};
} // namespace Media
} // namespace OHOS
#endif  // ALBUM_SCAN_INFO_COLUMN_H