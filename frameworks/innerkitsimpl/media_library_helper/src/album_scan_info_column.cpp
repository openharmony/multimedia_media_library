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

#include "album_scan_info_column.h"

namespace OHOS {
namespace Media {
const std::string AlbumScanInfoColumn::TABLE = "AlbumScanInfo";
const std::string AlbumScanInfoColumn::ID = "id";
const std::string AlbumScanInfoColumn::ALBUM_ID = "album_id";
const std::string AlbumScanInfoColumn::STORAGE_PATH = "storage_path";
const std::string AlbumScanInfoColumn::FOLDER_DATE_MODIFIED = "folder_date_modified";

const std::string AlbumScanInfoColumn::CREATE_TABLE = "CREATE TABLE IF NOT EXISTS AlbumScanInfo ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "album_id INTEGER NOT NULL, "
    "storage_path TEXT NOT NULL COLLATE NOCASE, "
    "folder_date_modified BIGINT DEFAULT 0 NOT NULL);";
const std::string AlbumScanInfoColumn::CREATE_INDEX_ON_ALBUM_ID_STORAGE_PATH =
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_AlbumScanInfo_album_id_storage_path ON AlbumScanInfo (album_id, "
    "storage_path COLLATE NOCASE);";
} // namespace Media
} // namespace OHOS