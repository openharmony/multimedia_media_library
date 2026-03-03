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

#include "download_resources_column.h"

#include <string>
#include <unordered_map>
#include "media_log.h"
#include "medialibrary_type_const.h"

namespace OHOS::Media {
using namespace std;
using namespace NativeRdb;

// DownloadResourcesTask table
const string DownloadResourcesColumn::MEDIA_ID = "file_id";
const string DownloadResourcesColumn::MEDIA_NAME = "display_name";
const string DownloadResourcesColumn::MEDIA_SIZE = "size";
const string DownloadResourcesColumn::MEDIA_URI = "uri";
const string DownloadResourcesColumn::MEDIA_DATE_ADDED = "add_time";
const string DownloadResourcesColumn::MEDIA_DATE_FINISH = "finish_time";
const string DownloadResourcesColumn::MEDIA_DOWNLOAD_STATUS = "download_status";
const string DownloadResourcesColumn::MEDIA_PERCENT = "percent";
const string DownloadResourcesColumn::MEDIA_AUTO_PAUSE_REASON = "auto_pause_reason";
const string DownloadResourcesColumn::MEDIA_COVER_LEVEL = "cover_level";

// index
const std::string DownloadResourcesColumn::IDSTATUS_INDEX = "idx_drtr_idstatus";

const std::string DownloadResourcesColumn::TABLE = "download_resources_task_records";

const std::string DownloadResourcesColumn::CREATE_TABLE = CreateTable() +
    TABLE + " (" +
    MEDIA_ID + " INTEGER PRIMARY KEY NOT NULL, " +
    MEDIA_NAME + " TEXT NOT NULL DEFAULT \"\", " +
    MEDIA_SIZE + " BIGINT NOT NULL DEFAULT -1, " +
    MEDIA_URI + " TEXT, " +
    MEDIA_DATE_ADDED + " BIGINT NOT NULL DEFAULT -1, " +
    MEDIA_DATE_FINISH + " BIGINT NOT NULL DEFAULT -1, " +
    MEDIA_DOWNLOAD_STATUS + " INT NOT NULL DEFAULT -1, " +
    MEDIA_PERCENT + " INT NOT NULL DEFAULT -1, " +
    MEDIA_AUTO_PAUSE_REASON + " INT NOT NULL DEFAULT 0, " +
    MEDIA_COVER_LEVEL + " INT NOT NULL DEFAULT 1 " +
    ")";

const std::string DownloadResourcesColumn::INDEX_DRTR_ID_STATUS =
    BaseColumn::CreateIndex() + IDSTATUS_INDEX + " ON " + DownloadResourcesColumn::TABLE +
    " (" + MEDIA_ID + "," + MEDIA_DOWNLOAD_STATUS + ");";

// CREATE TABLE IF NOT EXISTS download_resources_task_records (
//             file_id         INTEGER  PRIMARY KEY NOT NULL,
//             display_name       TEXT     NOT NULL DEFAULT "",
//             size       BIGINT NOT NULL DEFAULT -1,
//             uri        TEXT,
//             add_time      BIGINT NOT NULL DEFAULT -1,
//             finish_time     BIGINT NOT NULL DEFAULT -1,
//             download_status INT NOT NULL DEFAULT -1,
//             percent         INT NOT NULL DEFAULT -1,
//             auto_pause_reason INT NOT NULL DEFAULT 0
//         );
} // namespace OHOS::MEDIA
