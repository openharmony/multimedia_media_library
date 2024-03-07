/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_FILE_ASSET_COLUMNS_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_FILE_ASSET_COLUMNS_H

#include "medialibrary_db_const.h"

namespace OHOS {
namespace Media {
// fetch columns from fileAsset in medialibrary.d.ts
static const std::vector<std::string> FILE_ASSET_COLUMNS = {
    MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_URI, MEDIA_DATA_DB_MIME_TYPE, MEDIA_DATA_DB_MEDIA_TYPE,
    MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_TITLE, MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_PARENT_ID, MEDIA_DATA_DB_SIZE,
    MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_MODIFIED, MEDIA_DATA_DB_DATE_TAKEN, MEDIA_DATA_DB_ARTIST,
    MEDIA_DATA_DB_WIDTH, MEDIA_DATA_DB_HEIGHT, MEDIA_DATA_DB_ORIENTATION, MEDIA_DATA_DB_DURATION,
    MEDIA_DATA_DB_BUCKET_ID, MEDIA_DATA_DB_BUCKET_NAME, MEDIA_DATA_DB_IS_TRASH, MEDIA_DATA_DB_IS_FAV,
    MEDIA_DATA_DB_DATE_TRASHED
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_FILE_ASSET_COLUMNS_H