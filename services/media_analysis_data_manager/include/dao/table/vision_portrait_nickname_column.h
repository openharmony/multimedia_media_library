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

#ifndef OHOS_MEDIA_VISION_PORTRAIT_NICKNAME_COLUMN_H
#define OHOS_MEDIA_VISION_PORTRAIT_NICKNAME_COLUMN_H

#include <string>

namespace OHOS {
namespace Media {
#define ANALYSIS_NICK_NAME_TABLE "tab_analysis_nick_name"
#define NICK_NAME "nick_name"
#define PORTRAIT_NICKNAME_DELETE_TRIGGER "portrait_nickname_delete_trigger"
#define ANALYSIS_NICK_NAME_UNIQUE_INDEX "idx_analysis_nick_name_album_id_nick_name"

const std::string CREATE_ANALYSIS_NICK_NAME_TABLE = "\
    CREATE TABLE IF NOT EXISTS tab_analysis_nick_name (\
        album_id INTEGER NOT NULL, \
        nick_name TEXT NOT NULL\
    );";

const std::string CREATE_ANALYSIS_NICK_NAME_UNIQUE_INDEX = "\
    CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_nick_name_album_id_nick_name \
    ON tab_analysis_nick_name (album_id, nick_name);";

const std::string CREATE_ANALYSIS_NICK_NAME_DELETE_TRIGGER = "\
    CREATE TRIGGER IF NOT EXISTS portrait_nickname_delete_trigger \
    AFTER DELETE ON AnalysisAlbum \
    FOR EACH ROW WHEN OLD.album_subtype = 4102 \
    BEGIN \
        DELETE FROM tab_analysis_nick_name WHERE album_id = OLD.album_id; \
    END;";
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIA_VISION_PORTRAIT_NICKNAME_COLUMN_H
