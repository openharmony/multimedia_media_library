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

#include "media_config_info_column.h"

namespace OHOS {
namespace Media {
const std::string ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME = "ConfigInfo";
const std::string ConfigInfoColumn::MEDIA_CONFIG_INFO_SCENE_ID = "scene_id";
const std::string ConfigInfoColumn::MEDIA_CONFIG_INFO_KEY = "key";
const std::string ConfigInfoColumn::MEDIA_CONFIG_INFO_VALUE = "value";

const std::string ConfigInfoColumn::CREATE_CONFIG_INFO_TABLE =
    "CREATE TABLE IF NOT EXISTS " + MEDIA_CONFIG_INFO_TABLE_NAME + " ( " +
        MEDIA_CONFIG_INFO_SCENE_ID + " INT NOT NULL," +
        MEDIA_CONFIG_INFO_KEY + " TEXT NOT NULL," +
        MEDIA_CONFIG_INFO_VALUE + " TEXT NOT NULL," +
        "UNIQUE(" + MEDIA_CONFIG_INFO_SCENE_ID + ", " + MEDIA_CONFIG_INFO_KEY + ")" +
    ");";
}  // namespace Media
}  // namespace OHOS