
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_COVER_INFO_COLUMN_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_COVER_INFO_COLUMN_H

#include <string>

namespace OHOS {
namespace Media {
// story cover info table name
const std::string STORY_COVER_INFO_TABLE = "tab_story_cover_info";

// create story cover info table
const std::string RATIO = "ratio";
const std::string BACKGROUND = "background";
const std::string FOREGROUND = "foreground";
const std::string WORDART = "wordart";
const std::string IS_COVERED = "is_covered";
const std::string COLOR = "color";
const std::string RADIUS = "radius";
const std::string SATURATION = "saturation";
const std::string BRIGHTNESS = "brightness";
const std::string TITIE_SCALE_X = "titie_scale_x";
const std::string TITIE_SCALE_Y = "titie_scale_y";
const std::string TITIE_RECT_WIDTH = "titie_rect_width";
const std::string TITIE_RECT_HEIGHT = "titie_rect_height";
const std::string BACKGROUND_SCALE_X = "background_scale_x";
const std::string BACKGROUND_SCALE_Y = "background_scale_y";
const std::string BACKGROUND_RECT_WIDTH = "background_rect_width";
const std::string BACKGROUND_RECT_HEIGHT  = "background_rect_height";
const std::string IS_CHOSEN = "is_chosen";
const std::string COVER_ALGO_VERSION = "cover_algo_version";

const std::string URI_STORY_COVER_INFO = MEDIALIBRARY_DATA_URI + "/" + STORY_COVER_INFO_TABLE;
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_STORY_COVER_INFO_COLUMN_H