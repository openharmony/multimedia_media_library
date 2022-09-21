/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_CONST_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_CONST_H_

#include "medialibrary_db_const.h"

namespace OHOS {
namespace Media {
constexpr int32_t DEFAULT_THUMBNAIL_SIZE = 256;
constexpr int32_t DEFAULT_LCD_SIZE = 1080;
constexpr int32_t FULL_SCREEN_SIZE = 1920;

constexpr uint32_t DEVICE_UDID_LENGTH = 65;

constexpr int32_t THUMBNAIL_LCD_GENERATE_THRESHOLD = 2000;
constexpr int32_t THUMBNAIL_LCD_AGING_THRESHOLD = 4000;
constexpr int32_t WAIT_FOR_MS = 1000;
constexpr int32_t WAIT_FOR_SECOND = 3;

const std::string THUMBNAIL_END_SUFFIX = "_THU";
const std::string THUMBNAIL_LCD_END_SUFFIX = "_LCD";
const std::string FILE_URI_PREX = "file://";

const std::string THUMBNAIL_FORMAT = "image/jpeg";
constexpr uint8_t THUMBNAIL_QUALITY = 80;
constexpr uint32_t THUMBNAIL_QUERY_MAX = 2000;
constexpr int64_t AV_FRAME_TIME = 0;

constexpr uint8_t NUMBER_HINT_1 = 1;

const std::string THUMBNAIL_OPERN_KEYWORD = "operation";
const std::string THUMBNAIL_HEIGHT = "height";
const std::string THUMBNAIL_WIDTH = "width";
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_CONST_H_
