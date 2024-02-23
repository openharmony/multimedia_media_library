/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_CONST_H
#define OHOS_MEDIA_DFX_CONST_H

namespace OHOS {
namespace Media {
constexpr int32_t IMAGE_MIN = 4096;
constexpr int32_t VIDEO_8K_MIN = 7680;

constexpr int32_t FIVE_MINUTE = 5 * 60 * 1000;

constexpr int32_t COMMON_TIME_OUT = 200;
constexpr int32_t OPEN_FILE_TIME_OUT = 500;
constexpr int32_t CLOUD_DEFAULT_TIME_OUT = 100;
constexpr int32_t CLOUD_LCD_TIME_OUT = 800;
constexpr int32_t RDB_TIME_OUT = 100;

const std::string NULL_STRING = "";
const std::string OPEN_COULD_LCD = "open cloud lcd";
const std::string OPEN_COULD_DEFAULT = "open cloud default";
const std::string RDB_QUERY = "rdb query";
const std::string RDB_INSERT = "rdb insert";
const std::string RDB_DELETE = "rdb delete";
const std::string RDB_UPDATE = "rdb update";
const std::string RDB_UPDATE_BY_CMD = "rdb update by cmd";
const std::string RDB_EXECUTE_SQL = "rdb execute sql";
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_CONST_H