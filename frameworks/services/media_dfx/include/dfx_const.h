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

#include <string>

namespace OHOS {
namespace Media {
constexpr int32_t IMAGE_MIN = 4096;
constexpr int32_t VIDEO_8K_MIN = 7680;

constexpr int32_t COMMON_TIME_OUT = 200;
constexpr int32_t OPEN_FILE_TIME_OUT = 500;
constexpr int32_t CLOUD_DEFAULT_TIME_OUT = 100;
constexpr int32_t CLOUD_LCD_TIME_OUT = 800;
constexpr int32_t RDB_TIME_OUT = 100;
constexpr int32_t TO_MILLION = 1000;
constexpr int32_t ONE_MINUTE = 60;


constexpr int32_t NOT_INIT = -1;
constexpr int32_t COMMON_IMAGE = 0;
constexpr int32_t COMMON_VIDEO = 1;
constexpr int32_t OTHER_FORMAT_IMAGE = 2;
constexpr int32_t BIG_IMAGE = 3;
constexpr int32_t BIG_VIDEO = 4;

const std::string NULL_STRING = "";
const std::string SPLIT_CHAR = "|";

const std::string FIVE_MINUTE = "5";
const std::string ONE_DAY = "24";

const std::string OPEN_COULD_LCD = "open cloud lcd";
const std::string OPEN_COULD_DEFAULT = "open cloud default";
const std::string RDB_QUERY = "rdb query";
const std::string RDB_INSERT = "rdb insert";
const std::string RDB_DELETE = "rdb delete";
const std::string RDB_UPDATE = "rdb update";
const std::string RDB_UPDATE_BY_CMD = "rdb update by cmd";
const std::string RDB_EXECUTE_SQL = "rdb execute sql";

const std::string CREATE_IMAGE_SOURCE = "create image source";
const std::string GET_IMAGE_INFO = "get image info";
const std::string CREATE_PIXEL_MAP = "create pixel map";
const std::string AV_SET_SOURCE = "av set source";
const std::string AV_FETCH_FRAME = "av fetch frame";

const std::string THUMBNAIL_ERROR_XML = "/data/storage/el2/base/preferences/thumbnail_error.xml";
const std::string DFX_COMMON_XML = "/data/storage/el2/base/preferences/dfx_common.xml";
const std::string LAST_REPORT_TIME = "last_report_time";

const std::string CLOUD_APTH = "/storage/cloud/files/Photo";
const std::string GARBLE = "*";

struct ThumbnailErrorInfo {
    std::string method;
    int32_t errCode;
    int32_t time;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_CONST_H