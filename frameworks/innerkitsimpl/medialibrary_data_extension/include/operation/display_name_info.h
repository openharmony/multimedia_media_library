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

#ifndef OHOS_MEDIA_DISPLAY_NAME_INFO_H
#define OHOS_MEDIA_DISPLAY_NAME_INFO_H

#include <string>

#include "photo_asset_info.h"

namespace OHOS::Media {
class DisplayNameInfo {
public:
    explicit DisplayNameInfo(const PhotoAssetInfo &photoAssetInfo);
    std::string ToString();
    std::string Next();

private:
    void ParseDisplayName(const PhotoAssetInfo &photoAssetInfo);
    void ParseBurstDisplayName(const PhotoAssetInfo &photoAssetInfo);
    int32_t ToNumber(const std::string &str);
    void ParseNormalDisplayName(const PhotoAssetInfo &photoAssetInfo);
    int32_t GetPrefixStrLength(std::string yearMonthDayStr, std::string hourMinuteSecondStr);

private:
    enum {
        YEAR_MONTH_DAY_LENGTH = 8,
        HOUR_MINUTE_SECOND_LENGTH = 6,
        BURST_DISPLAY_NAME_MIN_LENGTH = 20,
        BURST_DISPLAY_NAME_YEAR_INDEX = 1,
        BURST_DISPLAY_NAME_HOUR_INDEX = 2,
        BURST_DISPLAY_NAME_MIN_SUBLINE_COUNT = 3,
        MAX_DISPLAY_NAME_LENGTH = 255,
    };
    std::string prefix;
    int32_t yearMonthDay = 0;
    int32_t hourMinuteSecond = 0;
    std::string suffix;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_DISPLAY_NAME_INFO_H