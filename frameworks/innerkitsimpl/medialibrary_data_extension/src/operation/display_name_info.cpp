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
#define MLOG_TAG "DisplayNameInfo"

#include "display_name_info.h"

#include <vector>
#include <regex>
#include <iomanip>

#include "userfile_manager_types.h"
#include "media_column.h"
#include "media_log.h"

namespace OHOS::Media {

// 处理重复displayName场景时，避免扩展的后缀长度超过255，截取超出的部分，保留最终总长为255
int32_t DisplayNameInfo::GetPrefixStrLength(std::string yearMonthDayStr, std::string hourMinuteSecondStr)
{
    int32_t extendLength = static_cast<int32_t>(yearMonthDayStr.size() + hourMinuteSecondStr.size()
        + this->suffix.size());
    return std::min<int32_t>(this->prefix.size(), static_cast<int32_t>(MAX_DISPLAY_NAME_LENGTH) - extendLength);
}

DisplayNameInfo::DisplayNameInfo(const PhotoAssetInfo &photoAssetInfo)
{
    ParseDisplayName(photoAssetInfo);
}

std::string DisplayNameInfo::ToString()
{
    std::string yearMonthDayStr;
    std::string hourMinuteSecondStr;
    if (this->yearMonthDay != 0) {
        std::ostringstream yearMonthDayStream;
        yearMonthDayStream << std::setw(YEAR_MONTH_DAY_LENGTH) << std::setfill('0') << this->yearMonthDay;
        std::ostringstream hourMinuteSecondStream;
        hourMinuteSecondStream << std::setw(HOUR_MINUTE_SECOND_LENGTH) << std::setfill('0') << this->hourMinuteSecond;
        yearMonthDayStr = "_" + yearMonthDayStream.str();
        hourMinuteSecondStr = "_" + hourMinuteSecondStream.str();
    } else {
        yearMonthDayStr = this->yearMonthDay == 0 ? "" : "_" + std::to_string(this->yearMonthDay);
        hourMinuteSecondStr = this->hourMinuteSecond == 0 ? "" : "_" + std::to_string(this->hourMinuteSecond);
    }
    
    return this->prefix.substr(0, GetPrefixStrLength(yearMonthDayStr, hourMinuteSecondStr))
        + yearMonthDayStr + hourMinuteSecondStr + this->suffix;
}

std::string DisplayNameInfo::Next()
{
    this->hourMinuteSecond++;
    return this->ToString();
}

void DisplayNameInfo::ParseDisplayName(const PhotoAssetInfo &photoAssetInfo)
{
    if (photoAssetInfo.subtype == static_cast<int32_t>(PhotoSubType::BURST)) {
        ParseBurstDisplayName(photoAssetInfo);
        return;
    }
    ParseNormalDisplayName(photoAssetInfo);
    return;
}

void DisplayNameInfo::ParseBurstDisplayName(const PhotoAssetInfo &photoAssetInfo)
{
    bool isValid = photoAssetInfo.subtype == static_cast<int32_t>(PhotoSubType::BURST);
    isValid = isValid && photoAssetInfo.displayName.size() > BURST_DISPLAY_NAME_MIN_LENGTH;
    if (!isValid) {
        return ParseNormalDisplayName(photoAssetInfo);
    }
    std::string displayName = photoAssetInfo.displayName;
    std::regex pattern(R"(IMG_\d{8}_\d{6}_)", std::regex_constants::icase);
    std::smatch match;
    if (!std::regex_search(displayName, match, pattern)) {
        return ParseNormalDisplayName(photoAssetInfo);
    }
    std::vector<std::string> parts;
    std::istringstream iss(displayName);
    std::string part;
    while (std::getline(iss, part, '_')) {
        parts.push_back(part);
    }
    if (parts.size() >= BURST_DISPLAY_NAME_MIN_SUBLINE_COUNT) {
        this->prefix = parts[0];
        this->yearMonthDay = this->ToNumber(parts[BURST_DISPLAY_NAME_YEAR_INDEX]);
        this->hourMinuteSecond = this->ToNumber(parts[BURST_DISPLAY_NAME_HOUR_INDEX]);
        this->suffix = displayName.substr(BURST_DISPLAY_NAME_MIN_LENGTH - 1);
    }
    MEDIA_INFO_LOG("ParseBurstDisplayName Original display name: %{public}s, BurstDisplayNameInfo: %{public}s",
        displayName.c_str(),
        this->ToString().c_str());
}

int32_t DisplayNameInfo::ToNumber(const std::string &str)
{
    char *end;
    long number = std::strtol(str.c_str(), &end, 10);

    if (*end != '\0') {
        MEDIA_ERR_LOG("ToNumber failed, has invalid char. str: %{public}s", str.c_str());
        return 0;
    } else if (number < INT_MIN || number > INT_MAX) {
        MEDIA_ERR_LOG("ToNumber failed, number overflow. str: %{public}s", str.c_str());
        return 0;
    }
    return static_cast<int32_t>(number);
}

void DisplayNameInfo::ParseNormalDisplayName(const PhotoAssetInfo &photoAssetInfo)
{
    std::string displayName = photoAssetInfo.displayName;
    size_t dotPos = displayName.rfind('.');
    if (dotPos != std::string::npos) {
        this->prefix = displayName.substr(0, dotPos);
        this->suffix = displayName.substr(dotPos);  // include dot, e.g. ".jpg"
    }
    MEDIA_INFO_LOG("ParseNormalDisplayName Original display name: %{public}s, BurstDisplayNameInfo: %{public}s",
        displayName.c_str(),
        this->ToString().c_str());
}
}  // namespace OHOS::Media