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

#ifndef OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H
#define OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H

#include <string>
#include <vector>
#include <regex>
#include <sstream>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_column.h"
#include "media_log.h"

namespace OHOS::Media {
class PhotoDisplayNameOperation {
private:
    struct PhotoAssetInfo {
        std::string displayName;
        int32_t subtype;
        int32_t ownerAlbumId;
    };
    class DisplayNameInfo {
    public:
        explicit DisplayNameInfo(const PhotoAssetInfo &photoAssetInfo)
        {
            ParseDisplayName(photoAssetInfo);
        }

        std::string ToString()
        {
            std::string yearMonthDayStr;
            std::string hourMinuteSecondStr;
            if (this->yearMonthDay != 0 && this->hourMinuteSecond != 0) {
                std::ostringstream yearMonthDayStream;
                yearMonthDayStream << std::setw(YEAR_MONTH_DAY_LENGTH) << std::setfill('0') << this->yearMonthDay;
                std::ostringstream hourMinuteSecondStream;
                hourMinuteSecondStream << std::setw(HOUR_MINUTE_SECOND_LENGTH) << std::setfill('0')
                                       << this->hourMinuteSecond;
                yearMonthDayStr = "_" + yearMonthDayStream.str();
                hourMinuteSecondStr = "_" + hourMinuteSecondStream.str();
            } else {
                yearMonthDayStr = this->yearMonthDay == 0 ? "" : "_" + std::to_string(this->yearMonthDay);
                hourMinuteSecondStr = this->hourMinuteSecond == 0 ? "" : "_" + std::to_string(this->hourMinuteSecond);
            }
            return this->prefix + yearMonthDayStr + hourMinuteSecondStr + this->suffix;
        }

        std::string Next()
        {
            this->hourMinuteSecond++;
            return this->ToString();
        }

    private:
        void ParseDisplayName(const PhotoAssetInfo &photoAssetInfo)
        {
            if (photoAssetInfo.subtype == static_cast<int32_t>(PhotoSubType::BURST)) {
                ParseBurstDisplayName(photoAssetInfo);
                return;
            }
            ParseNormalDisplayName(photoAssetInfo);
            return;
        }

        void ParseBurstDisplayName(const PhotoAssetInfo &photoAssetInfo)
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

        int32_t ToNumber(const std::string &str)
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

        void ParseNormalDisplayName(const PhotoAssetInfo &photoAssetInfo)
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

    private:
        enum {
            YEAR_MONTH_DAY_LENGTH = 8,
            HOUR_MINUTE_SECOND_LENGTH = 6,
            BURST_DISPLAY_NAME_MIN_LENGTH = 20,
            BURST_DISPLAY_NAME_YEAR_INDEX = 1,
            BURST_DISPLAY_NAME_HOUR_INDEX = 2,
            BURST_DISPLAY_NAME_MIN_SUBLINE_COUNT = 3
        };
        std::string prefix;
        int32_t yearMonthDay;
        int32_t hourMinuteSecond;
        std::string suffix;
    };

public:
    std::string FindDisplayName(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const int32_t targetAlbumId,
        const std::string displayName = "")
    {
        if (resultSet == nullptr || targetAlbumId <= 0) {
            MEDIA_ERR_LOG("Media_Operation: FindBurstKey: resultSet is null or targetAlbumId is invalid");
            return "";
        }
        // Build the photo asset info.
        PhotoDisplayNameOperation::PhotoAssetInfo photoAssetInfo;
        photoAssetInfo.displayName =
            displayName == "" ? GetStringVal(MediaColumn::MEDIA_NAME, resultSet) : displayName;
        photoAssetInfo.subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
        photoAssetInfo.ownerAlbumId = targetAlbumId;
        return this->FindDislayName(rdbStore, photoAssetInfo);
    }

private:
    std::string FindDislayName(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const PhotoAssetInfo &photoAssetInfo)
    {
        DisplayNameInfo displayNameInfo(photoAssetInfo);
        std::string displayName = displayNameInfo.ToString();
        int32_t retryCount = 0;
        const int32_t MAX_RETRY_COUNT = 100;
        while (IsDisplayNameExists(rdbStore, photoAssetInfo.ownerAlbumId, displayName)) {
            displayName = displayNameInfo.Next();
            if (retryCount++ > MAX_RETRY_COUNT) {
                MEDIA_ERR_LOG("Media_Operation: can not find unique display after retry %{public}d", MAX_RETRY_COUNT);
                break;
            }
        }
        if (photoAssetInfo.displayName != displayName) {
            MEDIA_INFO_LOG("Media_Operation: displayName changed from %{public}s to %{public}s",
                photoAssetInfo.displayName.c_str(),
                displayName.c_str());
        }
        return displayName;
    }

    bool IsDisplayNameExists(const std::shared_ptr<MediaLibraryRdbStore> rdbStore, const int32_t ownerAlbumId,
        const std::string &displayName)
    {
        if (ownerAlbumId <= 0 || displayName.empty()) {
            return false;
        }
        std::string querySql = this->SQL_PHOTOS_TABLE_QUERY_DISPLAY_NAME;
        const std::vector<NativeRdb::ValueObject> bindArgs = {ownerAlbumId, displayName};
        auto resultSet = rdbStore->QuerySql(querySql, bindArgs);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            return false;
        }
        std::string displayNameInDb = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        return displayNameInDb.size() > 0;
    }

private:
    const std::string SQL_PHOTOS_TABLE_QUERY_DISPLAY_NAME = "\
        SELECT \
            display_name \
        FROM Photos \
        WHERE owner_album_id = ? \
            AND LOWER(display_name) = LOWER(?) \
        LIMIT 1;";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H