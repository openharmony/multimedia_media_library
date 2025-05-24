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

#define MLOG_TAG "Media_Cloud_Utils"

#include "cloud_media_dao_utils.h"

#include <sstream>

#include "medialibrary_data_manager_utils.h"

namespace OHOS::Media::CloudSync {
std::string CloudMediaDaoUtils::ToStringWithCommaAndQuote(const std::vector<std::string> &values)
{
    std::stringstream os;
    for (size_t i = 0; i < values.size(); ++i) {
        os << "'" << values[i] << "'";
        if (i != values.size() - 1) {
            os << ",";
        }
    }
    return os.str();
}

std::string CloudMediaDaoUtils::ToStringWithComma(const std::vector<std::string> &fileIds)
{
    std::stringstream os;
    for (size_t i = 0; i < fileIds.size(); ++i) {
        os << fileIds[i];
        if (i != fileIds.size() - 1) {
            os << ",";
        }
    }
    return os.str();
}

std::string CloudMediaDaoUtils::FillParams(const std::string &sql, const std::vector<std::string> &bindArgs)
{
    std::stringstream os;
    std::string flag;
    const std::string leftBrace = "{";
    const std::string rightBrace = "}";
    std::string val;
    std::string result = sql;
    for (size_t i = 0; i < bindArgs.size(); i++) {
        flag = leftBrace + std::to_string(i) + rightBrace;
        val = bindArgs[i];
        size_t pos = result.find(flag);
        while (pos != std::string::npos) {
            os.str("");
            os << result.substr(0, pos) << bindArgs[i];
            os << result.substr(pos + flag.length());
            result = os.str();
            os.str("");
            pos = result.find(flag);
        }
    }
    return result;
}

std::vector<std::string> CloudMediaDaoUtils::GetNumbers(const std::vector<std::string> &albumIds)
{
    std::vector<std::string> numbers;
    bool isNumber = false;
    for (const auto &albumId : albumIds) {
        isNumber = MediaLibraryDataManagerUtils::IsNumber(albumId);
        if (!isNumber) {
            continue;
        }
        numbers.emplace_back(albumId);
    }
    return numbers;
}

std::vector<std::string> CloudMediaDaoUtils::GetStringVector(const std::vector<int32_t> &intVals)
{
    std::vector<std::string> strVals;
    for (auto &val : intVals) {
        strVals.emplace_back(std::to_string(val));
    }
    return strVals;
}
}  // namespace OHOS::Media::CloudSync