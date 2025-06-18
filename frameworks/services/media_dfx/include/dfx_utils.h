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

#ifndef OHOS_MEDIA_DFX_UTILS_H
#define OHOS_MEDIA_DFX_UTILS_H

#include <codecvt>
#include <string>
#include <unordered_set>
#include <vector>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class DfxUtils {
public:
    static std::vector<std::string> Split(std::string &input, const std::string &pattern);
    static std::string GetSafePath(const std::string &path);
    EXPORT static std::string GetSafeUri(const std::string &uri);
    static std::string GetCurrentDate();
    static std::string GetCurrentDateMillisecond();
    static std::string JoinStrings(const std::unordered_set<std::string>& strSet, char delimiter);
    static std::unordered_set<std::string> SplitString(const std::string& input, char delimiter);
    EXPORT static std::string GetSafeAlbumName(const std::string &value);
    static std::string GetSafeAlbumNameWhenChinese(const std::string &albumName);
    static std::string GetSafeDiaplayNameWhenChinese(const std::string &displayName);
    static std::u16string Str8ToStr16(const std::string &inputStr);
    static std::string Str16ToStr8(const std::u16string &inputStr);

private:
    static std::string GetSafeDiaplayName(std::string &displayName);
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_UTILS_H