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

#include "dfx_utils.h"

#include "dfx_const.h"
#include "media_file_utils.h"
using namespace std;
namespace OHOS {
namespace Media {
vector<string> DfxUtils::Split(string &input, const string &pattern)
{
    vector<string> result;
    if (input == "") {
        return result;
    }
    string strs = input + pattern;
    size_t pos = strs.find(pattern);
    while (pos != strs.npos) {
        string temp = strs.substr(0, pos);
        result.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(pattern);
    }
    return result;
}

string DfxUtils::GetSafePath(const string &path)
{
    string safePath = path;
    if (path == "") {
        return safePath;
    }
    if (MediaFileUtils::StartsWith(path, CLOUD_PHOTO_PATH)) {
        return safePath.replace(0, CLOUD_PHOTO_PATH.length(), GARBLE);
    }
    safePath = safePath.replace(0, CLOUD_FILE_PATH.length(), GARBLE);
    size_t splitIndex = safePath.find_last_of(SPLIT_PATH);
    string displayName;
    if (splitIndex == string::npos) {
        displayName = "";
    } else {
        displayName = safePath.substr(splitIndex + 1);
    }
    string safeDisplayName = GetSafeDiaplayName(displayName);
    safePath = safePath.substr(0, splitIndex) + safeDisplayName;
    return safePath;
}

string DfxUtils::GetSafeDiaplayName(string &displayName)
{
    if (displayName == "") {
        return displayName;
    }
    string extension;
    size_t splitIndex = displayName.find_last_of(DOT);
    if (splitIndex == string::npos) {
        extension = "";
    } else {
        extension = displayName.substr(splitIndex);
    }
    string title = MediaFileUtils::GetTitleFromDisplayName(displayName);
    if (title == "") {
        return title;
    }
    int32_t length = title.size();
    string safeDisplayName;
    if (length <= GARBLE_SMALL) {
        safeDisplayName = GARBLE + title.substr(length - GARBLE_LAST_ONE) + extension;
    } else if (length > GARBLE_LARGE) {
        safeDisplayName = GARBLE + title.substr(GARBLE_LARGE) + extension;
    } else {
        safeDisplayName = GARBLE + title.substr(length - GARBLE_LAST_TWO) + extension;
    }
    return safeDisplayName;
}
} // namespace Media
} // namespace OHOS