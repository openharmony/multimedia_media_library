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
#define MLOG_TAG "Thumbnail"

#include "thumbnail_uri_utils.h"

#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"

using namespace std;

namespace OHOS {
namespace Media {
bool ThumbnailUriUtils::ParseFileUri(const string &uriString, string &outFileId, string &ourNetworkId)
{
    outFileId = GetIdFromUri(uriString);
    ourNetworkId = GetNetworkIdFromUri(uriString);
    return true;
}

void ThumbnailUriUtils::ParseThumbnailKey(const string &key, const string &value, string &outAction,
    int &outWidth, int &outHeight)
{
    if (key == THUMBNAIL_OPERN_KEYWORD) {
        outAction = value;
    } else if (key == THUMBNAIL_WIDTH) {
        if (IsNumber(value)) {
            outWidth = stoi(value);
        }
    } else if (key == THUMBNAIL_HEIGHT) {
        if (IsNumber(value)) {
            outHeight = stoi(value);
        }
    }
}

bool ThumbnailUriUtils::ParseThumbnailInfo(const string &uriString, string &outFileId, Size &outSize,
    string &ourNetworkId)
{
    string::size_type pos = uriString.find_last_of('?');
    if (pos == string::npos) {
        return false;
    }
    vector<string> keyWords = {
        THUMBNAIL_OPERN_KEYWORD,
        THUMBNAIL_WIDTH,
        THUMBNAIL_HEIGHT
    };
    string queryKeys = uriString.substr(pos + 1);
    string uri = uriString.substr(0, pos);
    outFileId = GetIdFromUri(uri);
    ourNetworkId = GetNetworkIdFromUri(uri);
    vector<string> vectorKeys;
    SplitKeys(queryKeys, vectorKeys);
    if (vectorKeys.size() != keyWords.size()) {
        MEDIA_ERR_LOG("Parse error keys count %{private}d", (int)vectorKeys.size());
        return false;
    }
    string action;
    int width = 0;
    int height = 0;
    string subKey;
    string subVal;
    for (uint32_t i = 0; i < vectorKeys.size(); i++) {
        SplitKeyValue(vectorKeys[i], subKey, subVal);
        if (subKey.empty()) {
            MEDIA_ERR_LOG("Parse key error [ %{private}s ]", vectorKeys[i].c_str());
            return false;
        }
        ParseThumbnailKey(subKey, subVal, action, width, height);
    }
    MEDIA_INFO_LOG("Action [%{private}s] id %{public}s width %{private}d height %{private}d",
        action.c_str(), outFileId.c_str(), width, height);
    if (action != MEDIA_DATA_DB_THUMBNAIL || width <= 0 || height <= 0) {
        MEDIA_ERR_LOG("ParseThumbnailInfo | Error args");
        return false;
    }

    outSize.width = width;
    outSize.height = height;
    return true;
}

string ThumbnailUriUtils::GetNetworkIdFromUri(const string &uri)
{
    string deviceId;
    if (uri.empty()) {
        return deviceId;
    }
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        return deviceId;
    }

    string tempUri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length());
    if (tempUri.empty()) {
        return deviceId;
    }
    MEDIA_INFO_LOG("ThumbnailUriUtils::GetNetworkIdFromUri tempUri = %{private}s", tempUri.c_str());
    pos = tempUri.find_first_of('/');
    if (pos == 0 || pos == string::npos) {
        return deviceId;
    }
    deviceId = tempUri.substr(0, pos);
    return deviceId;
}

string ThumbnailUriUtils::GetIdFromUri(const string &uri)
{
    string rowNum = "-1";

    size_t pos = uri.rfind('/');
    if (pos != std::string::npos) {
        rowNum = uri.substr(pos + 1);
    }

    return rowNum;
}

void ThumbnailUriUtils::SplitKeyValue(const string& keyValue, string &key, string &value)
{
    string::size_type pos = keyValue.find('=');
    if (string::npos != pos) {
        key = keyValue.substr(0, pos);
        value = keyValue.substr(pos + 1);
    }
}

void ThumbnailUriUtils::SplitKeys(const string& query, vector<string>& keys)
{
    string::size_type pos1 = 0;
    string::size_type pos2 = query.find('&');
    while (string::npos != pos2) {
        keys.push_back(query.substr(pos1, pos2-pos1));
        pos1 = pos2 + 1;
        pos2 = query.find('&', pos1);
    }
    if (pos1 != query.length()) {
        keys.push_back(query.substr(pos1));
    }
}

bool ThumbnailUriUtils::IsNumber(const string &str)
{
    if (str.empty()) {
        MEDIA_ERR_LOG("IsNumber input is empty ");
        return false;
    }

    for (char const &c : str) {
        if (isdigit(c) == 0) {
            return false;
        }
    }
    return true;
}

bool ThumbnailUriUtils::ParseThumbnailInfo(const string &uriString)
{
    string outFileId;
    string ourNetworkId;
    Size outSize;
    return ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
}
} // namespace Media
} // namespace OHOS
