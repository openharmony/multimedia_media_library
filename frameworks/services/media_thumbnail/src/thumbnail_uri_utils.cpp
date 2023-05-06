/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <map>

#include "media_file_uri.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_column.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "userfile_manager_types.h"

using namespace std;

namespace OHOS {
namespace Media {
bool ThumbnailUriUtils::ParseFileUri(const string &uriString, string &outFileId, string &outNetworkId,
    string &outTableName)
{
    outFileId = GetIdFromUri(uriString);
    outNetworkId = GetNetworkIdFromUri(uriString);
    outTableName = GetTableFromUri(uriString);
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
    string &outNetworkId, string &outTableName)
{
    string::size_type pos = uriString.find_last_of('?');
    outTableName = GetTableFromUri(uriString);
    if (pos == string::npos) {
        return false;
    }
    vector<string> keyWords = {
        THUMBNAIL_OPERN_KEYWORD,
        THUMBNAIL_WIDTH,
        THUMBNAIL_HEIGHT,
        URI_PARAM_API_VERSION
    };
    string queryKeys = uriString.substr(pos + 1);
    string uri = uriString.substr(0, pos);
    outFileId = GetIdFromUri(uri);
    outNetworkId = GetNetworkIdFromUri(uri);
    vector<string> vectorKeys;
    SplitKeys(queryKeys, vectorKeys);
    if (vectorKeys.size() != keyWords.size() && vectorKeys.size() != keyWords.size() - 1) {
        // vectorKeys can contain or not contain api_version message
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
    return MediaFileUri(uri).GetNetworkId();
}

string ThumbnailUriUtils::GetIdFromUri(const string &uri)
{
    return MediaFileUri(uri).GetFileId();
}

string ThumbnailUriUtils::GetTableFromUri(const string &uri)
{
    size_t point = uri.find(URI_PARAM_API_VERSION);
    if (point == string::npos) {
        return MEDIALIBRARY_TABLE;
    }
    size_t middlePoint = uri.find('=', point);
    size_t endPoint = min(uri.find('&', point), uri.find('#', point));
    if ((middlePoint == string::npos) || (endPoint - middlePoint <= 1)) {
        return MEDIALIBRARY_TABLE;
    }

    string version;
    if (endPoint == string::npos) {
        version = uri.substr(middlePoint + 1);
    } else {
        version = uri.substr(middlePoint + 1, endPoint - middlePoint - 1);
    }
    if (version != to_string(static_cast<int32_t>(MediaLibraryApi::API_10))) {
        return MEDIALIBRARY_TABLE;
    }
    
    static map<string, string> TYPE_TO_TABLE_MAP = {
        { MEDIALIBRARY_TYPE_IMAGE_URI, PhotoColumn::PHOTOS_TABLE },
        { MEDIALIBRARY_TYPE_VIDEO_URI, PhotoColumn::PHOTOS_TABLE },
        { PhotoColumn::PHOTO_TYPE_URI, PhotoColumn::PHOTOS_TABLE },
        { MEDIALIBRARY_TYPE_AUDIO_URI, AudioColumn::AUDIOS_TABLE },
        { MEDIALIBRARY_TYPE_FILE_URI, DocumentColumn::DOCUMENTS_TABLE }
    };
    string table = MEDIALIBRARY_TABLE;
    for (const auto &iter : TYPE_TO_TABLE_MAP) {
        if (uri.find(iter.first) != string::npos) {
            table = iter.second;
            break;
        }
    }
    return table;
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
    string outNetworkId;
    Size outSize;
    string outTableName;
    return ParseThumbnailInfo(uriString, outFileId, outSize, outTableName, outNetworkId);
}
} // namespace Media
} // namespace OHOS
