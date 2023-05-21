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

bool ThumbnailUriUtils::ParseThumbnailInfo(const string &uriString, string &outFileId, Size &outSize,
    string &outPath, string &outTableName)
{
    string::size_type pos = uriString.find_last_of('?');
    outTableName = GetTableFromUri(uriString);
    if (pos == string::npos) {
        return false;
    }

    MediaFileUri uri(uriString);
    outFileId = uri.GetFileId();
    auto &queryKey = uri.GetQueryKeys();
    if (queryKey.count(THUMBNAIL_OPERN_KEYWORD) == 0 &&
        queryKey[THUMBNAIL_OPERN_KEYWORD] != MEDIA_DATA_DB_THUMBNAIL) {
        return false;
    }

    if (queryKey.count(THUMBNAIL_WIDTH) != 0) {
        outSize.width = stoi(queryKey[THUMBNAIL_WIDTH]);
    }

    if (queryKey.count(THUMBNAIL_HEIGHT) != 0) {
        outSize.height = stoi(queryKey[THUMBNAIL_HEIGHT]);
    }

    if (queryKey.count(THUMBNAIL_PATH) != 0) {
        outPath = queryKey[THUMBNAIL_PATH];
    }

    if (outSize.width <= 0 || outSize.height <= 0) {
        return false;
    }

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
        { AudioColumn::AUDIO_TYPE_URI, AudioColumn::AUDIOS_TABLE }
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
} // namespace Media
} // namespace OHOS
