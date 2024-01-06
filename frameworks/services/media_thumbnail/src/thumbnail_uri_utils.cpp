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
#include "media_file_utils.h"
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
    outFileId = MediaFileUtils::GetIdFromUri(uriString);
    outNetworkId = MediaFileUtils::GetNetworkIdFromUri(uriString);
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
        (queryKey[THUMBNAIL_OPERN_KEYWORD] != MEDIA_DATA_DB_THUMBNAIL ||
         queryKey[THUMBNAIL_OPERN_KEYWORD] != MEDIA_DATA_DB_THUMB_ASTC)) {
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

    if (!CheckSize(outSize, outPath)) {
        return false;
    }

    return true;
}

bool ThumbnailUriUtils::IsOriginalImg(const Size &outSize, const string &outPath)
{
    return outSize.width == DEFAULT_ORIGINAL && outSize.height == DEFAULT_ORIGINAL &&
        MediaFileUtils::GetMediaType(outPath) == MEDIA_TYPE_AUDIO;
}

bool ThumbnailUriUtils::CheckSize(Size &outSize, const string &outPath)
{
    if (IsOriginalImg(outSize, outPath)) {
        outSize.width = DEFAULT_LCD_SIZE;
        outSize.height = DEFAULT_LCD_SIZE;
    }

    if ((outSize.width <= 0 || outSize.height <= 0) && !IsOriginalImg(outSize, outPath)) {
        return false;
    }

    return true;
}

string ThumbnailUriUtils::GetTableFromUri(const string &uri)
{
    string table = MediaFileUri(uri).GetTableName();
    if (table.empty()) {
        return MEDIALIBRARY_TABLE;
    }
    return table;
}
} // namespace Media
} // namespace OHOS
