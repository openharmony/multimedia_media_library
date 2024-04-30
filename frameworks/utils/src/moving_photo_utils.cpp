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

#include "file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "moving_photo_utils.h"
#include "userfile_client.h"

namespace OHOS {
namespace Media {

bool MovingPhotoUtils::SplitMovingPhotoUri(const std::string& src, std::vector<std::string>& ret)
{
    const std::string split(MOVING_PHOTO_URI_SPLIT);
    if (src.empty() || IsMediaLibraryUri(src)) {
        MEDIA_ERR_LOG("Failed to split moving photo uri, uri=%{public}s", src.c_str());
        return false;
    }
    std::string temp = src;
    size_t pos = temp.find(split);
    uint32_t step = split.size();
    ret.push_back(temp.substr(0, pos));
    ret.push_back(temp.substr(pos + step));
    return true;
}

bool MovingPhotoUtils::IsMediaLibraryUri(const std::string& uri)
{
    return !uri.empty() && uri.find(MOVING_PHOTO_URI_SPLIT) == uri.npos;
}

static int32_t OpenReadOnlyVideo(const std::string& videoUri, bool isMediaLibUri)
{
    if (isMediaLibUri) {
        std::string openVideoUri = videoUri;
        MediaFileUtils::UriAppendKeyValue(openVideoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD,
            OPEN_MOVING_PHOTO_VIDEO);
        Uri uri(openVideoUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    AppFileService::ModuleFileUri::FileUri fileUri(videoUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("Failed to open read only video file");
        return -1;
    }
    return fd;
}

static int32_t OpenReadOnlyImage(const std::string& imageUri, bool isMediaLibUri)
{
    if (isMediaLibUri) {
        Uri uri(imageUri);
        return UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    }
    AppFileService::ModuleFileUri::FileUri fileUri(imageUri);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("Failed to open read only image file");
        return -1;
    }
    return fd;
}

int32_t MovingPhotoUtils::OpenReadOnlyFile(const std::string& uri, bool isReadImage)
{
    if (uri.empty()) {
        MEDIA_ERR_LOG("Failed to open read only file, uri is empty");
        return -1;
    }
    std::string curUri = uri;
    bool isMediaLibUri = IsMediaLibraryUri(uri);
    if (!isMediaLibUri) {
        std::vector<std::string> uris;
        if (!SplitMovingPhotoUri(uri, uris)) {
            MEDIA_ERR_LOG("Failed to open read only file, split moving photo failed");
            return -1;
        }
        curUri = uris[isReadImage ? 0 : 1];
    }
    return isReadImage ? OpenReadOnlyImage(curUri, isMediaLibUri) : OpenReadOnlyVideo(curUri, isMediaLibUri);
}

} // namespace Media
} // namespace OHOS