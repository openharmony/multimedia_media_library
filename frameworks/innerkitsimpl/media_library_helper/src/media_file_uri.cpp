/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <sstream>

#include "media_file_uri.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
const size_t LEAST_PATH_LENGTH = 2;
const std::string MEDIA_FILE_ID_DEFAULT = "-1";
static std::string SolveMediaTypeV9(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_TYPE_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_TYPE_IMAGE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_TYPE_FILE_URI;
    }
}

static std::string SolveMediaTypeV10(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
        case MEDIA_TYPE_IMAGE:
            return PhotoColumn::PHOTO_TYPE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_TYPE_FILE_URI;
    }
}

static std::string SolveMediaType(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_TYPE_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_TYPE_IMAGE_URI;
        case MEDIA_TYPE_ALBUM:
            return MEDIALIBRARY_TYPE_ALBUM_URI;
        case MEDIA_TYPE_SMARTALBUM:
            return MEDIALIBRARY_TYPE_SMART_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_TYPE_FILE_URI;
    }
}

static std::string GetMediaTypeUri(MediaType mediaType, const int32_t &apiVersion)
{
    switch (apiVersion) {
        case MEDIA_API_VERSION_V9:
            return SolveMediaTypeV9(mediaType);
        case MEDIA_API_VERSION_V10:
            return SolveMediaTypeV10(mediaType);
        case MEDIA_API_VERSION_DEFAULT:
        default:
            return SolveMediaType(mediaType);
    }
}

std::string MediaFileUri::MediaFileUriConstruct(MediaType mediaType,
    const std::string &fileId, const std::string &networkId, const int32_t &apiVersion)
{
    std::string uri = ML_FILE_URI_PREFIX;
    uri += GetMediaTypeUri(mediaType, apiVersion);
    if (!fileId.empty()) {
        uri += "/" + fileId;
    }

    if (!networkId.empty()) {
        uri += ML_URI_NETWORKID_EQUAL + networkId;
    }
    return uri;
}

static void SetQueryMap(MediaFileUri* uri, std::unordered_map<std::string,
    std::string> &queryMap)
{
    // file://media/image/12?networkid=xxxx&api_version=xxxx
    std::string query = uri->GetQuery();
    std::string pairString;
    std::stringstream queryStream(query);

    while (getline(queryStream, pairString, '&')) {
        size_t splitIndex = pairString.find('=');
        if (splitIndex == std::string::npos || splitIndex == (pairString.length() - 1)) {
            MEDIA_ERR_LOG("failed to parse query, query field is %{private}s!", pairString.c_str());
            continue;
        }
        queryMap[pairString.substr(0, splitIndex)] = pairString.substr(splitIndex + 1);
    }
    return;
}

static std::string CalNetworkId(MediaFileUri* uri, std::unordered_map<std::string,
    std::string> queryMap)
{
    std::string scheme = uri->GetScheme();
    if (scheme == ML_FILE_SCHEME) {
        if (queryMap.find(ML_URI_NETWORKID) != queryMap.end()) {
            return queryMap[ML_URI_NETWORKID];
        }
        return "";
    } else if (scheme == ML_DATA_SHARE_SCHEME) {
        return uri->GetAuthority();
    }
    MEDIA_ERR_LOG("CalNetworkId scheme is invalid, scheme is %{private}s", scheme.c_str());
    return "";
}

std::string MediaFileUri::GetNetworkId()
{
    if (this->networkId_ != MEDIA_FILE_URI_EMPTY) {
        return this->networkId_;
    }
    SetQueryMap(this, this->queryMap_);
    this->networkId_ = CalNetworkId(this, this->queryMap_);
    return this->networkId_;
}

static std::string CalFileId(MediaFileUri* uri)
{
    std::string path = uri->GetPath();
    if (path.length() < LEAST_PATH_LENGTH) {
        MEDIA_ERR_LOG("path is too short, path is %{private}s", path.c_str());
        return MEDIA_FILE_ID_DEFAULT;
    }

    std::size_t index = path.rfind("/");
    if (index == std::string::npos || index == path.length() - 1) {
        MEDIA_ERR_LOG("failed to rfind /, path is %{private}s", path.c_str());
        return MEDIA_FILE_ID_DEFAULT;
    }

    std::string fileId = path.substr(index + 1);
    if (!std::all_of(fileId.begin(), fileId.end(), ::isdigit)) {
        MEDIA_DEBUG_LOG("fileId is not all digit, fileId is %{private}s", fileId.c_str());
        return MEDIA_FILE_ID_DEFAULT;
    }

    return fileId;
}

std::string MediaFileUri::GetFileId()
{
    if (this->fileId_ != MEDIA_FILE_URI_EMPTY) {
        return this->fileId_;
    }
    this->fileId_ = CalFileId(this);
    return this->fileId_;
}

bool MediaFileUri::IsValid()
{
    std::string scheme = this->GetScheme();
    if (scheme != ML_FILE_SCHEME &&
        scheme != ML_DATA_SHARE_SCHEME) {
        MEDIA_ERR_LOG("scheme is invalid, uri is %{private}s", this->ToString().c_str());
        return false;
    }

    if (this->GetAuthority() != ML_URI_AUTHORITY &&
        this->GetPath().find(MEDIALIBRARY_DATA_URI_IDENTIFIER) != 0) {
        MEDIA_ERR_LOG("failed to find /media, uri is %{private}s", this->ToString().c_str());
        return false;
    }

    std::string fileId = this->GetFileId();
    if (fileId == MEDIA_FILE_ID_DEFAULT) {
        MEDIA_ERR_LOG("fileid is invaild, uri is %{private}s", this->ToString().c_str());
        return false;
    }

    return true;
}
} // namespace Media
} // namespace OHOS
