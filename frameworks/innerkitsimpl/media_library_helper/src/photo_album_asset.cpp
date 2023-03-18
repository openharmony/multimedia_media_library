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
#define MLOG_TAG "PhotoAlbum"

#include "photo_album_asset.h"

#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
PhotoAlbumAsset::PhotoAlbumAsset()
{
    albumId_ = DEFAULT_ALBUM_ID;
    type_ = USER;
    subType_ = USER_GENERIC;
    count_ = DEFAULT_COUNT;
    resultNapiType_ = ResultNapiType::TYPE_USERFILE_MGR;
}

PhotoAlbumAsset::~PhotoAlbumAsset() = default;

void PhotoAlbumAsset::SetAlbumId(const int32_t albumId)
{
    albumId_ = albumId;
}

int32_t PhotoAlbumAsset::GetAlbumId() const
{
    return albumId_;
}

void PhotoAlbumAsset::SetPhotoAlbumType(const PhotoAlbumType type)
{
    type_ = type;
}

PhotoAlbumType PhotoAlbumAsset::GetPhotoAlbumType() const
{
    return type_;
}

void PhotoAlbumAsset::SetPhotoAlbumSubType(const PhotoAlbumSubType subType)
{
    subType_ = subType;
}

PhotoAlbumSubType PhotoAlbumAsset::GetPhotoAlbumSubType() const
{
    return subType_;
}

void PhotoAlbumAsset::SetAlbumUri(const string &uri)
{
    uri_ = uri;
}

const string& PhotoAlbumAsset::GetAlbumUri() const
{
    return uri_;
}

void PhotoAlbumAsset::SetAlbumName(const string &albumName)
{
    albumName_ = albumName;
}

const string& PhotoAlbumAsset::GetAlbumName() const
{
    return albumName_;
}

void PhotoAlbumAsset::SetCoverUri(const string &coverUri)
{
    coverUri_ = coverUri;
}

const string& PhotoAlbumAsset::GetCoverUri() const
{
    return coverUri_;
}

void PhotoAlbumAsset::SetCount(const int32_t count)
{
    count_ = count;
}

int32_t PhotoAlbumAsset::GetCount() const
{
    return count_;
}

void PhotoAlbumAsset::SetRelativePath(const string &relativePath)
{
    relativePath_ = relativePath;
}

const string& PhotoAlbumAsset::GetRelativePath() const
{
    return relativePath_;
}

void PhotoAlbumAsset::SetTypeMask(const string &typeMask)
{
    typeMask_ = typeMask;
}

const string& PhotoAlbumAsset::GetTypeMask() const
{
    return typeMask_;
}

void PhotoAlbumAsset::SetResultNapiType(const ResultNapiType resultNapiType)
{
    resultNapiType_ = resultNapiType;
}

ResultNapiType PhotoAlbumAsset::GetResultNapiType() const
{
    return resultNapiType_;
}
}  // namespace Media
}  // namespace OHOS
