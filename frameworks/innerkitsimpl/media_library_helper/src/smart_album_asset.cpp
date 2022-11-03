/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "smart_album_asset.h"

#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
SmartAlbumAsset::SmartAlbumAsset()
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    albumUri_ = DEFAULT_ALBUM_URI;
    albumTag_ = DEFAULT_SMART_ALBUM_TAG;
    albumPrivateType_ = DEFAULT_SMART_ALBUM_PRIVATE_TYPE;
    albumCapacity_ = DEFAULT_SMART_ALBUM_ALBUMCAPACITY;
    categoryId_ = DEFAULT_SMART_ALBUM_CATEGORYID;
    albumDateModified_ = DEFAULT_SMART_ALBUM_DATE_MODIFIED;
    categoryName_ = DEFAULT_SMART_ALBUM_CATEGORYNAME;
    coverUri_ = DEFAULT_COVERURI;
    resultNapiType_ = ResultNapiType::TYPE_MEDIALIBRARY;
}

SmartAlbumAsset::~SmartAlbumAsset() = default;


void SmartAlbumAsset::SetAlbumId(const int32_t albumId)
{
    albumId_ = albumId;
}

void SmartAlbumAsset::SetAlbumName(const string albumName)
{
    albumName_ = albumName;
}

void SmartAlbumAsset::SetAlbumUri(const string albumUri)
{
    albumUri_ = albumUri;
}

void SmartAlbumAsset::SetAlbumTag(const string albumTag)
{
    albumTag_ = albumTag;
}

void SmartAlbumAsset::SetAlbumCapacity(const int32_t albumCapacity)
{
    albumCapacity_ = albumCapacity;
}

void SmartAlbumAsset::SetCategoryId(const int32_t categoryId)
{
    categoryId_ = categoryId;
}

void SmartAlbumAsset::SetAlbumDateModified(const int64_t albumDateModified)
{
    albumDateModified_ = albumDateModified;
}

void SmartAlbumAsset::SetCategoryName(const string categoryName)
{
    categoryName_ = categoryName;
}

void SmartAlbumAsset::SetCoverUri(const string coverUri)
{
    coverUri_ = coverUri;
}

void SmartAlbumAsset::SetTypeMask(const string &typeMask)
{
    typeMask_ = typeMask;
}

void SmartAlbumAsset::SetAlbumPrivateType(const PrivateAlbumType albumPrivateType)
{
    albumPrivateType_ = albumPrivateType;
}

void SmartAlbumAsset::SetResultNapiType(const ResultNapiType type)
{
    resultNapiType_ = type;
}

int32_t SmartAlbumAsset::GetAlbumId() const
{
    return albumId_;
}

string SmartAlbumAsset::GetAlbumName() const
{
    return albumName_;
}

string SmartAlbumAsset::GetAlbumUri() const
{
    return albumUri_;
}

string SmartAlbumAsset::GetAlbumTag() const
{
    return albumTag_;
}

int32_t SmartAlbumAsset::GetAlbumCapacity() const
{
    return albumCapacity_;
}

int32_t SmartAlbumAsset::GetCategoryId() const
{
    return categoryId_;
}

int64_t SmartAlbumAsset::GetAlbumDateModified() const
{
    return albumDateModified_;
}

string SmartAlbumAsset::GetCategoryName() const
{
    return categoryName_;
}

string SmartAlbumAsset::GetCoverUri() const
{
    return coverUri_;
}

string SmartAlbumAsset::GetTypeMask() const
{
    return typeMask_;
}

PrivateAlbumType SmartAlbumAsset::GetAlbumPrivateType() const
{
    return albumPrivateType_;
}

ResultNapiType SmartAlbumAsset::GetResultNapiType() const
{
    return resultNapiType_;
}
}  // namespace Media
}  // namespace OHOS
