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
#define MLOG_TAG "Album"

#include "album_asset.h"

#include "media_file_utils.h"
#include "medialibrary_type_const.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {
AlbumAsset::AlbumAsset()
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    albumUri_ = DEFAULT_ALBUM_URI;
    albumDateModified_ = DEFAULT_ALBUM_DATE_MODIFIED;
    count_ = DEFAULT_COUNT;
    albumRelativePath_ = DEFAULT_ALBUM_RELATIVE_PATH;
    coverUri_ = DEFAULT_COVERURI;
    albumPath_ = DEFAULT_ALBUM_PATH;
    albumVirtual_ = DEFAULT_ALBUM_VIRTUAL;
    typeMask_ = DEFAULT_TYPE_MASK;
    resultNapiType_ = ResultNapiType::TYPE_MEDIALIBRARY;
}

AlbumAsset::~AlbumAsset() = default;


void AlbumAsset::SetAlbumId(const int32_t albumId)
{
    albumId_ = albumId;
}

void AlbumAsset::SetAlbumName(const string albumName)
{
    albumName_ = albumName;
}

void AlbumAsset::SetAlbumUri(const string albumUri)
{
    albumUri_ = albumUri;
}

void AlbumAsset::SetAlbumDateModified(const int64_t albumDateModified)
{
    albumDateModified_ = albumDateModified;
}

void AlbumAsset::SetCount(const int32_t count)
{
    count_ = count;
}

void AlbumAsset::SetAlbumRelativePath(const string albumRelativePath)
{
    albumRelativePath_ = albumRelativePath;
}
void AlbumAsset::SetCoverUri(const string coverUri)
{
    coverUri_ = coverUri;
}

void AlbumAsset::SetAlbumPath(const string albumPath)
{
    albumPath_ = albumPath;
}

void AlbumAsset::SetAlbumVirtual(const bool albumVirtual)
{
    albumVirtual_ = albumVirtual;
}

void AlbumAsset::SetAlbumTypeMask(const string &typeMask)
{
    typeMask_ = typeMask;
}

int32_t AlbumAsset::GetAlbumId() const
{
    return albumId_;
}

string AlbumAsset::GetAlbumName() const
{
    return albumName_;
}

string AlbumAsset::GetAlbumUri() const
{
    return albumUri_;
}

int64_t AlbumAsset::GetAlbumDateModified() const
{
    return albumDateModified_;
}

int32_t AlbumAsset::GetCount() const
{
    return count_;
}

string AlbumAsset::GetAlbumRelativePath() const
{
    return albumRelativePath_;
}

string AlbumAsset::GetCoverUri() const
{
    return coverUri_;
}

string AlbumAsset::GetAlbumPath() const
{
    return albumPath_;
}

bool AlbumAsset::GetAlbumVirtual() const
{
    return albumVirtual_;
}

string AlbumAsset::GetAlbumTypeMask() const
{
    return typeMask_;
}

bool AlbumAsset::CreateAlbumAsset()
{
    if (!(MediaFileUtils::IsDirectory(albumPath_))) {
        return MediaFileUtils::CreateDirectory(albumPath_);
    } else {
        MEDIA_ERR_LOG("Cannot create album that already exists");
        return false;
    }
}

bool AlbumAsset::DeleteAlbumAsset(const string &albumUri)
{
    return MediaFileUtils::DeleteDir(albumUri);
}

bool AlbumAsset::ModifyAlbumAsset(const string &albumUri)
{
    string newAlbumUri;
    string oldAlbumUri;
    size_t slashIndex;
    bool errCode = false;

    oldAlbumUri = albumUri;
    slashIndex = albumUri.rfind("/");
    if (slashIndex != string::npos) {
        newAlbumUri = albumUri.substr(0, slashIndex) + SLASH_CHAR + albumName_;
        errCode =  MediaFileUtils::RenameDir(oldAlbumUri, newAlbumUri);
    }

    return errCode;
}

void AlbumAsset::SetResultNapiType(const ResultNapiType type)
{
    resultNapiType_ = type;
}

ResultNapiType AlbumAsset::GetResultNapiType() const
{
    return resultNapiType_;
}


}  // namespace Media
}  // namespace OHOS
