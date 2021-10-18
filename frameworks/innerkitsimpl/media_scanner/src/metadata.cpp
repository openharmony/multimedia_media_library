/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "metadata.h"

namespace OHOS {
namespace Media {
using std::string;

Metadata::Metadata()
{
    id_ = FILE_ID_DEFAULT;
    uri_ = URI_DEFAULT;
    filePath_ = FILE_PATH_DEFAULT;
    relativePath_ = FILE_RELATIVE_PATH_DEFAULT;
    mimeType_ = DEFAULT_FILE_MIME_TYPE;
    mediaType_ = FILE_MEDIA_TYPE_DEFAULT;
    name_ = FILE_NAME_DEFAULT;
    size_ = FILE_SIZE_DEFAULT;
    dateAdded_ = FILE_DATE_ADDED_DEFAULT;
    dateModified_ = FILE_DATE_MODIFIED_DEFAULT;
    fileExt_ = FILE_EXTENSION_DEFAULT;
    title_ = FILE_TITLE_DEFAULT;
    artist_ = FILE_ARTIST_DEFAULT;
    album_ = FILE_ALBUM_NAME_DEFAULT;
    height_ = FILE_HEIGHT_DEFAULT;
    width_ = FILE_WIDTH_DEFAULT;
    duration_ = FILE_DURATION_DEFAULT;
    orientation_ = FILE_ORIENTATION_DEFAULT;
    albumId_ = FILE_ALBUM_ID_DEFAULT;
    albumName_ = FILE_ALBUM_NAME_DEFAULT;
    parentId_ = FILE_ID_DEFAULT;
}

void Metadata::SetFileId(const int32_t id)
{
    id_ = id;
}

int32_t Metadata::GetFileId() const
{
    return id_;
}

void Metadata::SetUri(const string uri)
{
    uri_ = uri;
}

std::string Metadata::GetUri() const
{
    return uri_;
}

void Metadata::SetFilePath(const string filePath)
{
    filePath_ = filePath;
}

std::string Metadata::GetFilePath() const
{
    return filePath_;
}

void Metadata::SetRelativePath(const std::string relativePath)
{
    relativePath_ = relativePath;
}

std::string Metadata::GetRelativePath() const
{
    return relativePath_;
}

void Metadata::SetFileMimeType(const string mimeType)
{
    mimeType_ = mimeType;
}

std::string Metadata::GetFileMimeType() const
{
    return mimeType_;
}

void Metadata::SetFileMediaType(const MediaType mediaType)
{
    mediaType_ = mediaType;
}

MediaType Metadata::GetFileMediaType() const
{
    return mediaType_;
}

void Metadata::SetFileName(const string name)
{
    name_ = name;
}

std::string Metadata::GetFileName() const
{
    return name_;
}

void Metadata::SetFileSize(const int64_t size)
{
    size_ = size;
}

int64_t Metadata::GetFileSize() const
{
    return size_;
}

void Metadata::SetFileDateAdded(const int64_t dateAdded)
{
    dateAdded_ = dateAdded;
}

int64_t Metadata::GetFileDateAdded() const
{
    return dateAdded_;
}

void Metadata::SetFileDateModified(const int64_t dateModified)
{
    dateModified_ = dateModified;
}

int64_t Metadata::GetFileDateModified() const
{
    return dateModified_;
}

void Metadata::SetFileExtension(const string fileExt)
{
    fileExt_ = fileExt;
}

std::string Metadata::GetFileExtension() const
{
    return fileExt_;
}

void Metadata::SetFileTitle(const string title)
{
    title_ = title;
}

string Metadata::GetFileTitle() const
{
    return title_;
}

void Metadata::SetFileArtist(const string artist)
{
    artist_ = artist;
}

string Metadata::GetFileArtist() const
{
    return artist_;
}

void Metadata::SetAlbum(const std::string album)
{
    album_ = album;
}

std::string Metadata::GetAlbum() const
{
    return album_;
}

void Metadata::SetFileHeight(const int32_t height)
{
    height_ = height;
}

int32_t Metadata::GetFileHeight() const
{
    return height_;
}

void Metadata::SetFileWidth(const int32_t width)
{
    width_ = width;
}

int32_t Metadata::GetFileWidth() const
{
    return width_;
}

void Metadata::SetFileDuration(const int32_t duration)
{
    duration_ = duration;
}

int32_t Metadata::GetFileDuration() const
{
    return duration_;
}

void Metadata::SetOrientation(const int32_t orientation)
{
    orientation_ = orientation;
}

int32_t Metadata::GetOrientation() const
{
    return orientation_;
}

void Metadata::SetAlbumId(const int32_t albumId)
{
    albumId_ = albumId;
}

int32_t Metadata::GetAlbumId() const
{
    return albumId_;
}

void Metadata::SetAlbumName(const std::string albumName)
{
    albumName_ = albumName;
}

std::string Metadata::GetAlbumName() const
{
    return albumName_;
}

void Metadata::SetParentId(const int32_t parentId)
{
    parentId_ = parentId;
}

int32_t Metadata::GetParentId() const
{
    return parentId_;
}
} // namespace Media
} // namespace OHOS
