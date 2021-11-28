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

#include "file_asset.h"

using namespace std;

namespace OHOS {
namespace Media {
FileAsset::FileAsset()
    : id_(DEFAULT_MEDIA_ID),
    uri_(DEFAULT_MEDIA_URI),
    path_(DEFAULT_MEDIA_PATH),
    relativePath_(DEFAULT_MEDIA_RELATIVE_PATH),
    mimeType_(DEFAULT_MEDIA_MIMETYPE),
    mediaType_(DEFAULT_MEDIA_TYPE),
    displayName_(DEFAULT_MEDIA_NAME),
    size_(DEFAULT_MEDIA_SIZE),
    dateAdded_(DEFAULT_MEDIA_DATE_ADDED),
    dateModified_(DEFAULT_MEDIA_DATE_MODIFIED),
    title_(DEFAULT_MEDIA_TITLE),
    artist_(DEFAULT_MEDIA_ARTIST),
    album_(DEFAULT_MEDIA_ALBUM),
    width_(DEFAULT_MEDIA_WIDTH),
    height_(DEFAULT_MEDIA_HEIGHT),
    duration_(DEFAULT_MEDIA_DURATION),
    orientation_(DEFAULT_MEDIA_ORIENTATION),
    albumId_(DEFAULT_ALBUM_ID),
    albumName_(DEFAULT_ALBUM_NAME)
{}

int32_t FileAsset::GetId() const
{
    return id_;
}

void FileAsset::SetId(int32_t id)
{
    id_ = id;
}

const string &FileAsset::GetUri() const
{
    return uri_;
}

void FileAsset::SetUri(const string &uri)
{
    uri_ = uri;
}

const string &FileAsset::GetPath() const
{
    return path_;
}

void FileAsset::SetPath(const string &path)
{
    path_ = path;
}

const string &FileAsset::GetRelativePath() const
{
    return relativePath_;
}

void FileAsset::SetRelativePath(const std::string &relativePath)
{
    relativePath_ = relativePath;
}

const string &FileAsset::GetMimeType() const
{
    return mimeType_;
}

void FileAsset::SetMimeType(const string &mimeType)
{
    mimeType_ = mimeType;
}

MediaType FileAsset::GetMediaType() const
{
    return mediaType_;
}

void FileAsset::SetMediaType(MediaType mediaType)
{
    mediaType_ = mediaType;
}

const string &FileAsset::GetDisplayName() const
{
    return displayName_;
}

void FileAsset::SetDisplayName(const string &displayName)
{
    displayName_ = displayName;
}

int64_t FileAsset::GetSize() const
{
    return size_;
}

void FileAsset::SetSize(int64_t size)
{
    size_ = size;
}

int64_t FileAsset::GetDateAdded() const
{
    return dateAdded_;
}

void FileAsset::SetDateAdded(int64_t dateAdded)
{
    dateAdded_ = dateAdded;
}

int64_t FileAsset::GetDateModified() const
{
    return dateModified_;
}

void FileAsset::SetDateModified(int64_t dateModified)
{
    dateModified_ = dateModified;
}

const string &FileAsset::GetTitle() const
{
    return title_;
}

void FileAsset::SetTitle(const string &title)
{
    title_ = title;
}

const string &FileAsset::GetArtist() const
{
    return artist_;
}

void FileAsset::SetArtist(const string &artist)
{
    artist_ = artist;
}

const string &FileAsset::GetAlbum() const
{
    return album_;
}

void FileAsset::SetAlbum(const string &album)
{
    album_ = album;
}

int32_t FileAsset::GetWidth() const
{
    return width_;
}

void FileAsset::SetWidth(int32_t width)
{
    width_ = width;
}

int32_t FileAsset::GetHeight() const
{
    return height_;
}

void FileAsset::SetHeight(int32_t height)
{
    height_ = height;
}

int32_t FileAsset::GetDuration() const
{
    return duration_;
}

void FileAsset::SetDuration(int32_t duration)
{
    duration_ = duration;
}

int32_t FileAsset::GetOrientation() const
{
    return orientation_;
}

void FileAsset::SetOrientation(int32_t orientation)
{
    orientation_ = orientation;
}

int32_t FileAsset::GetAlbumId() const
{
    return albumId_;
}

void FileAsset::SetAlbumId(int32_t albumId)
{
    albumId_ = albumId;
}

const string &FileAsset::GetAlbumName() const
{
    return albumName_;
}

void FileAsset::SetAlbumName(const string &albumName)
{
    albumName_ = albumName;
}

int32_t FileAsset::CreateAsset(const string &filePath)
{
    int32_t errCode = FAIL;

    if (filePath.empty() || MediaFileUtils::IsFileExists(filePath)) {
        MEDIA_ERR_LOG("Filepath is empty or the file exists");
        return errCode;
    }

    size_t slashIndex = filePath.rfind('/');
    if (slashIndex != string::npos) {
        string fileName = filePath.substr(slashIndex + 1);
        if (!fileName.empty() && fileName.at(0) != '.') {
            size_t dotIndex = filePath.rfind('.');
            if (dotIndex == string::npos && mediaType_ != MEDIA_TYPE_FILE) {
                return errCode;
            }
        }
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created");
        return errCode;
    }

    file.close();

    return DATA_ABILITY_SUCCESS;
}

int32_t FileAsset::ModifyAsset(const string &oldPath, const string &newPath)
{
    int32_t errRet = -1;

    if (!oldPath.empty() && !newPath.empty() &&
        MediaFileUtils::IsFileExists(oldPath) &&
        !MediaFileUtils::IsFileExists(newPath)) {
        errRet = rename(oldPath.c_str(), newPath.c_str());
    }

    return errRet;
}

int32_t FileAsset::DeleteAsset(const string &filePath)
{
    return remove(filePath.c_str());
}

int32_t FileAsset::OpenAsset(const string &filePath, const string &mode)
{
    int32_t errCode = FAIL;

    if (filePath.empty() || mode.empty()) {
        return errCode;
    }

    int32_t flags = O_RDWR;
    if (mode == MEDIA_FILEMODE_READONLY) {
        flags = O_RDONLY;
    } else if (mode == MEDIA_FILEMODE_WRITEONLY) {
        flags = O_WRONLY;
    } else if (mode == MEDIA_FILEMODE_WRITETRUNCATE) {
        flags = O_WRONLY | O_TRUNC;
    } else if (mode == MEDIA_FILEMODE_WRITEAPPEND) {
        flags = O_WRONLY | O_APPEND;
    } else if (mode == MEDIA_FILEMODE_READWRITETRUNCATE) {
        flags = O_RDWR | O_TRUNC;
    }

    char actualPath[PATH_MAX];
    auto absFilePath = realpath(filePath.c_str(), actualPath);
    if (absFilePath == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path");
        return errCode;
    }

    return open(absFilePath, flags);
}

int32_t FileAsset::CloseAsset(int32_t fd)
{
    return close(fd);
}
}  // namespace Media
}  // namespace OHOS