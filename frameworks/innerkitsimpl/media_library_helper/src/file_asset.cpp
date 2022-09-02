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
#define MLOG_TAG "FileAsset"

#include "file_asset.h"

#include <fcntl.h>
#include <fstream>
#include <unistd.h>

#include "directory_ex.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
FileAsset::FileAsset()
    : albumUri_(DEFAULT_MEDIA_ALBUM_URI),
    typeMask_(DEFAULT_TYPE_MASK),
    resultNapiType_(ResultNapiType::TYPE_NAPI_MAX)
{}

int32_t FileAsset::GetId() const
{
    return GetInt32Member(MEDIA_DATA_DB_ID);
}

void FileAsset::SetId(int32_t id)
{
    member_[MEDIA_DATA_DB_ID] = id;
}

int32_t FileAsset::GetCount() const
{
    return count_;
}

void FileAsset::SetCount(int32_t count)
{
    count_ = count;
}

const string &FileAsset::GetUri() const
{
    return GetStrMember(MEDIA_DATA_DB_URI);
}

void FileAsset::SetUri(const string &uri)
{
    member_[MEDIA_DATA_DB_URI] = uri;
}

const string &FileAsset::GetPath() const
{
    return GetStrMember(MEDIA_DATA_DB_FILE_PATH);
}

void FileAsset::SetPath(const string &path)
{
    member_[MEDIA_DATA_DB_FILE_PATH] = path;
}

const string &FileAsset::GetRelativePath() const
{
    return GetStrMember(MEDIA_DATA_DB_RELATIVE_PATH);
}

void FileAsset::SetRelativePath(const std::string &relativePath)
{
    member_[MEDIA_DATA_DB_RELATIVE_PATH] = relativePath;
}

const string &FileAsset::GetMimeType() const
{
    return GetStrMember(MEDIA_DATA_DB_MIME_TYPE);
}

void FileAsset::SetMimeType(const string &mimeType)
{
    member_[MEDIA_DATA_DB_MIME_TYPE] = mimeType;
}

MediaType FileAsset::GetMediaType() const
{
    return static_cast<Media::MediaType>(GetInt32Member(MEDIA_DATA_DB_MEDIA_TYPE));
}

void FileAsset::SetMediaType(MediaType mediaType)
{
    member_[MEDIA_DATA_DB_MEDIA_TYPE] = mediaType;
}

const string &FileAsset::GetDisplayName() const
{
    return GetStrMember(MEDIA_DATA_DB_NAME);
}

void FileAsset::SetDisplayName(const string &displayName)
{
    member_[MEDIA_DATA_DB_NAME] = displayName;
}

int64_t FileAsset::GetSize() const
{
    return GetInt64Member(MEDIA_DATA_DB_SIZE);
}

void FileAsset::SetSize(int64_t size)
{
    member_[MEDIA_DATA_DB_SIZE] = size;
}

int64_t FileAsset::GetDateAdded() const
{
    return GetInt64Member(MEDIA_DATA_DB_DATE_ADDED);
}

void FileAsset::SetDateAdded(int64_t dateAdded)
{
    member_[MEDIA_DATA_DB_DATE_ADDED] = dateAdded;
}

int64_t FileAsset::GetDateModified() const
{
    return GetInt64Member(MEDIA_DATA_DB_DATE_MODIFIED);
}

void FileAsset::SetDateModified(int64_t dateModified)
{
    member_[MEDIA_DATA_DB_DATE_MODIFIED] = dateModified;
}

const string &FileAsset::GetTitle() const
{
    return GetStrMember(MEDIA_DATA_DB_TITLE);
}

void FileAsset::SetTitle(const string &title)
{
    member_[MEDIA_DATA_DB_TITLE] = title;
}

const string &FileAsset::GetArtist() const
{
    return GetStrMember(MEDIA_DATA_DB_ARTIST);
}

void FileAsset::SetArtist(const string &artist)
{
    member_[MEDIA_DATA_DB_ARTIST] = artist;
}

const string &FileAsset::GetAlbum() const
{
    return GetStrMember(MEDIA_DATA_DB_ALBUM);
}

void FileAsset::SetAlbum(const string &album)
{
    member_[MEDIA_DATA_DB_ALBUM] = album;
}

int32_t FileAsset::GetWidth() const
{
    return GetInt32Member(MEDIA_DATA_DB_WIDTH);
}

void FileAsset::SetWidth(int32_t width)
{
    member_[MEDIA_DATA_DB_WIDTH] = width;
}

int32_t FileAsset::GetHeight() const
{
    return GetInt32Member(MEDIA_DATA_DB_HEIGHT);
}

void FileAsset::SetHeight(int32_t height)
{
    member_[MEDIA_DATA_DB_HEIGHT] = height;
}

int32_t FileAsset::GetDuration() const
{
    return GetInt32Member(MEDIA_DATA_DB_DURATION);
}

void FileAsset::SetDuration(int32_t duration)
{
    member_[MEDIA_DATA_DB_DURATION] = duration;
}

int32_t FileAsset::GetOrientation() const
{
    return GetInt32Member(MEDIA_DATA_DB_ORIENTATION);
}

void FileAsset::SetOrientation(int32_t orientation)
{
    member_[MEDIA_DATA_DB_ORIENTATION] = orientation;
}

int32_t FileAsset::GetAlbumId() const
{
    return GetInt32Member(MEDIA_DATA_DB_BUCKET_ID);
}

void FileAsset::SetAlbumId(int32_t albumId)
{
    member_[MEDIA_DATA_DB_BUCKET_ID] = albumId;
}

const string &FileAsset::GetAlbumName() const
{
    return GetStrMember(MEDIA_DATA_DB_BUCKET_NAME);
}

void FileAsset::SetAlbumName(const string &albumName)
{
    member_[MEDIA_DATA_DB_BUCKET_NAME] = albumName;
}

int32_t FileAsset::GetParent() const
{
    return GetInt32Member(MEDIA_DATA_DB_PARENT_ID);
}

void FileAsset::SetParent(int32_t parent)
{
    member_[MEDIA_DATA_DB_PARENT_ID] = parent;
}

const string &FileAsset::GetAlbumUri() const
{
    return albumUri_;
}

void FileAsset::SetAlbumUri(const string &albumUri)
{
    albumUri_ = albumUri;
}

const string &FileAsset::GetTypeMask() const
{
    return typeMask_;
}

void FileAsset::SetTypeMask(const string &typeMask)
{
    typeMask_ = typeMask;
}

int64_t FileAsset::GetDateTaken() const
{
    return GetInt64Member(MEDIA_DATA_DB_DATE_TAKEN);
}

void FileAsset::SetDateTaken(int64_t dateTaken)
{
    member_[MEDIA_DATA_DB_DATE_TAKEN] = dateTaken;
}

bool FileAsset::IsPending() const
{
    return GetInt32Member(MEDIA_DATA_DB_IS_PENDING);
}

void FileAsset::SetPending(bool dateTaken)
{
    member_[MEDIA_DATA_DB_IS_PENDING] = dateTaken;
}

int64_t FileAsset::GetTimePending() const
{
    return GetInt64Member(MEDIA_DATA_DB_TIME_PENDING);
}

void FileAsset::SetTimePending(int64_t timePending)
{
    member_[MEDIA_DATA_DB_TIME_PENDING] = timePending;
}

bool FileAsset::IsFavorite() const
{
    return GetInt32Member(MEDIA_DATA_DB_IS_FAV);
}

void FileAsset::SetFavorite(bool isFavorite)
{
    member_[MEDIA_DATA_DB_IS_FAV] = isFavorite;
}

int64_t FileAsset::GetDateTrashed() const
{
    return GetInt64Member(MEDIA_DATA_DB_DATE_TRASHED);
}

void FileAsset::SetDateTrashed(int64_t dateTrashed)
{
    member_[MEDIA_DATA_DB_DATE_TRASHED] = dateTrashed;
}

const string &FileAsset::GetSelfId() const
{
    return GetStrMember(MEDIA_DATA_DB_SELF_ID);
}

void FileAsset::SetSelfId(const string &selfId)
{
    member_[MEDIA_DATA_DB_SELF_ID] = selfId;
}

int32_t FileAsset::GetIsTrash() const
{
    return GetInt32Member(MEDIA_DATA_DB_IS_TRASH);
}

void FileAsset::SetIsTrash(int32_t isTrash)
{
    member_[MEDIA_DATA_DB_IS_TRASH] = isTrash;
}

const string &FileAsset::GetRecyclePath() const
{
    return GetStrMember(MEDIA_DATA_DB_RECYCLE_PATH);
}

void FileAsset::SetRecyclePath(const string &recyclePath)
{
    member_[MEDIA_DATA_DB_RECYCLE_PATH] = recyclePath;
}

ResultNapiType FileAsset::GetResultNapiType() const
{
    return resultNapiType_;
}

void FileAsset::SetResultNapiType(const ResultNapiType type)
{
    resultNapiType_ = type;
}

int32_t FileAsset::CreateAsset(const string &filePath)
{
    MEDIA_ERR_LOG("CreateAsset in");
    int32_t errCode = E_ERR;

    if (filePath.empty()) {
        MEDIA_ERR_LOG("Filepath is empty");
        return E_VIOLATION_PARAMETERS;
    }

    if (MediaFileUtils::IsFileExists(filePath)) {
        MEDIA_ERR_LOG("the file exists path: %{private}s", filePath.c_str());
        return E_FILE_EXIST;
    }

    size_t slashIndex = filePath.rfind('/');
    if (slashIndex != string::npos) {
        string fileName = filePath.substr(slashIndex + 1);
        if (!fileName.empty() && fileName.at(0) != '.') {
            size_t dotIndex = filePath.rfind('.');
            if ((dotIndex == string::npos) && (GetMediaType() != MEDIA_TYPE_FILE)) {
                return errCode;
            }
        }
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created errno %{public}d", errno);
        return errCode;
    }

    file.close();

    return E_SUCCESS;
}

int32_t FileAsset::ModifyAsset(const string &oldPath, const string &newPath)
{
    int32_t err = E_MODIFY_DATA_FAIL;

    if (oldPath.empty() || newPath.empty()) {
        MEDIA_ERR_LOG("Failed to modify asset, oldPath: %{private}s or newPath: %{private}s is empty!",
            oldPath.c_str(), newPath.c_str());
        return err;
    }
    if (!MediaFileUtils::IsFileExists(oldPath)) {
        MEDIA_ERR_LOG("Failed to modify asset, oldPath: %{private}s does not exist!", oldPath.c_str());
        return E_NO_SUCH_FILE;
    }
    if (MediaFileUtils::IsFileExists(newPath)) {
        MEDIA_ERR_LOG("Failed to modify asset, newPath: %{private}s is already exist!", newPath.c_str());
        return E_FILE_EXIST;
    }
    err = rename(oldPath.c_str(), newPath.c_str());
    if (err < 0) {
        MEDIA_ERR_LOG("Failed ModifyAsset errno %{public}d", errno);
        return E_FILE_OPER_FAIL;
    }

    return E_SUCCESS;
}

bool FileAsset::IsFileExists(const string &filePath)
{
    return MediaFileUtils::IsFileExists(filePath);
}

int32_t FileAsset::DeleteAsset(const string &filePath)
{
    int32_t errCode = E_ERR;
    if (!MediaFileUtils::IsDirectory(filePath)) {
        errCode = remove(filePath.c_str());
    } else {
        errCode = MediaFileUtils::RemoveDirectory(filePath);
    }
    if (errCode != E_SUCCESS) {
        MEDIA_ERR_LOG("DeleteAsset failed, filePath: %{private}s, errno: %{public}d, errmsg: %{public}s",
            filePath.c_str(), errno, strerror(errno));
    }
    return errCode;
}

int32_t FileAsset::OpenAsset(const string &filePath, const string &mode)
{
    return MediaFileUtils::OpenFile(filePath, mode);
}

std::unordered_map<std::string, std::variant<int32_t, int64_t, std::string>> &FileAsset::GetMemberMap()
{
    return member_;
}

std::variant<int32_t, int64_t, std::string> &FileAsset::GetMemberValue(const std::string &name)
{
    return member_[name];
}

const string &FileAsset::GetStrMember(const std::string &name) const
{
    return (member_.count(name) > 0) ? get<string>(member_.at(name)) : DEFAULT_STR;
}

int32_t FileAsset::GetInt32Member(const std::string &name) const
{
    return (member_.count(name) > 0) ? get<int32_t>(member_.at(name)) : DEFAULT_INT32;
}

int64_t FileAsset::GetInt64Member(const std::string &name) const
{
    return (member_.count(name) > 0) ? get<int64_t>(member_.at(name)) : DEFAULT_INT64;
}
}  // namespace Media
}  // namespace OHOS
