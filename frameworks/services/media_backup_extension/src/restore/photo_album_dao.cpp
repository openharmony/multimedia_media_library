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
#include "photo_album_dao.h"

#include <vector>
#include <string>

#include "rdb_store.h"
#include "media_log.h"
#include "result_set_utils.h"

namespace OHOS::Media {
std::string StringUtils::ToLower(const std::string &str)
{
    std::string lowerStr;
    std::transform(
        str.begin(), str.end(), std::back_inserter(lowerStr), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

/**
 * @brief Check the AlbumName unique or not. true - unique, false - not unique.
 */
bool PhotoAlbumDao::CheckAlbumNameUnique(const std::string &albumName, const std::string &lPath)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {albumName, lPath};
    std::string querySql = this->SQL_PHOTO_ALBUM_CHECK_ALBUM_NAME_UNIQUE;
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToNextRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return true;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count == 0;
}

/**
 * @brief Find the Unique Album Name.
 */
std::string PhotoAlbumDao::FindUniqueAlbumName(const PhotoAlbumDao::PhotoAlbumRowData &photoAlbum)
{
    if (photoAlbum.lPath.empty() || photoAlbum.albumName.empty()) {
        MEDIA_ERR_LOG("Invalid album data");
        return "";
    }
    const std::string lPath = photoAlbum.lPath;
    // The PhotoAlbum is cached.
    if (this->photoAlbumCache_.count(StringUtils::ToLower(lPath)) > 0) {
        PhotoAlbumDao::PhotoAlbumRowData albumDataInCache = this->photoAlbumCache_[StringUtils::ToLower(lPath)];
        return albumDataInCache.albumName;
    }
    // Check if the album name is unique.
    std::string albumName = photoAlbum.albumName;
    int32_t sequence = 1;
    bool isUnique = this->CheckAlbumNameUnique(albumName, photoAlbum.lPath);
    while (!isUnique && sequence < this->MAX_ALBUM_NAME_SEQUENCE) {
        albumName = photoAlbum.albumName + " " + std::to_string(sequence);
        sequence++;
        isUnique = this->CheckAlbumNameUnique(albumName, photoAlbum.lPath);
    }
    MEDIA_INFO_LOG("FindUniqueAlbumName, old albumName: %{public}s, albumName: %{public}s, lPath: %{public}s",
        photoAlbum.albumName.c_str(),
        albumName.c_str(),
        photoAlbum.lPath.c_str());
    return albumName;
}

/**
 * @brief get the data of PhotoAlbum table, to find the differenct between the PhotoAlbum and the gallery_album
 */
std::vector<PhotoAlbumDao::PhotoAlbumRowData> PhotoAlbumDao::GetPhotoAlbums()
{
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> result;
    std::string querySql = this->SQL_PHOTO_ALBUM_SELECT;
    int rowCount = 0;
    int offset = 0;
    int pageSize = 200;
    do {
        std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
        auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            PhotoAlbumDao::PhotoAlbumRowData albumRowData;
            albumRowData.albumId = GetInt32Val(this->FIELD_NAME_ALBUM_ID, resultSet);
            albumRowData.albumName = GetStringVal(this->FIELD_NAME_ALBUM_NAME, resultSet);
            albumRowData.bundleName = GetStringVal(this->FIELD_NAME_BUNDLE_NAME, resultSet);
            albumRowData.albumType = GetInt32Val(this->FIELD_NAME_ALBUM_TYPE, resultSet);
            albumRowData.albumSubType = GetInt32Val(this->FIELD_NAME_ALBUM_SUBTYPE, resultSet);
            albumRowData.lPath = GetStringVal(this->FIELD_NAME_LPATH, resultSet);
            albumRowData.priority = GetInt32Val(this->FIELD_NAME_PRIORITY, resultSet);
            result.emplace_back(albumRowData);
        }
        // Check if there are more rows to fetch.
        resultSet->GetRowCount(rowCount);
        offset += pageSize;
    } while (rowCount > 0);
    return result;
}

/**
 * @brief Get and cache PhotoAlbum info by lPath from PhotoAlbum table.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotoAlbumDao::GetPhotoAlbum(const std::string &lPath)
{
    // find the PhotoAlbum info by lPath in cache
    if (this->photoAlbumCache_.count(StringUtils::ToLower(lPath)) > 0) {
        return this->photoAlbumCache_[StringUtils::ToLower(lPath)];
    }
    MEDIA_INFO_LOG("Media_Restore: can not find the PhotoAlbum info by lPath in cache."
                   " lPath=%{public}s, lPath in cache=%{public}s",
        lPath.c_str(),
        StringUtils::ToLower(lPath).c_str());
    PhotoAlbumDao::PhotoAlbumRowData albumRowData;
    // query the PhotoAlbum info by lPath from PhotoAlbum table
    std::vector<NativeRdb::ValueObject> bindArgs = {lPath};
    std::string querySql = this->SQL_PHOTO_ALBUM_SELECT_BY_LPATH;
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToNextRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return albumRowData;
    }
    albumRowData.albumId = GetInt32Val(this->FIELD_NAME_ALBUM_ID, resultSet);
    albumRowData.albumName = GetStringVal(this->FIELD_NAME_ALBUM_NAME, resultSet);
    albumRowData.bundleName = GetStringVal(this->FIELD_NAME_BUNDLE_NAME, resultSet);
    albumRowData.albumType = GetInt32Val(this->FIELD_NAME_ALBUM_TYPE, resultSet);
    albumRowData.albumSubType = GetInt32Val(this->FIELD_NAME_ALBUM_SUBTYPE, resultSet);
    albumRowData.lPath = GetStringVal(this->FIELD_NAME_LPATH, resultSet);
    albumRowData.priority = GetInt32Val(this->FIELD_NAME_PRIORITY, resultSet);
    // cache the PhotoAlbum info by lPath
    this->photoAlbumCache_[StringUtils::ToLower(lPath)] = albumRowData;
    return albumRowData;
}

/**
 * @brief Get and cache PhotoAlbum info by lPath, if PhotoAlbum not exists, create it.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotoAlbumDao::GetOrCreatePhotoAlbum(const PhotoAlbumRowData &album)
{
    // validate inputs
    PhotoAlbumDao::PhotoAlbumRowData result;
    if (album.lPath.empty()) {
        return result;
    }
    // try to get from cache
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->GetPhotoAlbum(album.lPath);
    if (!albumRowData.lPath.empty()) {
        return albumRowData;
    }
    std::string uniqueAlbumName = this->FindUniqueAlbumName(album);
    std::vector<NativeRdb::ValueObject> bindArgs = {
        album.albumType, album.albumSubType, uniqueAlbumName, album.bundleName, album.lPath, album.priority};
    auto err = this->mediaLibraryRdb_->ExecuteSql(this->SQL_PHOTO_ALBUM_INSERT, bindArgs);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("INSERT INTO PhotoAlbum failed, err = %{public}d", err);
        return result;
    }
    MEDIA_INFO_LOG("INSERT INTO PhotoAlbum success, albumName = %{public}s, lPath = %{public}s",
        album.albumName.c_str(),
        album.lPath.c_str());
    return this->GetPhotoAlbum(album.lPath);
}

void DEBUG_LOG_TO_CONSOLE(const std::string &executeSql, std::vector<NativeRdb::ValueObject> &bindArgs)
{
    std::string args;
    for (auto &arg : bindArgs) {
        std::string tempStr;
        arg.GetString(tempStr);
        args += tempStr + ", ";
    }
    MEDIA_INFO_LOG("Media_Restore: executeSql = %{public}s, \
        bindArgs = %{public}s",
        executeSql.c_str(),
        args.c_str());
}

/**
 * @brief restore the PhotoAlbum table
 */
int32_t PhotoAlbumDao::RestoreAlbums(std::vector<PhotoAlbumDao::PhotoAlbumRowData> &photoAlbums)
{
    if (photoAlbums.empty()) {
        MEDIA_INFO_LOG("albumInfos are empty");
        return NativeRdb::E_OK;
    }
    int32_t err = NativeRdb::E_OK;
    this->mediaLibraryRdb_->BeginTransaction();
    for (const PhotoAlbumDao::PhotoAlbumRowData &data : photoAlbums) {
        std::vector<NativeRdb::ValueObject> bindArgs = {
            data.albumType, data.albumSubType, data.albumName, data.bundleName, data.lPath, data.priority};
        DEBUG_LOG_TO_CONSOLE(this->SQL_PHOTO_ALBUM_INSERT, bindArgs);
        err = this->mediaLibraryRdb_->ExecuteSql(this->SQL_PHOTO_ALBUM_INSERT, bindArgs);
        if (err != NativeRdb::E_OK) {
            this->mediaLibraryRdb_->RollBack();
            return err;
        }
    }
    this->mediaLibraryRdb_->Commit();
    MEDIA_INFO_LOG("restore albums success, %{public}d albums", static_cast<int32_t>(photoAlbums.size()));
    return NativeRdb::E_OK;
}
}  // namespace OHOS::Media