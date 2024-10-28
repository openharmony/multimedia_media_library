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
#include "album_plugin_config.h"
#include "userfile_manager_types.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_transaction.h"

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
    if (this->mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryRdb_ is null.");
        return true;
    }
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToNextRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: Query resultSql is null.");
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
        MEDIA_ERR_LOG("Media_Restore: Invalid album data");
        return "";
    }
    const std::string lPath = photoAlbum.lPath;
    // The PhotoAlbum is cached.
    PhotoAlbumDao::PhotoAlbumRowData albumDataInCache;
    if (this->photoAlbumCache_.Find(StringUtils::ToLower(lPath), albumDataInCache)) {
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
    MEDIA_INFO_LOG("Media_Restore: FindUniqueAlbumName, old name: %{public}s, new name: %{public}s, lPath: %{public}s",
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
        if (this->mediaLibraryRdb_ == nullptr) {
            MEDIA_ERR_LOG("Media_Restore: mediaLibraryRdb_ is null.");
            break;
        }
        auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Media_Restore: Query resultSql is null.");
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
    std::unique_lock<std::mutex> lock(this->cacheLock_);
    // find the PhotoAlbum info by lPath in cache
    PhotoAlbumDao::PhotoAlbumRowData albumRowData;
    if (this->photoAlbumCache_.Find(StringUtils::ToLower(lPath), albumRowData)) {
        return albumRowData;
    }
    MEDIA_INFO_LOG("Media_Restore: can not find the PhotoAlbum info by lPath in cache."
                   " lPath=%{public}s, lPath in cache=%{public}s",
        lPath.c_str(),
        StringUtils::ToLower(lPath).c_str());
    // query the PhotoAlbum info by lPath from PhotoAlbum table
    std::vector<NativeRdb::ValueObject> bindArgs = {lPath};
    std::string querySql = this->SQL_PHOTO_ALBUM_SELECT_BY_LPATH;
    if (this->mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryRdb_ is null.");
        return albumRowData;
    }
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToNextRow() != NativeRdb::E_OK) {
        MEDIA_WARN_LOG("Media_Restore: can not find the PhotoAlbum info by lPath [%{public}s] in PhotoAlbum table.",
            lPath.c_str());
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
    this->photoAlbumCache_.Insert(StringUtils::ToLower(lPath), albumRowData);
    MEDIA_INFO_LOG("Media_Restore: add the PhotoAlbum info by lPath into cache."
                   " lPath=%{public}s, lPath in cache=%{public}s",
        lPath.c_str(),
        StringUtils::ToLower(albumRowData.lPath).c_str());
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
        MEDIA_ERR_LOG(
            "Media_Restore: Invalid album data, lPath is empty. Object: %{public}s", this->ToString(album).c_str());
        return result;
    }
    std::unique_lock<std::mutex> lock(this->photoAlbumCreateLock_);
    // try to get from cache
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->GetPhotoAlbum(album.lPath);
    if (!albumRowData.lPath.empty()) {
        return albumRowData;
    }
    std::string uniqueAlbumName = this->FindUniqueAlbumName(album);
    std::vector<NativeRdb::ValueObject> bindArgs = {
        album.albumType, album.albumSubType, uniqueAlbumName, album.bundleName, album.lPath, album.priority};
    if (this->mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryRdb_ is null.");
        return result;
    }
    TransactionOperations transactionOprn(this->mediaLibraryRdb_);
    auto errCode = transactionOprn.Start(true);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG(
            "Media_Restore: INSERT INTO PhotoAlbum failed, can not get rdb transaction. err = %{public}d", errCode);
        return result;
    }
    auto err = this->mediaLibraryRdb_->ExecuteSql(this->SQL_PHOTO_ALBUM_INSERT, bindArgs);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: INSERT INTO PhotoAlbum failed, err = %{public}d, executeSql = %{public}s, "
                      "bindArgs = %{public}s",
            err,
            this->SQL_PHOTO_ALBUM_INSERT.c_str(),
            this->ToString(bindArgs).c_str());
        return result;
    }
    transactionOprn.Finish();
    MEDIA_INFO_LOG("Media_Restore: INSERT INTO PhotoAlbum success, Object: %{public}s", this->ToString(album).c_str());
    return this->GetPhotoAlbum(album.lPath);
}

std::string PhotoAlbumDao::ToString(const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    std::string args;
    for (auto &arg : bindArgs) {
        std::string tempStr;
        arg.GetString(tempStr);
        args += tempStr + ", ";
    }
    return args;
}

/**
 * @brief restore the PhotoAlbum table
 */
int32_t PhotoAlbumDao::RestoreAlbums(std::vector<PhotoAlbumDao::PhotoAlbumRowData> &photoAlbums)
{
    if (photoAlbums.empty()) {
        MEDIA_INFO_LOG("Media_Restore: albumInfos are empty");
        return NativeRdb::E_OK;
    }
    int32_t err = NativeRdb::E_OK;
    if (this->mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryRdb_ is null.");
        return E_FAIL;
    }
    for (const PhotoAlbumDao::PhotoAlbumRowData &data : photoAlbums) {
        std::vector<NativeRdb::ValueObject> bindArgs = {
            data.albumType, data.albumSubType, data.albumName, data.bundleName, data.lPath, data.priority};
        err = this->mediaLibraryRdb_->ExecuteSql(this->SQL_PHOTO_ALBUM_INSERT, bindArgs);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: restore albums failed, "
                          "err = %{public}d, executeSql = %{public}s, bindArgs = %{public}s",
                err,
                this->SQL_PHOTO_ALBUM_INSERT.c_str(),
                this->ToString(bindArgs).c_str());
        }
    }
    MEDIA_INFO_LOG(
        "Media_Restore: restore albums success, %{public}d albums", static_cast<int32_t>(photoAlbums.size()));
    return NativeRdb::E_OK;
}

/**
 * @brief Build PhotoAlbumRowData for ScreenRecorder.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotoAlbumDao::BuildAlbumInfoOfRecorders()
{
    PhotoAlbumRowData albumInfo;
    // bind albumName and bundleName by lPath.
    albumInfo.albumName = AlbumPlugin::ALBUM_NAME_SCREEN_RECORDS;
    albumInfo.bundleName = AlbumPlugin::BUNDLE_NAME_SCREEN_RECORDS;
    albumInfo.lPath = AlbumPlugin::LPATH_SCREEN_RECORDS;
    albumInfo.albumType = static_cast<int32_t>(PhotoAlbumType::SOURCE);
    albumInfo.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC);
    albumInfo.priority = 1;
    return albumInfo;
}
}  // namespace OHOS::Media