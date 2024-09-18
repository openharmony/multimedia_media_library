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
#include "photos_clone.h"

#include <uuid.h>
#include <numeric>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "photo_album_dao.h"
#include "backup_const.h"
#include "media_log.h"

namespace OHOS::Media {
/**
 * @brief Get Row Count of Photos in Album.
 */
int32_t PhotosClone::GetPhotosRowCountInPhotoMap()
{
    std::string querySql = this->SQL_PHOTOS_TABLE_COUNT_IN_PHOTO_MAP;
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Get Row Count of Photos not in Album.
 */
int32_t PhotosClone::GetPhotosRowCountNotInPhotoMap()
{
    std::string querySql = this->SQL_PHOTOS_TABLE_COUNT_NOT_IN_PHOTO_MAP;
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Query the Photos Info, which is in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetPhotosInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_PHOTOS_TABLE_QUERY_IN_PHOTO_MAP, bindArgs);
}

/**
 * @brief Query the Photos Info, which is not in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetPhotosNotInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_PHOTOS_TABLE_QUERY_NOT_IN_PHOTO_MAP, bindArgs);
}

/**
 * @brief Find the albumId of the PhotoAlbum related to Photos from target database.
 */
int32_t PhotosClone::FindAlbumId(const FileInfo &fileInfo)
{
    if (fileInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Media_Restore: FindAlbumId-lPath is empty, lPath=%{public}s", fileInfo.lPath.c_str());
        return 0;
    }
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->photoAlbumDaoPtr_->GetPhotoAlbum(fileInfo.lPath);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Media_Restore: albumInfo is empty, lPath=%{public}s, albumInfo = %{public}s",
            fileInfo.lPath.c_str(),
            this->photoAlbumDaoPtr_->ToString(albumInfo).c_str());
    }
    return albumInfo.albumId;
}

/**
 * @brief Find the packageName of the PhotoAlbum related to Photos from target database.
 */
std::string PhotosClone::FindPackageName(const FileInfo &fileInfo)
{
    if (fileInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Media_Restore: FindPackageName-lPath is empty, lPath=%{public}s", fileInfo.lPath.c_str());
        return "";
    }
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->photoAlbumDaoPtr_->GetPhotoAlbum(fileInfo.lPath);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("albumInfo is empty, lPath=%{public}s, albumInfo = %{public}s",
            fileInfo.lPath.c_str(),
            this->photoAlbumDaoPtr_->ToString(albumInfo).c_str());
        return "";
    }
    // Only provide the package name of the SOURCE album.
    if (albumInfo.albumType != static_cast<int32_t>(PhotoAlbumType::SOURCE) ||
        albumInfo.albumSubType != static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC)) {
        return "";
    }
    return albumInfo.albumName;
}

/**
 * @brief Find the bundleName of the PhotoAlbum related to Photos from target database.
 */
std::string PhotosClone::FindBundleName(const FileInfo &fileInfo)
{
    if (fileInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Media_Restore: FindBundleName-lPath is empty, lPath=%{public}s", fileInfo.lPath.c_str());
        return "";
    }
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->photoAlbumDaoPtr_->GetPhotoAlbum(fileInfo.lPath);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("albumInfo is empty, lPath=%{public}s, albumInfo = %{public}s",
            fileInfo.lPath.c_str(),
            this->photoAlbumDaoPtr_->ToString(albumInfo).c_str());
        return "";
    }
    // Only provide the bundle name of the SOURCE album.
    if (albumInfo.albumType != static_cast<int32_t>(PhotoAlbumType::SOURCE) ||
        albumInfo.albumSubType != static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC)) {
        return "";
    }
    return albumInfo.bundleName;
}

std::vector<PhotosDao::PhotosRowData> PhotosClone::FindDuplicateBurstKey()
{
    std::vector<PhotosDao::PhotosRowData> result;
    std::string querySql = this->SQL_PHOTOS_TABLE_BURST_KEY_DUPLICATE_QUERY;
    int rowCount = 0;
    int offset = 0;
    int pageSize = 200;
    do {
        std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
        auto resultSet = this->mediaLibraryTargetRdb_->QuerySql(querySql, bindArgs);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            PhotosDao::PhotosRowData info;
            info.burstKey = GetStringVal("burst_key", resultSet);
            info.ownerAlbumId = GetInt32Val("owner_album_id", resultSet);
            result.emplace_back(info);
        }
        // Check if there are more rows to fetch.
        resultSet->GetRowCount(rowCount);
        offset += pageSize;
    } while (rowCount > 0);
    return result;
}

std::string PhotosClone::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    for (auto &value : values) {
        std::string str;
        value.GetString(str);
        result.emplace_back(str);
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

/**
 * @brief generate a uuid
 *
 * @return std::string uuid with 32 characters
 */
std::string PhotosClone::GenerateUuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

/**
 * @brief Fix Duplicate burst_key in Photos, which is used in different PhotoAlbum.
 */
int32_t PhotosClone::FixDuplicateBurstKeyInDifferentAlbum()
{
    std::vector<PhotosDao::PhotosRowData> duplicateBurstKeyList = this->FindDuplicateBurstKey();
    std::string executeSql = this->SQL_PHOTOS_TABLE_BURST_KEY_UPDATE;
    for (auto &info : duplicateBurstKeyList) {
        std::string burstKeyNew = this->GenerateUuid();
        std::vector<NativeRdb::ValueObject> bindArgs = {burstKeyNew, info.ownerAlbumId, info.burstKey};
        MEDIA_INFO_LOG("Media_Restore: executeSql = %{public}s, bindArgs=%{public}s",
            executeSql.c_str(),
            this->ToString(bindArgs).c_str());
        int32_t ret = this->mediaLibraryTargetRdb_->ExecuteSql(executeSql, bindArgs);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: FixDuplicateBurstKeyInDifferentAlbum failed,"
                          " ret=%{public}d, sql=%{public}s, bindArgs=%{public}s",
                ret,
                executeSql.c_str(),
                this->ToString(bindArgs).c_str());
        }
    }
    return 0;
}
}  // namespace OHOS::Media