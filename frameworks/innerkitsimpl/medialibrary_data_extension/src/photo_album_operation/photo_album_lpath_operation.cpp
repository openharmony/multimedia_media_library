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
#define MLOG_TAG "PhotoAlbumLPathOperation"

#include "photo_album_lpath_operation.h"

#include <algorithm>
#include <numeric>

#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "photo_album_merge_operation.h"

namespace OHOS::Media {
PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::SetRdbStore(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr)
{
    this->rdbStorePtr_ = rdbStorePtr;
    return *this;
}

int32_t PhotoAlbumLPathOperation::GetAlbumAffectedCount() const
{
    return this->albumAffectedCount_;
}

PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::CleanInvalidPhotoAlbums()
{
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> invalidAlbumList = this->GetInvalidPhotoAlbums();
    if (invalidAlbumList.empty()) {
        MEDIA_INFO_LOG("Media_Operation: no invalid album found.");
        return *this;
    }
    // Log the invalid albums
    int index = 0;
    for (const auto &albumInfo : invalidAlbumList) {
        MEDIA_INFO_LOG("Media_Operation: clean invalid album! index: %{public}d, Object: %{public}s",
            ++index,
            albumInfo.ToString().c_str());
    }
    this->albumAffectedCount_ += static_cast<int32_t>(invalidAlbumList.size());
    // Delete the invalid albums
    std::string sql = this->SQL_PHOTO_ALBUM_EMPTY_DELETE;
    auto result = this->rdbStorePtr_->ExecuteSql(sql);
    MEDIA_INFO_LOG("Media_Operation: clean invalid album completed! result: %{public}d", result);
    return *this;
}

std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> PhotoAlbumLPathOperation::GetInvalidPhotoAlbums()
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_EMPTY_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: resultSet is null! querySql: %{public}s", querySql.c_str());
        return {};
    }
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoAlbumLPathOperation::PhotoAlbumInfo info;
        info.albumId = GetInt64Val("album_id", resultSet);
        info.albumName = GetStringVal("album_name", resultSet);
        info.albumType = GetInt32Val("album_type", resultSet);
        info.albumSubType = GetInt32Val("album_subtype", resultSet);
        info.lPath = GetStringVal("lpath", resultSet);
        info.bundleName = GetStringVal("bundle_name", resultSet);
        info.dirty = GetInt32Val("dirty", resultSet);
        info.count = GetInt32Val("count", resultSet);
        info.cloudId = GetStringVal("cloud_id", resultSet);
        info.priority = GetInt32Val("priority", resultSet);
        result.emplace_back(info);
    }
    return result;
}

PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::CleanDuplicatePhotoAlbums()
{
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> mainAlbumInfoList = this->GetDuplicatelPathAlbumInfoMain();
    if (mainAlbumInfoList.empty()) {
        MEDIA_INFO_LOG("Media_Operation: no duplicate album found.");
        return *this;
    }
    // Execute & Log the duplicate albums
    int index = 0;
    int32_t total = static_cast<int32_t>(mainAlbumInfoList.size());
    for (const auto &albumInfo : mainAlbumInfoList) {
        int32_t ret = this->CleanDuplicatePhotoAlbum(albumInfo);
        MEDIA_INFO_LOG("Media_Operation: clean duplicate album (MAIN) completed! "
                       "index: %{public}d / %{public}d, ret: %{public}d, Object: %{public}s",
            ++index,
            total,
            ret,
            albumInfo.ToString().c_str());
    }
    this->albumAffectedCount_ += total;
    return *this;
}

int32_t PhotoAlbumLPathOperation::CleanDuplicatePhotoAlbum(
    const PhotoAlbumLPathOperation::PhotoAlbumInfo &mainAlbumInfo)
{
    bool isInvalid = mainAlbumInfo.albumId <= 0 || mainAlbumInfo.lPath.empty() || mainAlbumInfo.albumName.empty();
    if (isInvalid) {
        MEDIA_ERR_LOG("Media_Operation: invalid main album found.");
        return NativeRdb::E_OK;
    }
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> subAlbumInfoList =
        this->GetDuplicatelPathAlbumInfoSub(mainAlbumInfo);
    if (subAlbumInfoList.empty()) {
        MEDIA_INFO_LOG(
            "Media_Operation: no duplicate album found. mainAlbum: %{public}s", mainAlbumInfo.ToString().c_str());
        return NativeRdb::E_OK;
    }
    int32_t index = 0;
    int32_t total = static_cast<int32_t>(subAlbumInfoList.size());
    for (const auto &subAlbumInfo : subAlbumInfoList) {
        index++;
        isInvalid = subAlbumInfo.albumId <= 0 || subAlbumInfo.lPath.empty() || subAlbumInfo.albumName.empty();
        if (isInvalid) {
            MEDIA_ERR_LOG("Media_Operation: subAlbumInfo invalid. "
                          "index: %{public}d / %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
                index,
                total,
                mainAlbumInfo.ToString().c_str(),
                subAlbumInfo.ToString().c_str());
            continue;
        }
        int32_t err = this->MergePhotoAlbum(mainAlbumInfo, subAlbumInfo);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG(
                "Media_Operation: Photos merge main & sub album failed, "
                "err: %{public}d, index: %{public}d / %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
                err,
                index,
                total,
                mainAlbumInfo.ToString().c_str(),
                subAlbumInfo.ToString().c_str());
            continue;
        }
        MEDIA_INFO_LOG("Media_Operation: clean duplicate album (sub) completed! "
                       "index: %{public}d / %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
            index,
            total,
            mainAlbumInfo.ToString().c_str(),
            subAlbumInfo.ToString().c_str());
    }
    return NativeRdb::E_OK;
}

PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::CleanEmptylPathPhotoAlbums()
{
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> subAlbumInfoList = this->GetEmptylPathAlbumInfo();
    if (subAlbumInfoList.empty()) {
        MEDIA_INFO_LOG("Media_Operation: no empty lPath album found.");
        return *this;
    }
    // Execute & Log the empty albums
    int32_t index = 0;
    int32_t total = static_cast<int32_t>(subAlbumInfoList.size());
    for (const auto &subAlbumInfo : subAlbumInfoList) {
        index++;
        int32_t ret = this->CleanEmptylPathPhotoAlbum(subAlbumInfo);
        MEDIA_INFO_LOG("Media_Operation: clean empty lPath album completed! "
                       "index: %{public}d / %{public}d, ret: %{public}d, subAlbum: %{public}s",
            index,
            total,
            ret,
            subAlbumInfo.ToString().c_str());
    }
    this->albumAffectedCount_ += total;
    return *this;
}

std::string PhotoAlbumLPathOperation::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    for (auto &value : values) {
        std::string str;
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

int32_t PhotoAlbumLPathOperation::UpdateAlbumByAlbumPlugin(const PhotoAlbumInfo &albumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return NativeRdb::E_ERROR;
    }
    bool isInvalid = albumInfo.lPath.empty();
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    std::string sql = this->SQL_PHOTO_ALBUM_QUERY_BY_LPATH;
    const std::vector<NativeRdb::ValueObject> bindArgs = {
        albumInfo.lPath, albumInfo.lPath, albumInfo.lPath, albumInfo.lPath};
    auto ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumLPathOperation::UpdateAlbumLPathByAlbumId(const PhotoAlbumInfo &albumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return NativeRdb::E_ERROR;
    }
    bool isInvalid = albumInfo.lPath.empty() || albumInfo.albumId <= 0;
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    std::string sql = this->SQL_PHOTO_ALBUM_UPDATE_LPATH_BY_ALBUM_ID;
    const std::vector<NativeRdb::ValueObject> bindArgs = {albumInfo.lPath, albumInfo.albumId, albumInfo.lPath};
    auto ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

PhotoAlbumLPathOperation::PhotoAlbumInfo PhotoAlbumLPathOperation::GetAlbumInfoBylPath(const std::string &lPath)
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return PhotoAlbumLPathOperation::PhotoAlbumInfo();
    }
    if (lPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: lPath is empty.");
        return PhotoAlbumLPathOperation::PhotoAlbumInfo();
    }
    std::string sql = this->SQL_PHOTO_ALBUM_QUERY_BY_LPATH;
    const std::vector<NativeRdb::ValueObject> bindArgs = {lPath};
    auto resultSet = this->rdbStorePtr_->QuerySql(sql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: resultSet is null! querySql: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return PhotoAlbumLPathOperation::PhotoAlbumInfo();
    }
    PhotoAlbumLPathOperation::PhotoAlbumInfo info;
    info.albumId = GetInt64Val("album_id", resultSet);
    info.albumName = GetStringVal("album_name", resultSet);
    info.albumType = GetInt32Val("album_type", resultSet);
    info.albumSubType = GetInt32Val("album_subtype", resultSet);
    info.lPath = GetStringVal("lpath", resultSet);
    info.bundleName = GetStringVal("bundle_name", resultSet);
    info.dirty = GetInt32Val("dirty", resultSet);
    info.count = GetInt32Val("count", resultSet);
    info.cloudId = GetStringVal("cloud_id", resultSet);
    info.priority = GetInt32Val("priority", resultSet);
    return info;
}

int32_t PhotoAlbumLPathOperation::CleanEmptylPathPhotoAlbum(
    const PhotoAlbumLPathOperation::PhotoAlbumInfo &subAlbumInfo)
{
    bool isInvalid = subAlbumInfo.albumId <= 0 || subAlbumInfo.lPath.empty() || subAlbumInfo.albumName.empty();
    if (isInvalid) {
        MEDIA_ERR_LOG("Media_Operation: subAlbumInfo invalid. subAlbum: %{public}s", subAlbumInfo.ToString().c_str());
        return NativeRdb::E_OK;
    }
    PhotoAlbumLPathOperation::PhotoAlbumInfo mainAlbumInfo = this->GetAlbumInfoBylPath(subAlbumInfo.lPath);
    bool isMainAlbumInvalid =
        mainAlbumInfo.albumId <= 0 || mainAlbumInfo.lPath.empty() || mainAlbumInfo.albumName.empty();
    if (!isMainAlbumInvalid) {
        int32_t err = this->MergePhotoAlbum(mainAlbumInfo, subAlbumInfo);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Operation: Photos merge album failed, "
                          "err: %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
                err,
                mainAlbumInfo.ToString().c_str(),
                subAlbumInfo.ToString().c_str());
            return err;
        }
    } else {
        int32_t err = this->UpdateAlbumLPathByAlbumId(subAlbumInfo);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Operation: Update Album LPath By AlbumId failed, "
                          "err: %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
                err,
                mainAlbumInfo.ToString().c_str(),
                subAlbumInfo.ToString().c_str());
            return err;
        }
        mainAlbumInfo = subAlbumInfo;
    }
    int32_t err = this->UpdateAlbumByAlbumPlugin(mainAlbumInfo);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Update Album By AlbumPlugin failed, "
                      "err: %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
            err,
            mainAlbumInfo.ToString().c_str(),
            subAlbumInfo.ToString().c_str());
        return err;
    }
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumLPathOperation::MergePhotoAlbum(const PhotoAlbumLPathOperation::PhotoAlbumInfo &mainAlbumInfo,
    const PhotoAlbumLPathOperation::PhotoAlbumInfo &subAlbumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return NativeRdb::E_OK;
    }
    if (mainAlbumInfo.albumId <= 0 || subAlbumInfo.albumId <= 0) {
        MEDIA_ERR_LOG("Media_Operation: mainAlbum or subAlbum invalid, mainAlbum: %{public}s, subAlbum: %{public}s",
            mainAlbumInfo.ToString().c_str(),
            subAlbumInfo.ToString().c_str());
        return NativeRdb::E_OK;
    }
    return PhotoAlbumMergeOperation()
        .SetRdbStore(this->rdbStorePtr_)
        .MergeAlbum(subAlbumInfo.albumId, mainAlbumInfo.albumId);
}

std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> PhotoAlbumLPathOperation::GetDuplicatelPathAlbumInfoMain()
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_DUPLICATE_LPATH_MAIN_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: resultSet is null! querySql: %{public}s", querySql.c_str());
        return {};
    }
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoAlbumLPathOperation::PhotoAlbumInfo info;
        info.albumId = GetInt64Val("album_id", resultSet);
        info.albumName = GetStringVal("album_name", resultSet);
        info.albumType = GetInt32Val("album_type", resultSet);
        info.albumSubType = GetInt32Val("album_subtype", resultSet);
        info.lPath = GetStringVal("lpath", resultSet);
        info.bundleName = GetStringVal("bundle_name", resultSet);
        info.dirty = GetInt32Val("dirty", resultSet);
        info.count = GetInt32Val("count", resultSet);
        info.cloudId = GetStringVal("cloud_id", resultSet);
        info.priority = GetInt32Val("priority", resultSet);
        result.emplace_back(info);
    }
    return result;
}

std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> PhotoAlbumLPathOperation::GetDuplicatelPathAlbumInfoSub(
    const PhotoAlbumInfo &albumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return {};
    }
    if (albumInfo.albumId <= 0 || albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: albumId or lPath is invalid.");
        return {};
    }
    std::string sql = this->SQL_PHOTO_ALBUM_DUPLICATE_LPATH_SUB_QUERY;
    const std::vector<NativeRdb::ValueObject> bindArgs = {albumInfo.albumId, albumInfo.lPath};
    auto resultSet = this->rdbStorePtr_->QuerySql(sql, bindArgs);
    if (resultSet == nullptr) {
        MEDIA_WARN_LOG("Media_Operation: resultSet is null! querySql: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return {};
    }
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoAlbumLPathOperation::PhotoAlbumInfo info;
        info.albumId = GetInt64Val("album_id", resultSet);
        info.albumName = GetStringVal("album_name", resultSet);
        info.albumType = GetInt32Val("album_type", resultSet);
        info.albumSubType = GetInt32Val("album_subtype", resultSet);
        info.lPath = GetStringVal("lpath", resultSet);
        info.bundleName = GetStringVal("bundle_name", resultSet);
        info.dirty = GetInt32Val("dirty", resultSet);
        info.count = GetInt32Val("count", resultSet);
        info.cloudId = GetStringVal("cloud_id", resultSet);
        info.priority = GetInt32Val("priority", resultSet);
        result.emplace_back(info);
    }
    return result;
}

std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> PhotoAlbumLPathOperation::GetEmptylPathAlbumInfo()
{
    if (this->rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: rdbStore is null.");
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_FIX_LPATH_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: resultSet is null! querySql: %{public}s", querySql.c_str());
        return {};
    }
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoAlbumLPathOperation::PhotoAlbumInfo info;
        info.albumId = GetInt64Val("album_id", resultSet);
        info.albumName = GetStringVal("album_name", resultSet);
        info.albumType = GetInt32Val("album_type", resultSet);
        info.albumSubType = GetInt32Val("album_subtype", resultSet);
        info.lPath = GetStringVal("lpath", resultSet);
        info.bundleName = GetStringVal("bundle_name", resultSet);
        info.dirty = GetInt32Val("dirty", resultSet);
        info.count = GetInt32Val("count", resultSet);
        info.cloudId = GetStringVal("cloud_id", resultSet);
        info.priority = GetInt32Val("priority", resultSet);
        result.emplace_back(info);
    }
    return result;
}
}  // namespace OHOS::Media