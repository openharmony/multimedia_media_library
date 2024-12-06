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
    std::vector<PhotoAlbumInfoPo> invalidAlbumList = this->GetInvalidPhotoAlbums();
    if (invalidAlbumList.empty()) {
        MEDIA_INFO_LOG("Media_Operation: no invalid album found.");
        return *this;
    }
    // Log the invalid albums
    int32_t index = 0;
    int32_t total = static_cast<int32_t>(invalidAlbumList.size());
    for (const auto &albumInfo : invalidAlbumList) {
        MEDIA_INFO_LOG("Media_Operation: clean invalid album! index: %{public}d / %{public}d, Object: %{public}s",
            ++index,
            total,
            albumInfo.ToString().c_str());
    }
    this->albumAffectedCount_ += static_cast<int32_t>(invalidAlbumList.size());
    // Delete the invalid albums
    std::string sql = this->SQL_PHOTO_ALBUM_EMPTY_DELETE;
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Failed to exec: %{public}s", sql.c_str());
    }
    MEDIA_INFO_LOG("Media_Operation: clean invalid album completed! "
                   "total: %{public}d, ret: %{public}d",
        total,
        ret);
    return *this;
}

std::vector<PhotoAlbumInfoPo> PhotoAlbumLPathOperation::GetInvalidPhotoAlbums()
{
    if (this->rdbStorePtr_ == nullptr) {
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_EMPTY_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        return {};
    }
    std::vector<PhotoAlbumInfoPo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        result.emplace_back(PhotoAlbumInfoPo().Parse(resultSet));
    }
    return result;
}

PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::CleanDuplicatePhotoAlbums()
{
    std::vector<PhotoAlbumInfoPo> mainAlbumInfoList = this->GetDuplicatelPathAlbumInfoMain();
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

int32_t PhotoAlbumLPathOperation::CleanDuplicatePhotoAlbum(const PhotoAlbumInfoPo &mainAlbumInfo)
{
    bool isInvalid = mainAlbumInfo.albumId <= 0 || mainAlbumInfo.lPath.empty() || mainAlbumInfo.albumName.empty();
    if (isInvalid) {
        return NativeRdb::E_OK;
    }
    std::vector<PhotoAlbumInfoPo> subAlbumInfoList = this->GetDuplicatelPathAlbumInfoSub(mainAlbumInfo);
    if (subAlbumInfoList.empty()) {
        return NativeRdb::E_OK;
    }
    int32_t index = 0;
    int32_t total = static_cast<int32_t>(subAlbumInfoList.size());
    for (const auto &subAlbumInfo : subAlbumInfoList) {
        index++;
        bool isInvalidSub = subAlbumInfo.albumId <= 0 || subAlbumInfo.lPath.empty() || subAlbumInfo.albumName.empty();
        isInvalidSub = isInvalidSub || this->MergePhotoAlbum(mainAlbumInfo, subAlbumInfo) != NativeRdb::E_OK;
        MEDIA_INFO_LOG("Media_Operation: clean duplicate album (sub) completed! "
                       "index: %{public}d / %{public}d, "
                       "isInvalid: %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
            index,
            total,
            isInvalidSub,
            mainAlbumInfo.ToString().c_str(),
            subAlbumInfo.ToString().c_str());
    }
    return this->UpdateAlbumInfoFromAlbumPluginByAlbumId(mainAlbumInfo);
}

PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::CleanEmptylPathPhotoAlbums()
{
    std::vector<PhotoAlbumInfoPo> subAlbumInfoList = this->GetEmptylPathAlbumInfo();
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
    std::string str;
    for (auto &value : values) {
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

int32_t PhotoAlbumLPathOperation::UpdateAlbumInfoFromAlbumPluginByAlbumId(const PhotoAlbumInfoPo &albumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        return NativeRdb::E_ERROR;
    }
    bool isInvalid = albumInfo.albumId <= 0 || albumInfo.lPath.empty();
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    std::string sql = this->SQL_PHOTO_ALBUM_SYNC_BUNDLE_NAME_UPDATE;
    const std::vector<NativeRdb::ValueObject> bindArgs = {
        albumInfo.lPath, albumInfo.lPath, albumInfo.lPath, albumInfo.albumId, albumInfo.lPath};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumLPathOperation::UpdateAlbumLPathByAlbumId(const PhotoAlbumInfoPo &albumInfo)
{
    if (this->rdbStorePtr_ == nullptr) {
        return NativeRdb::E_ERROR;
    }
    bool isInvalid = albumInfo.lPath.empty() || albumInfo.albumId <= 0;
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    std::string sql = this->SQL_PHOTO_ALBUM_UPDATE_LPATH_BY_ALBUM_ID;
    const std::vector<NativeRdb::ValueObject> bindArgs = {albumInfo.lPath, albumInfo.albumId, albumInfo.lPath};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s",
            sql.c_str(),
            this->ToString(bindArgs).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

PhotoAlbumInfoPo PhotoAlbumLPathOperation::GetLatestAlbumInfoBylPath(const std::string &lPath)
{
    if (this->rdbStorePtr_ == nullptr || lPath.empty()) {
        return PhotoAlbumInfoPo();
    }
    std::string sql = this->SQL_PHOTO_ALBUM_QUERY_BY_LPATH;
    const std::vector<NativeRdb::ValueObject> bindArgs = {lPath};
    auto resultSet = this->rdbStorePtr_->QuerySql(sql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return PhotoAlbumInfoPo();
    }
    return PhotoAlbumInfoPo().Parse(resultSet);
}

int32_t PhotoAlbumLPathOperation::CleanEmptylPathPhotoAlbum(const PhotoAlbumInfoPo &subAlbumInfo)
{
    bool isInvalid = subAlbumInfo.albumId <= 0 || subAlbumInfo.lPath.empty() || subAlbumInfo.albumName.empty();
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    PhotoAlbumInfoPo mainAlbumInfo = this->GetLatestAlbumInfoBylPath(subAlbumInfo.lPath);
    bool isMainAlbumInvalid =
        mainAlbumInfo.albumId <= 0 || mainAlbumInfo.lPath.empty() || mainAlbumInfo.albumName.empty();
    bool isSuccessed = false;
    if (!isMainAlbumInvalid) {
        isSuccessed = this->MergePhotoAlbum(mainAlbumInfo, subAlbumInfo) == NativeRdb::E_OK;
    } else {
        isSuccessed = this->UpdateAlbumLPathByAlbumId(subAlbumInfo) == NativeRdb::E_OK;
        mainAlbumInfo = subAlbumInfo;
    }
    isSuccessed = isSuccessed && this->UpdateAlbumInfoFromAlbumPluginByAlbumId(mainAlbumInfo) == NativeRdb::E_OK;
    MEDIA_INFO_LOG("Media_Operation: clean empty lPath album (sub) completed! "
                   "isSuccessed: %{public}d, mainAlbum: %{public}s, subAlbum: %{public}s",
        isSuccessed,
        mainAlbumInfo.ToString().c_str(),
        subAlbumInfo.ToString().c_str());
    return isSuccessed ? NativeRdb::E_OK : NativeRdb::E_ERROR;
}

int32_t PhotoAlbumLPathOperation::MergePhotoAlbum(
    const PhotoAlbumInfoPo &mainAlbumInfo, const PhotoAlbumInfoPo &subAlbumInfo)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || mainAlbumInfo.albumId <= 0 || subAlbumInfo.albumId <= 0;
    if (isInvalid) {
        return NativeRdb::E_ERROR;
    }
    return PhotoAlbumMergeOperation()
        .SetRdbStore(this->rdbStorePtr_)
        .MergeAlbum(subAlbumInfo.albumId, mainAlbumInfo.albumId);
}

std::vector<PhotoAlbumInfoPo> PhotoAlbumLPathOperation::GetDuplicatelPathAlbumInfoMain()
{
    if (this->rdbStorePtr_ == nullptr) {
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_DUPLICATE_LPATH_MAIN_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        return {};
    }
    std::vector<PhotoAlbumInfoPo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        result.emplace_back(PhotoAlbumInfoPo().Parse(resultSet));
    }
    return result;
}

std::vector<PhotoAlbumInfoPo> PhotoAlbumLPathOperation::GetDuplicatelPathAlbumInfoSub(const PhotoAlbumInfoPo &albumInfo)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || albumInfo.albumId <= 0 || albumInfo.lPath.empty();
    if (isInvalid) {
        return {};
    }
    std::string sql = this->SQL_PHOTO_ALBUM_DUPLICATE_LPATH_SUB_QUERY;
    const std::vector<NativeRdb::ValueObject> bindArgs = {albumInfo.albumId, albumInfo.lPath};
    auto resultSet = this->rdbStorePtr_->QuerySql(sql, bindArgs);
    if (resultSet == nullptr) {
        return {};
    }
    std::vector<PhotoAlbumInfoPo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        result.emplace_back(PhotoAlbumInfoPo().Parse(resultSet));
    }
    return result;
}

std::vector<PhotoAlbumInfoPo> PhotoAlbumLPathOperation::GetEmptylPathAlbumInfo()
{
    if (this->rdbStorePtr_ == nullptr) {
        return {};
    }
    std::string querySql = this->SQL_PHOTO_ALBUM_FIX_LPATH_QUERY;
    auto resultSet = this->rdbStorePtr_->QuerySql(querySql);
    if (resultSet == nullptr) {
        return {};
    }
    std::vector<PhotoAlbumInfoPo> result;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        result.emplace_back(PhotoAlbumInfoPo().Parse(resultSet));
    }
    return result;
}
}  // namespace OHOS::Media