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
#include "photo_album_clone.h"

#include "media_log.h"
#include "rdb_store.h"
#include "result_set_utils.h"

namespace OHOS::Media {
std::string PhotoAlbumClone::ToString(const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    std::string args;
    for (auto &arg : bindArgs) {
        std::string tempStr;
        arg.GetString(tempStr);
        args += tempStr + ", ";
    }
    return args;
}

std::string PhotoAlbumClone::GetPhotoAlbumCountQuerySql()
{
    return isCloudRestoreSatisfied_ ? SQL_PHOTO_ALBUM_COUNT_FOR_CLONE_LOCAL_AND_CLOUD :
        SQL_PHOTO_ALBUM_COUNT_FOR_CLONE_LOCAL;
}

std::string PhotoAlbumClone::GetPhotoAlbumSelectQuerySql()
{
    return isCloudRestoreSatisfied_ ? SQL_PHOTO_ALBUM_SELECT_FOR_CLONE_LOCAL_AND_CLOUD :
        SQL_PHOTO_ALBUM_SELECT_FOR_CLONE_LOCAL;
}

/**
 * @brief Get Total Count of PhotoAlbum, for clone.
 */
int32_t PhotoAlbumClone::GetPhotoAlbumCountInOriginalDb()
{
    std::string querySql = GetPhotoAlbumCountQuerySql();
    std::vector<NativeRdb::ValueObject> bindArgs = { static_cast<int32_t>(DirtyType::TYPE_DELETED), 
        static_cast<int32_t>(PhotoAlbumSubType::USER_GENERIC) };
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql, bindArgs);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, 0, "Failed to query album! querySql = %{public}s", querySql.c_str());
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Get Row Data of PhotoAlbum, for clone.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotoAlbumClone::GetPhotoAlbumInOriginalDb(int32_t offset, int32_t pageSize)
{
    std::string querySql = GetPhotoAlbumSelectQuerySql();
    std::vector<NativeRdb::ValueObject> bindArgs = { static_cast<int32_t>(DirtyType::TYPE_DELETED), 
        static_cast<int32_t>(PhotoAlbumSubType::USER_GENERIC), offset, pageSize };
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, nullptr,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql, bindArgs);
    CHECK_AND_PRINT_LOG(resultSet != nullptr, "Failed to query album! querySql = %{public}s, bindArgs = %{public}s",
        querySql.c_str(), this->ToString(bindArgs).c_str());
    return resultSet;
}

void PhotoAlbumClone::TRACE_LOG(std::vector<PhotoAlbumDao::PhotoAlbumRowData> &albumInfos)
{
    MEDIA_INFO_LOG("Media_Restore: albumInfos size : %{public}d", static_cast<int32_t>(albumInfos.size()));
    for (auto &info : albumInfos) {
        MEDIA_INFO_LOG("Media_Restore: restore album info: albumId = %{public}d, \
            albumName = %{public}s, \
            albumType = %{public}d, \
            albumSubType = %{public}d, \
            lPath = %{public}s, \
            bundleName = %{public}s, \
            priority = %{public}d",
            info.albumId,
            info.albumName.c_str(),
            info.albumType,
            info.albumSubType,
            info.lPath.c_str(),
            info.bundleName.c_str(),
            info.priority);
    }
}

void PhotoAlbumClone::TRACE_LOG(const std::string &tableName, vector<AlbumInfo> &albumInfos)
{
    for (auto &albumInfo : albumInfos) {
        MEDIA_INFO_LOG("Media_Restore: tableName %{public}s, \
        albumInfo.albumName = %{public}s, \
        albumInfo.albumBundleName = %{public}s, \
        albumInfo.albumType = %{public}d, \
        albumInfo.albumSubType = %{public}d, \
        albumInfo.lPath = %{public}s",
            tableName.c_str(),
            albumInfo.albumName.c_str(),
            albumInfo.albumBundleName.c_str(),
            static_cast<int32_t>(albumInfo.albumType),
            static_cast<int32_t>(albumInfo.albumSubType),
            albumInfo.lPath.c_str());
    }
    // fetch all albums from mediaLibraryRdb
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> targetAlbumInfos = this->photoAlbumDao_.GetPhotoAlbums();
    this->TRACE_LOG(targetAlbumInfos);
}
}  // namespace OHOS::Media