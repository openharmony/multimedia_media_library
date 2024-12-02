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

#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#include "media_file_utils.h"
#include "result_set_utils.h"

namespace OHOS::Media {
PhotoAlbumLPathOperation &PhotoAlbumLPathOperation::SetRdbStore(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr)
{
    this->rdbStorePtr_ = rdbStorePtr;
    return *this;
}

int32_t PhotoAlbumLPathOperation::CleanInvalidPhotoAlbums()
{
    std::vector<PhotoAlbumLPathOperation::PhotoAlbumInfo> invalidAlbumList = this->GetInvalidPhotoAlbums();
    if (invalidAlbumList.empty()) {
        MEDIA_INFO_LOG("Media_Operation: no invalid album found.");
        return NativeRdb::E_OK;
    }
    // Log the invalid albums
    int index = 0;
    for (const auto &albumInfo : invalidAlbumList) {
        MEDIA_INFO_LOG("Media_Operation: clean invalid album! index: %{public}d, Object: %{public}s",
            ++index,
            albumInfo.ToString().c_str());
    }
    // Delete the invalid albums
    std::string sql = this->SQL_PHOTO_ALBUM_EMPTY_DELETE;
    auto result = this->rdbStorePtr_->ExecuteSql(sql);
    MEDIA_INFO_LOG("Media_Operation: clean invalid album completed! result: %{public}d", result);
    return result;
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
}  // namespace OHOS::Media