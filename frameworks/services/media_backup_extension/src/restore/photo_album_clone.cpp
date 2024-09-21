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

#include <string>
#include <vector>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "media_log.h"

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

/**
 * @brief Get Total Count of PhotoAlbum, for clone.
 */
int32_t PhotoAlbumClone::GetPhotoAlbumCountInOriginalDb()
{
    std::string querySql = this->SQL_PHOTO_ALBUM_COUNT_FOR_CLONE;
    if (this->mediaLibraryOriginalRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryOriginalRdb_ is null.");
        return 0;
    }
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query album! querySql = %{public}s", querySql.c_str());
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief Get Row Data of PhotoAlbum, for clone.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotoAlbumClone::GetPhotoAlbumInOriginalDb(int32_t offset, int32_t pageSize)
{
    std::string querySql = this->SQL_PHOTO_ALBUM_SELECT_FOR_CLONE;
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    if (this->mediaLibraryOriginalRdb_ == nullptr) {
        MEDIA_ERR_LOG("Media_Restore: mediaLibraryOriginalRdb_ is null.");
        return nullptr;
    }
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query album! querySql = %{public}s, bindArgs = %{public}s",
            querySql.c_str(),
            this->ToString(bindArgs).c_str());
    }
    return resultSet;
}
}  // namespace OHOS::Media