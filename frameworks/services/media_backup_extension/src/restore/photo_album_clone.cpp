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
void DEBUG_LOG_TO_CONSOLE_V2(const std::string &executeSql, std::vector<NativeRdb::ValueObject> &bindArgs)
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
 * @brief Get Total Count of PhotoAlbum, for clone.
 */
int32_t PhotoAlbumClone::GetPhotoAlbumCountInOriginalDb()
{
    std::string querySql = this->SQL_PHOTO_ALBUM_COUNT_FOR_CLONE;
    std::vector<NativeRdb::ValueObject> bindArgs;
    DEBUG_LOG_TO_CONSOLE_V2(querySql, bindArgs);
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query album!");
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
    DEBUG_LOG_TO_CONSOLE_V2(querySql, bindArgs);
    return this->mediaLibraryOriginalRdb_->QuerySql(querySql, bindArgs);
}
}  // namespace OHOS::Media