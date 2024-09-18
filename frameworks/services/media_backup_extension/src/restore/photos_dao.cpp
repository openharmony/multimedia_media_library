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
#include <string>
#include <vector>

#include "photos_dao.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "backup_const.h"

namespace OHOS::Media {
/**
 * @brief Find FileInfo related PhotoAlbu, by lPath, displayName, fileSize and orientation.
 */
PhotosDao::PhotosRowData PhotosDao::FindSameFileInAlbum(const FileInfo &fileInfo, int32_t maxFileId)
{
    PhotosDao::PhotosRowData rowData;
    if (maxFileId <= 0) {
        return rowData;
    }
    // pictureFlag: 0 for video, 1 for photo; Only search for photo in this case.
    int pictureFlag = fileInfo.fileType == MEDIA_TYPE_VIDEO ? 0 : 1;
    const std::vector<NativeRdb::ValueObject> params = {
        fileInfo.lPath, maxFileId, fileInfo.displayName, fileInfo.fileSize, pictureFlag, fileInfo.orientation};
    std::string querySql = this->SQL_PHOTOS_FIND_SAME_FILE_IN_ALBUM;
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return rowData;
    }
    rowData.fileId = GetInt32Val("file_id", resultSet);
    rowData.data = GetStringVal("data", resultSet);
    return rowData;
}

/**
 * @brief Find FileInfo, which is not related PhotoAlbum, by displayName, fileSize and orientation.
 */
PhotosDao::PhotosRowData PhotosDao::FindSameFileWithoutAlbum(const FileInfo &fileInfo, int32_t maxFileId)
{
    PhotosDao::PhotosRowData rowData;
    if (maxFileId <= 0) {
        return rowData;
    }
    // pictureFlag: 0 for video, 1 for photo; Only search for photo in this case.
    int pictureFlag = fileInfo.fileType == MEDIA_TYPE_VIDEO ? 0 : 1;
    const std::vector<NativeRdb::ValueObject> params = {
        maxFileId, fileInfo.displayName, fileInfo.fileSize, pictureFlag, fileInfo.orientation};
    std::string querySql = this->SQL_PHOTOS_FIND_SAME_FILE_WITHOUT_ALBUM;
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql, params);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return rowData;
    }
    rowData.fileId = GetInt32Val("file_id", resultSet);
    rowData.data = GetStringVal("data", resultSet);
    return rowData;
}

/**
 * @brief Get basic information of the Photos.
 */
PhotosDao::PhotosBasicInfo PhotosDao::GetBasicInfo()
{
    std::string querySql = this->SQL_PHOTOS_BASIC_INFO;
    auto resultSet = this->mediaLibraryRdb_->QuerySql(querySql);
    PhotosDao::PhotosBasicInfo basicInfo = {0, 0};
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return basicInfo;
    }
    basicInfo.maxFileId = GetInt32Val("max_file_id", resultSet);
    basicInfo.count = GetInt32Val("count", resultSet);
    return basicInfo;
}
}  // namespace OHOS::Media