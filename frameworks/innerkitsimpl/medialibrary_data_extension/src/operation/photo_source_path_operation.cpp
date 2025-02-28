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
#define MLOG_TAG "PhotoSourcePathOperation"

#include "photo_source_path_operation.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#include "media_file_utils.h"
#include "media_column.h"
#include "result_set_utils.h"

namespace OHOS::Media {
void PhotoSourcePathOperation::ResetPhotoSourcePath(std::shared_ptr<MediaLibraryRdbStore> mediaRdbStorePtr)
{
    std::vector<PhotoSourcePathOperation::PhotoAssetInfo> photoAssetInfos =
        this->GetPhotoOfMissingSourcePath(mediaRdbStorePtr);
    int32_t count = 0;
    for (const auto &info : photoAssetInfos) {
        bool isSkip = info.hidden == 0 && info.dateTrashed == 0;
        isSkip = isSkip || info.lPath.empty();
        isSkip = isSkip || !info.sourcePath.empty();
        if (isSkip) {
            MEDIA_ERR_LOG("Media_Operation: obj is invalid, info: %{public}s.", info.ToString().c_str());
            continue;
        }
        std::string sql = this->SQL_PHOTO_SOURCE_PATH_FIX_UPDATE;
        std::string sourcePath = this->SOURCE_PATH_PREFIX + info.lPath + "/" + info.displayName;
        std::vector<NativeRdb::ValueObject> params = {sourcePath, info.fileId};
        int32_t err = mediaRdbStorePtr->ExecuteSql(sql, params);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Operation: update photo source_path failed, err: %{public}d, info: %{public}s.",
                err,
                info.ToString().c_str());
            continue;
        }
        count++;
    }
    MEDIA_INFO_LOG("Media_Operation: reset photo source_path success. count: %{public}d.", count);
}

std::vector<PhotoSourcePathOperation::PhotoAssetInfo> PhotoSourcePathOperation::GetPhotoOfMissingSourcePath(
    std::shared_ptr<MediaLibraryRdbStore> mediaRdbStorePtr, const int32_t offset, const int32_t limit)
{
    std::vector<PhotoSourcePathOperation::PhotoAssetInfo> photoAssetInfos;
    CHECK_AND_RETURN_RET_LOG(mediaRdbStorePtr != nullptr, photoAssetInfos,
        "Media_Operation: mediaRdbStorePtr is null.");

    const std::vector<NativeRdb::ValueObject> params = {offset, limit};
    std::string querySql = this->SQL_PHOTO_SOURCE_PATH_MISSING_QUERY;
    auto resultSet = mediaRdbStorePtr->QuerySql(querySql, params);
    CHECK_AND_RETURN_RET(resultSet != nullptr, photoAssetInfos);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoSourcePathOperation::PhotoAssetInfo info;
        info.albumId = GetInt64Val("album_id", resultSet);
        info.albumName = GetStringVal("album_name", resultSet);
        info.lPath = GetStringVal("lpath", resultSet);
        info.fileId = GetInt64Val("file_id", resultSet);
        info.displayName = GetStringVal("display_name", resultSet);
        info.hidden = GetInt32Val("hidden", resultSet);
        info.dateTrashed = GetInt64Val("date_trashed", resultSet);
        info.sourcePath = GetStringVal("source_path", resultSet);
        photoAssetInfos.emplace_back(info);
    }
    return photoAssetInfos;
}
}  // namespace OHOS::Media