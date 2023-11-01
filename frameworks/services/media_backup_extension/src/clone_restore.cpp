/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryCloneRestore"

#include "clone_restore.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
const std::string MEDIA_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";

int32_t CloneRestore::Init(const std::string &orignPath, const std::string &updatePath, bool isUpdate)
{
    dbPath_ = ORIGIN_PATH + MEDIA_DB_PATH;
    filePath_ = ORIGIN_PATH + "/storage/cloud/files";
    if (!MediaFileUtils::IsFileExists(dbPath_)) {
        MEDIA_ERR_LOG("Media db is not exist.");
        return E_FAIL;
    }
    if (isUpdate && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }

    NativeRdb::RdbStoreConfig config(MEDIA_DATA_ABILITY_DB_NAME);
    config.SetPath(dbPath_);
    config.SetBundleName(BUNDLE_NAME);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);

    int32_t err;
    RdbCallback cb;
    mediaRdb_ = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    if (mediaRdb_ == nullptr) {
        MEDIA_ERR_LOG("Init media rdb fail");
        return E_FAIL;
    }
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void CloneRestore::RestorePhoto(void)
{
    int32_t totalNumber = QueryTotalNumber();
    MEDIA_INFO_LOG("QueryTotalNumber, totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<FileInfo> infos = QueryFileInfos(offset);
        InsertPhoto(infos);
    }
    (void)NativeRdb::RdbHelper::DeleteRdbStore(dbPath_);
}

void CloneRestore::HandleRestData(void)
{}

int32_t CloneRestore::QueryTotalNumber(void)
{
    if (mediaRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return 0;
    }
    std::string querySql = "SELECT count(1) as count FROM Photos";
    auto resultSet = mediaRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val("count", resultSet);
    return result;
}

std::vector<FileInfo> CloneRestore::QueryFileInfos(int32_t offset)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    if (mediaRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return result;
    }
    std::string querySql = "SELECT " + MediaColumn::MEDIA_FILE_PATH + "," + MediaColumn::MEDIA_NAME +
        "," + MediaColumn::MEDIA_SIZE + "," + MediaColumn::MEDIA_DURATION + "," + MediaColumn::MEDIA_DATE_TRASHED +
        "," + MediaColumn::MEDIA_HIDDEN + "," + MediaColumn::MEDIA_IS_FAV + "," + MediaColumn::MEDIA_TYPE +
        "," + MediaColumn::MEDIA_DATE_ADDED + "," + PhotoColumn::PHOTO_HEIGHT + "," + PhotoColumn::PHOTO_WIDTH +
        "," + PhotoColumn::PHOTO_USER_COMMENT + "," + MediaColumn::MEDIA_TITLE + " FROM " + PhotoColumn::PHOTOS_TABLE +
        " limit " + std::to_string(offset) + "," + std::to_string(QUERY_COUNT);
    auto resultSet = mediaRdb_->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSet(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

bool CloneRestore::ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    // only parse image and video
    std::string oldPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (!ConvertPathToRealPath(oldPath, filePath_, info.filePath, info.relativePath)) {
        return false;
    }

    info.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    info.title = GetStringVal(MediaColumn::MEDIA_TITLE, resultSet);
    info.userComment = GetStringVal(PhotoColumn::PHOTO_USER_COMMENT, resultSet);
    info.fileSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultSet);
    info.duration = GetInt64Val(MediaColumn::MEDIA_DURATION, resultSet);
    info.recycledTime = GetInt64Val(MediaColumn::MEDIA_DATE_TRASHED, resultSet);
    info.hidden = GetInt32Val(MediaColumn::MEDIA_HIDDEN, resultSet);
    info.isFavorite = GetInt32Val(MediaColumn::MEDIA_IS_FAV, resultSet);
    info.fileType =  GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    info.showDateToken = GetInt64Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);
    info.height = GetInt64Val(PhotoColumn::PHOTO_HEIGHT, resultSet);
    info.width = GetInt64Val(PhotoColumn::PHOTO_WIDTH, resultSet);
    return true;
}
} // namespace Media
} // namespace OHOS
