/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Background"

#include "media_file_manager_temp_file_aging_task.h"

#include "rdb_predicates.h"
#include "media_file_utils.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {
// LCOV_EXCL_START
bool MediaFileManagerTempFileAgingTask::Accept()
{
    return MedialibrarySubscriber::IsCurrentStatusOn();
}

void MediaFileManagerTempFileAgingTask::Execute()
{
    this->HandleMediaFileManagerTempFileAging();
    return;
}

void MediaFileManagerTempFileAgingTask::HandleMediaFileManagerTempFileAging()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }

    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t timeBefore24Hours = current - 24 * 60 * 60 * 1000;
    const std::string QUERY_NO_TEMP_FILE_24H_BEFORE_INFO =
        "SELECT file_id, data FROM Photos WHERE " + PhotoColumn::PHOTO_FILE_SOURCE_TYPE +
        " = " + std::to_string(static_cast<int32_t>(FileSourceTypes::TEMP_FILE_MANAGER)) + " AND " +
        PhotoColumn::MEDIA_DATE_ADDED + " <= " + std::to_string(timeBefore24Hours);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_NO_TEMP_FILE_24H_BEFORE_INFO);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query not match data fails");
        return;
    }

    std::vector<std::string> fileIds;
    std::error_code errCode;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int columnIndex = 0;
        int32_t fileId = -1;
        if (resultSet->GetColumnIndex(MediaColumn::MEDIA_ID, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetInt(columnIndex, fileId);
            fileIds.emplace_back(std::to_string(fileId));
        }
        std::string filePath = "";
        if (resultSet->GetColumnIndex(MediaColumn::MEDIA_FILE_PATH, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetString(columnIndex, filePath);
        }
        int32_t errRet = std::filesystem::remove(filePath, errCode);
        CHECK_AND_PRINT_LOG(errCode.value() == 0, "Failed to remove errCode: %{public}d, \
            path: %{private}s", errCode.value(), filePath.c_str());
        MEDIA_INFO_LOG("Handle file id %{public}d", fileId);
    }
    if (fileIds.size() == 0) {
        return;
    }

    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, fileIds);
    int deleteRow = -1;
    auto ret = rdbStore->Delete(deleteRow, predicates);
    MEDIA_INFO_LOG("Delete temp files, deleteRow is %{public}d", deleteRow);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete temp files failed, ret = %{public}d, deleteRow is %{public}d", ret, deleteRow);
    }
}
// LCOV_EXCL_STOP
}  // namespace OHOS::Media::Background