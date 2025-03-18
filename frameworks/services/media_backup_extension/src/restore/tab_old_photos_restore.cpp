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

#include "tab_old_photos_restore.h"

#include <algorithm>
#include <numeric>

#include "backup_database_utils.h"
#include "media_log.h"

namespace OHOS::Media {
int32_t TabOldPhotosRestore::Restore(
    std::shared_ptr<NativeRdb::RdbStore> &rdbStorePtr, const std::vector<FileInfo> &fileInfos)
{
    CHECK_AND_RETURN_RET_LOG(rdbStorePtr != nullptr, NativeRdb::E_DB_NOT_EXIST,
        "rdbStorePtr is nullptr, Maybe init failed");

    TabOldPhotosRestoreHelper restoreHelper;
    restoreHelper.SetPlaceHoldersAndBindArgs(fileInfos);
    CHECK_AND_RETURN_RET_LOG(!restoreHelper.IsEmpty(), NativeRdb::E_ERROR, "restoreHelper is empty");

    std::string insertSql = restoreHelper.GetInsertSql();
    std::vector<NativeRdb::ValueObject> bindArgs = restoreHelper.GetBindArgs();
    int32_t ret = rdbStorePtr->ExecuteSql(insertSql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: TabOldPhotosRestore failed, ret=%{public}d, "
                      "executeSql=%{public}s, bindArgs: %{public}s",
            ret,
            executeSql.c_str(),
            this->ToString(bindArgs).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

std::string TabOldPhotosRestore::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    for (auto &value : values) {
        std::string str;
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

void TabOldPhotosRestoreHelper::SetPlaceHoldersAndBindArgs(const std::vector<FileInfo> &fileInfos)
{
    for (const auto &fileInfo : fileInfos) {
        AddPlaceHolders();
        AddBindArgs(fileInfo);
    }
}

bool TabOldPhotosRestoreHelper::IsEmpty()
{
    return placeHolders_.empty() || bindArgs_.empty();
}

std::string TabOldPhotosRestoreHelper::GetInsertSql()
{
    return GetInputTableClause() + SQL_TAB_OLD_PHOTOS_INSERT;
}

std::vector<NativeRdb::ValueObject> TabOldPhotosRestoreHelper::GetBindArgs()
{
    return bindArgs_;
}

void TabOldPhotosRestoreHelper::AddPlaceHolders()
{
    placeHolders_.emplace_back(SQL_PLACEHOLDERS);
}

void TabOldPhotosRestoreHelper::AddBindArgs(const FileInfo &fileInfo)
{
    bindArgs_.emplace_back(fileInfo.localMediaId);
    bindArgs_.emplace_back(fileInfo.oldPath);
    bindArgs_.emplace_back(fileInfo.cloudPath);
}

std::string TabOldPhotosRestoreHelper::GetInputTableClause()
{
    return "WITH INPUT (old_file_id, old_data, data) AS (VALUES " +
        BackupDatabaseUtils::JoinValues(placeHolders_, ",") + " ) ";
}
} // namespace OHOS::Media