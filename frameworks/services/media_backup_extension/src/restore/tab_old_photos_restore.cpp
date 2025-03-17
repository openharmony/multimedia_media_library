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

#include <string>
#include <vector>
#include <numeric>
#include <algorithm>

#include "backup_const.h"
#include "media_log.h"

namespace OHOS::Media {
int32_t TabOldPhotosRestore::Restore(
    std::shared_ptr<NativeRdb::RdbStore> &rdbStorePtr, const std::vector<FileInfo> &fileInfos)
{
    CHECK_AND_RETURN_RET_LOG(rdbStorePtr != nullptr, NativeRdb::E_DB_NOT_EXIST,
        "rdbStorePtr is nullptr, Maybe init failed");

    TabOldPhotosTempTable tempTable;
    tempTable.SetPlaceHoldersAndBindArgs(fileInfos);
    CHECK_AND_RETURN_RET_LOG(!tempTable.IsEmpty(), E_FAIL, "tempTable is empty");

    std::string insertSql = GetInsertSql(tempTable);
    std::vector<NativeRdb::ValueObject> bindArgs = tempTable.GetBindArgs();
    int32_t ret = rdbStorePtr->ExecuteSql(insertSql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: TabOldPhotosRestore failed, ret=%{public}d, "
                        "executeSql=%{public}s, bindArgs: %{public}s, Object: %{public}s",
            ret,
            insertSql.c_str(),
            this->ToString(bindArgs).c_str(),
            this->ToString(fileInfo).c_str());
        return ret;
    }
    return NativeRdb::E_OK;
}

std::string TabOldPhotosRestore::GetInsertSql(const TabOldPhotosTempTable &tempTable)
{
    std::string inputTableClause = tempTable.GetInputTableClause();
    return inputTableClause + SQL_TAB_OLD_PHOTOS_INSERT;
}

int32_t TabOldPhotosRestore::Insert(std::shared_ptr<NativeRdb::RdbStore> &rdbStorePtr, const std::string &insertSql)
{
    TabOldPhotosTempTable tempTable;
    tempTable.SetPlaceHoldersAndBindArgs(fileInfos);
    CHECK_AND_RETURN_RET_LOG(!tempTable.IsEmpty(), E_FAIL, "tempTable is empty");
    std::string insertSql = GetInsertSql(tempTable);
    std::vector<NativeRdb::ValueObject> bindArgs = tempTable.GetBindArgs();
    int32_t ret = rdbStorePtr->ExecuteSql(insertSql, bindArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: TabOldPhotosRestore failed, ret=%{public}d, "
                      "executeSql=%{public}s, bindArgs: %{public}s, Object: %{public}s",
            ret,
            insertSql.c_str(),
            this->ToString(bindArgs).c_str(),
            this->ToString(fileInfo).c_str());
    }
    CHECK_AND_RETURN_RET_LOG(!insertSql.empty(), NativeRdb::E_ERROR, "insertSql is empty");
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

std::string TabOldPhotosRestore::ToString(const FileInfo &fileInfo)
{
    return "FileInfo[ fileId: " + std::to_string(fileInfo.localMediaId) + ", displayName: " + fileInfo.displayName +
        ", bundleName: " + std::to_string(fileInfo.fileSize) + ", fileType: " +
        std::to_string(fileInfo.fileType) + " ]";
}

void TabOldPhotosTempTable::SetPlaceHoldersAndBindArgs(const std::vector<FileInfo> &fileInfos)
{
    for (const auto &fileInfo : fileInfos) {
        AddPlaceHolder();
        AddBindArg(fileInfo);
    }
}

bool TabOldPhotosTempTable::IsEmpty()
{
    return placeHolders_.empty() || bindArgs_.empty();
}

std::string TabOldPhotosTempTable::GetInputTableClause()
{
    return "WITH INPUT (old_file_id, old_data, data) AS (VALUES " + Join(placeHolders_, ",") + " ) ";
}

std::vector<NativeRdb::ValueObject> TabOldPhotosTempTable::GetBindArgs()
{
    return bindArgs_;
}

void TabOldPhotosTempTable::AddPlaceHolders()
{
    placeHolders_.emplace_back(SQL_PLACEHOLDERS);
}

void TabOldPhotosTempTable::AddBindArgs(const FileInfo &fileInfo)
{
    bindArgs_.emplace_back(fileInfo.localMediaId);
    bindArgs_.emplace_back(fileInfo.oldPath);
    bindArgs_.emplace_back(fileInfo.cloudPath);
}

std::string TabOldPhotosTempTable::Join(const std::vector<std::string> &values, const std::string &delimiter)
{
    return std::accumulate(values.begin(), values.end(), delimiter);
}
} // namespace OHOS::Media