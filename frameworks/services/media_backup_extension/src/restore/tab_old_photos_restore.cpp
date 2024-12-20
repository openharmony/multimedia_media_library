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
    std::shared_ptr<NativeRdb::RdbStore> &rdbStorePtr, const std::vector<FileInfo> fileInfos)
{
    if (rdbStorePtr ==  nullptr) {
        MEDIA_ERR_LOG("rdbStorePtr is nullptr, Maybe init failed");
        return NativeRdb::E_OK;
    }
    for (const auto &fileInfo : fileInfos) {
        std::string executeSql = this->SQL_TAB_OLD_PHOTOS_INSERT;
        std::vector<NativeRdb::ValueObject> bindArgs = { fileInfo.fileIdOld, fileInfo.oldPath, fileInfo.cloudPath };
        int32_t ret = rdbStorePtr->ExecuteSql(executeSql, bindArgs);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: TabOldPhotosRestore failed, ret=%{public}d, "
                          "executeSql=%{public}s, bindArgs: %{public}s, Object: %{public}s",
                ret,
                executeSql.c_str(),
                this->ToString(bindArgs).c_str(),
                this->ToString(fileInfo).c_str());
        }
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

std::string TabOldPhotosRestore::ToString(const FileInfo &fileInfo)
{
    return "FileInfo[ fileId: " + std::to_string(fileInfo.fileIdOld) + ", displayName: " + fileInfo.displayName +
        ", bundleName: " + std::to_string(fileInfo.fileSize) + ", fileType: " +
        std::to_string(fileInfo.fileType) + " ]";
}
} // namespace OHOS::Media