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

#include "backup_database_utils.h"

#include "backup_const.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
int32_t BackupDatabaseUtils::InitDb(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &dbName,
    const std::string &dbPath, const std::string &bundleName, bool isMediaLibrary)
{
    NativeRdb::RdbStoreConfig config(dbName);
    config.SetPath(dbPath);
    config.SetBundleName(bundleName);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    if (isMediaLibrary) {
        config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
        config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
    }
    int32_t err;
    RdbCallback cb;
    rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    return err;
}

std::string BackupDatabaseUtils::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    return "";
}

std::string BackupDatabaseUtils::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "false";
}

int32_t BackupDatabaseUtils::QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
    const std::string &column)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb_ is nullptr, Maybe init failed.");
        return 0;
    }
    auto resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(column, resultSet);
    return result;
}

int32_t BackupDatabaseUtils::InitGarbageAlbum(std::shared_ptr<NativeRdb::RdbStore> galleryRdb,
    std::set<std::string> &cacheSet, std::unordered_map<std::string, std::string> &nickMap)
{
    if (galleryRdb == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return E_FAIL;
    }

    const string querySql = "SELECT nick_dir, nick_name FROM garbage_album where type = 0";
    auto resultSet = galleryRdb->QuerySql(QUERY_GARBAGE_ALBUM);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t count = -1;
    int32_t err = resultSet->GetRowCount(count);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
        return E_FAIL;
    }
    MEDIA_INFO_LOG("garbageCount: %{public}d", count);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t type;
        resultSet->GetInt(INDEX_TYPE, type);
        if (type == NICK) {
            string nickName;
            string nickDir;
            resultSet->GetString(INDEX_NICK_DIR, nickDir);
            resultSet->GetString(INDEX_NICK_NAME, nickName);
            nickMap[nickDir] = nickName;
        } else {
            string cacheDir;
            resultSet->GetString(INDEX_CACHE_DIR, cacheDir);
            cacheSet.insert(cacheDir);
        }
    }
    MEDIA_INFO_LOG("add map success!");
    resultSet->Close();
    return E_OK;
}
} // namespace Media
} // namespace OHOS