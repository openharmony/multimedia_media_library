/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "AlbumPluginTableEventHandler"

#include <string>
#include <vector>

#include "album_plugin_table_event_handler.h"
#include "album_plugin_config.h"
#include "dfx_transaction.h"
#include "rdb_store.h"
#include "rdb_errno.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS::Media {

bool AlbumPluginTableEventHandler::IsTableCreated(NativeRdb::RdbStore &store, const std::string &tableName)
{
    std::string sql = "SELECT COUNT(1) AS count FROM sqlite_master WHERE type='table' AND name= ?;";
    const std::vector<NativeRdb::ValueObject> params = {NativeRdb::ValueObject(tableName)};
    auto resultSet = store.QuerySql(sql, params);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null!");
        return 0;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("go to first row failed");
        return 0;
    }
    int32_t count = get<int32_t>(ResultSetUtils::GetValFromColumn("count", resultSet, TYPE_INT32));
    if (count < 0) {
        MEDIA_ERR_LOG(
            "Check sqlite_master count error, tableName: %{public}s, count is %{public}d", tableName.c_str(), count);
        return 0;
    }
    return count > 0;
}

int32_t AlbumPluginTableEventHandler::InitiateData(NativeRdb::RdbStore &store)
{
    int32_t err = NativeRdb::E_OK;
    MEDIA_INFO_LOG("InitiateData begin initiate %{public}s table data.", TABLE_NAME.c_str());
    auto [errCode, trans] = store.CreateTransaction(OHOS::NativeRdb::Transaction::DEFERRED);
    DfxTransaction reporter{ __func__ };
    if (errCode != NativeRdb::E_OK || trans == nullptr) {
        reporter.ReportError(DfxTransaction::AbnormalType::CREATE_ERROR, errCode);
        MEDIA_ERR_LOG("transaction failed, err:%{public}d", errCode);
        return errCode;
    }
    for (const AlbumPlugin::AlbumPluginRowData &data : AlbumPlugin::ALBUM_PLUGIN_DATA) {
        std::vector<NativeRdb::ValueObject> bindArgs = {
            data.lpath,
            data.album_name,
            data.album_name_en,
            data.bundle_name,
            data.cloud_id,
            data.dual_album_name,
            data.priority
        };
        auto res = trans->Execute(this->INSERT_DATA_SQL, bindArgs);
        err = res.first;
        if (err != NativeRdb::E_OK) {
            reporter.ReportError(DfxTransaction::AbnormalType::EXECUTE_ERROR, err);
            trans->Rollback();
            MEDIA_ERR_LOG("Execute sql failed, err: %{public}d", err);
            return err;
        }
    }
    err = trans->Commit();
    if (err != NativeRdb::E_OK) {
        reporter.ReportError(DfxTransaction::AbnormalType::COMMIT_ERROR, err);
        MEDIA_ERR_LOG("InitiateData tans finish fail!, ret:%{public}d", err);
    } else {
        reporter.ReportIfTimeout();
    }
    MEDIA_INFO_LOG("InitiateData end initiate %{public}s table data %{public}d.",
        TABLE_NAME.c_str(),
        static_cast<int32_t>(AlbumPlugin::ALBUM_PLUGIN_DATA.size()));
    return NativeRdb::E_OK;
}

int32_t AlbumPluginTableEventHandler::GetAlbumPluginDataCount(NativeRdb::RdbStore &store)
{
    std::string querySql = this->SQL_SELECT_DATA_COUNT;
    auto resultSet = store.QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_WARN_LOG("resultSet is null! querySql = %{public}s", querySql.c_str());
        return 0;
    }
    return GetInt32Val("count", resultSet);
}

/**
 * @brief execute sql while database created
 * @param store rdb store
 */
int32_t AlbumPluginTableEventHandler::OnCreate(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("OnCreate begin create %{public}s table.", TABLE_NAME.c_str());
    if (store.ExecuteSql(this->CREATE_TABLE_SQL) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }
    if (InitiateData(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }
    MEDIA_INFO_LOG("OnCreate end create %{public}s table.", TABLE_NAME.c_str());
    return NativeRdb::E_OK;
}

/**
 * @brief execute sql while database upgraded
 * @param store rdb store
 */
int32_t AlbumPluginTableEventHandler::OnUpgrade(NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    MEDIA_INFO_LOG("OnUpgrade begin upgrade %{public}s table.", TABLE_NAME.c_str());
    // if table is exists and has data, do not need to create again
    if (this->IsTableCreated(store, TABLE_NAME)) {
        int32_t count = this->GetAlbumPluginDataCount(store);
        if (count > 0) {
            MEDIA_INFO_LOG("OnUpgrade check table %{public}s is exists, and has data %{public}d, "
                           "no need to create again.",
                TABLE_NAME.c_str(),
                count);
            return NativeRdb::E_OK;
        }
    }
    int32_t ret = OnCreate(store);
    MEDIA_INFO_LOG("OnUpgrade end upgrade %{public}s table.", TABLE_NAME.c_str());
    return ret;
}
}  // namespace OHOS::Media