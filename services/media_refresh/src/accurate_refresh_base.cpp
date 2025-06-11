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
#define MLOG_TAG "AccurateRefresh::AccurateRefreshBase"

#include <sstream>

#include "media_file_utils.h"
#include "accurate_refresh_base.h"
#include "medialibrary_unistore_manager.h"
#include "accurate_debug_log.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

int32_t AccurateRefreshBase::Insert(MediaLibraryCommand &cmd, int64_t &outRowId)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }

    auto ret = Init();
    if (ret != ACCURATE_REFRESH_RET_OK) {
        MEDIA_WARN_LOG("no Init.");
        return ret;
    }

    lock_guard<mutex> lock(dbOperationMtx_);
    vector<int32_t> keys;
    #ifdef MEDIA_REFRESH_TEST
        pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
        vector<ValuesBucket> values = { cmd.GetValueBucket() };
        if (trans_) {
            retWithResults = trans_->BatchInsert(cmd.GetTableName(), values, GetReturningKeyName());
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb trans BatchInsert error.");
        } else {
            auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
            CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
            retWithResults = rdbStore->BatchInsert(cmd.GetTableName(), values, GetReturningKeyName());
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb BatchInsert error.");
        }
        keys = GetReturningKeys(retWithResults);
        outRowId = keys[0];
    #else
        if (trans_) {
            trans_->Insert(cmd, outRowId);
        } else {
            auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
            CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
            auto ret = rdbStore->Insert(cmd, outRowId);
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb insert error.");
        }
        keys.push_back(static_cast<int32_t> (outRowId));
        ACCURATE_DEBUG("Insert key: %{public}" PRId64, outRowId);
    #endif
    return UpdateModifiedDatasInner(keys, RDB_OPERATION_ADD);
}

int32_t AccurateRefreshBase::Insert(int64_t &outRowId, const string &table, ValuesBucket &value)
{
    if (!IsValidTable(table)) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }

    auto ret = Init();
    if (ret != ACCURATE_REFRESH_RET_OK) {
        MEDIA_WARN_LOG("no Init.");
        return ret;
    }

    lock_guard<mutex> lock(dbOperationMtx_);
    vector<int32_t> keys;
    #ifdef MEDIA_REFRESH_TEST
        pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
        vector<ValuesBucket> values = { value };
        if (trans_) {
            retWithResults = trans_->BatchInsert(table, values, GetReturningKeyName());
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb trans BatchInsert error.");
        } else {
            auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
            CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
            retWithResults = rdbStore->BatchInsert(table, values, GetReturningKeyName());
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb BatchInsert error.");
        }
        keys = GetReturningKeys(retWithResults);
        outRowId = keys[0];
    #else
        if (trans_) {
            auto ret = trans_->Insert(outRowId, table, value);
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb trans insert error.");
        } else {
            auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
            CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
            auto ret = rdbStore->Insert(outRowId, table, value);
            CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb insert error.");
        }
        
        keys.push_back(static_cast<int32_t> (outRowId));
        ACCURATE_DEBUG("Insert key: %{public}" PRId64, outRowId);
    #endif
    return UpdateModifiedDatasInner(keys, RDB_OPERATION_ADD);
}

int32_t AccurateRefreshBase::BatchInsert(MediaLibraryCommand &cmd, int64_t& changedRows, vector<ValuesBucket>& values)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return BatchInsert(changedRows, cmd.GetTableName(), values);
}

int32_t AccurateRefreshBase::BatchInsert(int64_t &changedRows, const string &table,
    vector<ValuesBucket> &values)
{
    if (!IsValidTable(table)) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }

    auto ret = Init();
    if (ret != ACCURATE_REFRESH_RET_OK) {
        MEDIA_WARN_LOG("no Init.");
        return ret;
    }
    lock_guard<mutex> lock(dbOperationMtx_);
    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    if (trans_) {
        retWithResults = trans_->BatchInsert(table, values, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(retWithResults.first != E_HAS_DB_ERROR, E_HAS_DB_ERROR,
            "rdb trans BatchInsert error.");
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->BatchInsert(table, values, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(retWithResults.first != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb BatchInsert error.");
    }
    changedRows = retWithResults.second.changed;
    vector<int32_t> keys = GetReturningKeys(retWithResults);
    return UpdateModifiedDatasInner(keys, RDB_OPERATION_ADD);
}
int32_t AccurateRefreshBase::Update(MediaLibraryCommand &cmd, int32_t &changedRows)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return Update(changedRows, cmd.GetValueBucket(), *(cmd.GetAbsRdbPredicates()));
}

int32_t AccurateRefreshBase::Update(int32_t &changedRows, const string &table, const ValuesBucket &value,
    const string &whereClause, const vector<string> &args)
{
    if (!IsValidTable(table)) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(args);
    return Update(changedRows, value, predicates);
}

int32_t AccurateRefreshBase::Update(int32_t &changedRows, const ValuesBucket &value, const AbsRdbPredicates &predicates,
    RdbOperation operation)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    lock_guard<mutex> lock(dbOperationMtx_);

    // 初始化Init数据
    auto ret = Init(predicates);
    if (ret != ACCURATE_REFRESH_RET_OK) {
        MEDIA_WARN_LOG("no Init.");
        return ret;
    }

    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    if (trans_) {
        retWithResults = trans_->Update(value, predicates, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(retWithResults.first != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb trans Update error.");
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->Update(value, predicates, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(retWithResults.first != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb Update error.");
    }

    vector<int32_t> keys = GetReturningKeys(retWithResults);
    changedRows = retWithResults.second.changed;
    ACCURATE_DEBUG("ret: %{public}d", ret);
    return UpdateModifiedDatasInner(keys, operation);
}

// Files表和Photos表，执行Update；PhotosAlbum表，执行Update；PhotoTable，执行Update；其它执行Delete
// 媒体库设置标识，触发端云同步，同步完成后才会真正的删除放到对应的子类进行处理
int32_t AccurateRefreshBase::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    return ACCURATE_REFRESH_RET_OK;
}

// 同上
int32_t AccurateRefreshBase::Delete(const AbsRdbPredicates &predicates, int32_t &deletedRows)
{
    return ACCURATE_REFRESH_RET_OK;
}

// Delete处理，彻底删除
int32_t AccurateRefreshBase::Delete(int32_t &deletedRows, const string &table, const string &whereClause,
    const vector<string> &args)
{
    if (!IsValidTable(table)) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    // 初始化Init数据
    AbsRdbPredicates predicates(table);
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(args);
    return Delete(deletedRows, predicates);
}

// Delete处理
int32_t AccurateRefreshBase::Delete(int32_t &deletedRows, const AbsRdbPredicates &predicates)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    lock_guard<mutex> lock(dbOperationMtx_);
    auto ret = Init(predicates);
    if (ret != ACCURATE_REFRESH_RET_OK) {
        MEDIA_WARN_LOG("no Init.");
        return ret;
    }
    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    if (trans_) {
        retWithResults = trans_->Delete(predicates, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb Delete error.");
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->Delete(predicates, GetReturningKeyName());
        CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb Delete error.");
    }
    
    vector<int32_t> keys = GetReturningKeys(retWithResults);
    deletedRows = retWithResults.second.changed;
    ACCURATE_DEBUG("deletedRows: %{public}d", deletedRows);
    return UpdateModifiedDatasInner(keys, RDB_OPERATION_REMOVE);
}

int32_t AccurateRefreshBase::UpdateModifiedDatasInner(const vector<int32_t> &keys, RdbOperation operation)
{
    return ACCURATE_REFRESH_RET_OK;
}

vector<int32_t> AccurateRefreshBase::GetReturningKeys(const pair<int32_t, Results> &retWithResults)
{
    stringstream ss;
    vector<int32_t> keys;
    auto resultSet = retWithResults.second.results;
    if (retWithResults.first != ACCURATE_REFRESH_RET_OK) {
        MEDIA_ERR_LOG("ret err: %{publid}d", retWithResults.first);
        return keys;
    }
    do {
        int32_t key = get<int32_t>(ResultSetUtils::GetValFromColumn(GetReturningKeyName(), resultSet, TYPE_INT32));
        keys.push_back(key);
        ss << " " << key;
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    ACCURATE_DEBUG("returning new rows: %{public}s, ret: %{public}d", ss.str().c_str(), retWithResults.first);
    return keys;
}

int32_t AccurateRefreshBase::ExecuteSql(const string &sql, RdbOperation operation)
{
    return ExecuteSql(sql, vector<ValueObject>(), operation);
}

int32_t AccurateRefreshBase::ExecuteForLastInsertedRowId(const string &sql, const vector<ValueObject> &bindArgs,
    RdbOperation operation)
{
    lock_guard<mutex> lock(dbOperationMtx_);
    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    int32_t ret = 0;
    if (trans_) {
        retWithResults = trans_->Execute(sql, bindArgs, GetReturningKeyName());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->Execute(sql, bindArgs, GetReturningKeyName());
    }

    ACCURATE_DEBUG("sql:%{public}s", sql.c_str());
    
    CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb ExecuteForLastInsertedRowId error.");
    vector<int32_t> keys = GetReturningKeys(retWithResults);
    UpdateModifiedDatasInner(keys, operation);
    auto rowId = -1;
    if (!keys.empty()) {
        rowId = keys.back();
    }
    ACCURATE_DEBUG("ExecuteForLastInsertedRowId: %{public}d", rowId);
    return rowId;
}

int32_t AccurateRefreshBase::ExecuteSql(const string &sql, const vector<ValueObject> &bindArgs, RdbOperation operation)
{
    lock_guard<mutex> lock(dbOperationMtx_);
    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    int32_t ret = 0;
    if (trans_) {
        retWithResults = trans_->Execute(sql, bindArgs, GetReturningKeyName());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->Execute(sql, bindArgs, GetReturningKeyName());
    }
    CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb ExecuteSql error.");
    
    vector<int32_t> keys = GetReturningKeys(retWithResults);
    ACCURATE_DEBUG("ExecuteSql: %{public}d", retWithResults.second.changed);
    return UpdateModifiedDatasInner(keys, operation);
}

int32_t AccurateRefreshBase::ExecuteForChangedRowCount(int64_t &outValue, const string &sql,
    const vector<ValueObject> &bindArgs, RdbOperation operation)
{
    lock_guard<mutex> lock(dbOperationMtx_);
    pair<int32_t, Results> retWithResults = {E_HAS_DB_ERROR, -1};
    int32_t ret = 0;
    if (trans_) {
        retWithResults = trans_->Execute(sql, bindArgs, GetReturningKeyName());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null.");
        retWithResults = rdbStore->Execute(sql, bindArgs, GetReturningKeyName());
    }
    
    CHECK_AND_RETURN_RET_LOG(ret != E_HAS_DB_ERROR, E_HAS_DB_ERROR, "rdb ExecuteForChangedRowCount error.");
    outValue = retWithResults.second.changed;
    vector<int32_t> keys = GetReturningKeys(retWithResults);
    ACCURATE_DEBUG("ExecuteForChangedRowCount: %{public}" PRId64, outValue);
    return UpdateModifiedDatasInner(keys, operation);
}

int32_t AccurateRefreshBase::UpdateWithDateTime(ValuesBucket &values, const AbsRdbPredicates &predicates)
{
    if (predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    }
    int32_t changedRows = -1;
    auto ret = Update(changedRows, values, predicates);
    if (ret != ACCURATE_REFRESH_RET_OK) {
        ACCURATE_ERR("ret: 0x%{public}x", ret);
        return -1;
    }
    return changedRows;
}

} // namespace Media
} // namespace OHOS