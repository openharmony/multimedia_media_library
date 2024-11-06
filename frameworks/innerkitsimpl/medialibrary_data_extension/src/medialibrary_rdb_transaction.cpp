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

#include "medialibrary_rdb_transaction.h"
#include "medialibrary_restore.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::NativeRdb;
constexpr int32_t E_HAS_DB_ERROR = -222;
constexpr int32_t E_OK = 0;

TransactionOperations::TransactionOperations() {}

TransactionOperations::~TransactionOperations()
{
    Rollback();
}

void TransactionOperations::SetBackupRdbStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore)
{
    backupRdbStore_ = rdbStore;
}

int32_t TransactionOperations::Start(std::string funcName, bool isBackup)
{
    funcName_ = funcName;
    MEDIA_INFO_LOG("Start transaction_, funName is :%{public}s", funcName_.c_str());
    if (isBackup) {
        rdbStore_ = backupRdbStore_;
    } else {
        rdbStore_ = MediaLibraryRdbStore::GetRaw();
    }

    int currentTime = 0;
    int32_t busyRetryTime = 0;
    int errCode = -1;
    while (busyRetryTime < MAX_BUSY_TRY_TIMES && currentTime <= MAX_TRY_TIMES) {
        auto [ret, transaction] = rdbStore_->CreateTransaction(OHOS::NativeRdb::Transaction::DEFERRED);
        errCode = ret;
        if (ret == NativeRdb::E_OK) {
            transaction_ = transaction;
            break;
        } else if (ret == NativeRdb::E_SQLITE_LOCKED) {
            this_thread::sleep_for(chrono::milliseconds(TRANSACTION_WAIT_INTERVAL));
            currentTime++;
            MEDIA_ERR_LOG("CreateTransaction busy, ret:%{public}d, time:%{public}d", ret, currentTime);
        } else if (ret == NativeRdb::E_SQLITE_BUSY || ret == NativeRdb::E_DATABASE_BUSY) {
            busyRetryTime++;
            MEDIA_ERR_LOG("CreateTransaction busy, ret:%{public}d, busyRetryTime:%{public}d", ret, busyRetryTime);
        } else {
            MEDIA_ERR_LOG("CreateTransaction faile, ret = %{public}d", ret);
            break;
        }
    }
    if (errCode != NativeRdb::E_OK) {
        errCode = E_HAS_DB_ERROR;
    }
    return errCode;
}

int32_t TransactionOperations::Finish()
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("Commit transaction, funcName is :%{public}s", funcName_.c_str());
    auto ret = transaction_->Commit();
    if (ret == NativeRdb::E_OK) {
        transaction_ = nullptr;
        return NativeRdb::E_OK;
    }
    MEDIA_ERR_LOG("transaction commit fail!, ret:%{public}d", ret);
    return ret;
}

int32_t TransactionOperations::Rollback()
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return NativeRdb::E_OK;
    }
    auto ret = transaction_->Rollback();
    if (ret == NativeRdb::E_OK) {
        transaction_ = nullptr;
        return ret;
    }
    MEDIA_ERR_LOG("Rollback fail:%{public}d", ret);
    return ret;
}

int32_t TransactionOperations::ExecuteSql(const std::string &sql, const std::vector<NativeRdb::ValueObject> &args)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
    auto [ret, value] = transaction_->Execute(sql, args);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

int32_t TransactionOperations::Execute(const std::string &sql, const std::vector<NativeRdb::ValueObject> &args)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
    auto [ret, value] = transaction_->Execute(sql, args);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Execute failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

int32_t TransactionOperations::ExecuteForLastInsertedRowId(const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
    int64_t lastInsertRowId = 0;
    auto [err, valueObject] = transaction_->Execute(sql, bindArgs);
    (void)valueObject.GetLong(lastInsertRowId);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute insert, err: %{public}d", err);
        MediaLibraryRestore::GetInstance().CheckRestore(err);
        return E_HAS_DB_ERROR;
    }
    return lastInsertRowId;
}

int32_t TransactionOperations::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }

    auto [ret, rows] = transaction_->Insert(cmd.GetTableName(), cmd.GetValueBucket());
    rowId = rows;
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

int32_t TransactionOperations::Update(NativeRdb::ValuesBucket &values, const NativeRdb::AbsRdbPredicates &predicates)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
        if (predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    }
    auto [err, changedRows] = transaction_->Update(values, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute update, err: %{public}d", err);
        MediaLibraryRestore::GetInstance().CheckRestore(err);
        return E_HAS_DB_ERROR;
    }
    return changedRows;
}

int32_t TransactionOperations::Update(int32_t &changedRows, NativeRdb::ValuesBucket &values,
    const NativeRdb::AbsRdbPredicates &predicates)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction is null");
        return E_HAS_DB_ERROR;
    }
        auto [err, rows] = transaction_->Update(values, predicates);
    changedRows = rows;
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute update, err: %{public}d", err);
        MediaLibraryRestore::GetInstance().CheckRestore(err);
        return err;
    }
    return err;
}

int32_t TransactionOperations::Update(MediaLibraryCommand &cmd, int32_t &changedRows)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return E_HAS_DB_ERROR;
    }

    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        cmd.GetValueBucket().PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED,
            MediaFileUtils::UTCTimeMilliSeconds());
        cmd.GetValueBucket().PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME,
            MediaFileUtils::UTCTimeMilliSeconds());
    }

    int32_t ret = E_HAS_DB_ERROR;
    auto res = transaction_->Update(cmd.GetTableName(), cmd.GetValueBucket(),
        cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetBindArgs());
    ret = res.first;
    changedRows = res.second;

    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Update failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

int32_t TransactionOperations::BatchInsert(int64_t &outRowId, const std::string &table,
    const std::vector<NativeRdb::ValuesBucket> &values)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return E_HAS_DB_ERROR;
    }

    auto [ret, rows] = transaction_->BatchInsert(table, values);
    outRowId = rows;
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("transaction_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    MEDIA_DEBUG_LOG("transaction_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outRowId, ret);
    return ret;
}

int32_t TransactionOperations::BatchInsert(MediaLibraryCommand &cmd, int64_t& outInsertNum,
    const std::vector<ValuesBucket>& values)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return E_HAS_DB_ERROR;
    }
    auto [ret, rows] = transaction_->BatchInsert(cmd.GetTableName(), values);
    outInsertNum = rows;
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("transaction_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    MEDIA_DEBUG_LOG("rdbStore_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outInsertNum, ret);
    return ret;
}

int32_t TransactionOperations::Insert(int64_t &rowId, const std::string tableName,
    const NativeRdb::ValuesBucket &values)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return E_HAS_DB_ERROR;
    }

    auto [ret, rows] = transaction_->Insert(tableName, values);
    rowId = rows;
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("transaction_->Insert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("transaction_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

static int32_t DoDeleteFromPredicates(const AbsRdbPredicates &predicates,
    int32_t &deletedRows, std::shared_ptr<OHOS::NativeRdb::Transaction> transaction)
{
    int32_t ret = NativeRdb::E_ERROR;
    string tableName = predicates.GetTableName();
    ValuesBucket valuesBucket;
    if (tableName == MEDIALIBRARY_TABLE || tableName == PhotoColumn::PHOTOS_TABLE) {
        valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        valuesBucket.PutInt(MEDIA_DATA_DB_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_UPLOAD));
        valuesBucket.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        auto res = transaction->Update(valuesBucket, predicates);
        ret = res.first;
        deletedRows = res.second;
        MEDIA_INFO_LOG("delete photos permanently, ret: %{public}d", ret);
    } else if (tableName == PhotoAlbumColumns::TABLE) {
        valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        auto res = transaction->Update(valuesBucket, predicates);
        ret = res.first;
        deletedRows = res.second;
    } else if (tableName == PhotoMap::TABLE) {
        valuesBucket.PutInt(PhotoMap::DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        auto res = transaction->Update(valuesBucket, predicates);
        ret = res.first;
        deletedRows = res.second;
    } else {
        auto res = transaction->Delete(predicates);
        ret = res.first;
        deletedRows = res.second;
    }
    return ret;
}

int32_t TransactionOperations::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (transaction_ == nullptr) {
        MEDIA_ERR_LOG("transaction_ is null");
        return E_HAS_DB_ERROR;
    }
    /* local delete */
    int32_t ret = DoDeleteFromPredicates(*(cmd.GetAbsRdbPredicates()), deletedRows, transaction_);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}
} // namespace OHOS::Media
