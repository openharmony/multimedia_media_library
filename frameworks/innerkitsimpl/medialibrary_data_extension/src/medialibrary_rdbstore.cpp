/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "RdbStore"

#include "medialibrary_rdbstore.h"

#include <mutex>

#include "media_log.h"
#include "medialibrary_device.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "sqlite_database_utils.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "cloud_sync_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media {
shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::rdbStore_;

const std::string MediaLibraryRdbStore::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    CloudSyncHelper::GetInstance()->StartSync();
    return "";
}

const std::string MediaLibraryRdbStore::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "true";
}

MediaLibraryRdbStore::MediaLibraryRdbStore(const shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    string databaseDir = context->GetDatabaseDir();
    string name = MEDIA_DATA_ABILITY_DB_NAME;
    int32_t errCode = 0;
    string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, name, errCode);
    config_.SetName(move(name));
    config_.SetPath(move(realPath));
    config_.SetBundleName(context->GetBundleName());
    config_.SetArea(context->GetArea());
    config_.SetSecurityLevel(SecurityLevel::S3);
    config_.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config_.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
    isInTransaction_.store(false);
}

int32_t MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("Init rdb store");
    if (rdbStore_ != nullptr) {
        return E_OK;
    }

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack;
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("GetRdbStore is failed ");
        return E_ERR;
    }

    if (rdbDataCallBack.HasDistributedTables()) {
        int ret = rdbStore_->SetDistributedTables(
            { MEDIALIBRARY_TABLE, PhotoColumn::PHOTOS_TABLE, AudioColumn::AUDIOS_TABLE,
            SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE });
        MEDIA_DEBUG_LOG("ret = %{private}d", ret);
    }

    if (!SubscribeRdbStoreObserver()) {
        MEDIA_ERR_LOG("subscribe rdb observer err");
        return E_ERR;
    }

    MEDIA_INFO_LOG("SUCCESS");
    return E_OK;
}

MediaLibraryRdbStore::~MediaLibraryRdbStore() = default;

void MediaLibraryRdbStore::Stop()
{
    if (rdbStore_ == nullptr) {
        return;
    }

    UnSubscribeRdbStoreObserver();
    rdbStore_ = nullptr;
}

bool MediaLibraryRdbStore::SubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("SubscribeRdbStoreObserver rdbStore is null");
        return false;
    }
    rdbStoreObs_ = make_shared<MediaLibraryRdbStoreObserver>(bundleName_);
    if (rdbStoreObs_ == nullptr) {
        return false;
    }

    DistributedRdb::SubscribeOption option{};
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    int ret = rdbStore_->Subscribe(option, rdbStoreObs_.get());
    MEDIA_DEBUG_LOG("Subscribe ret = %d", ret);

    return ret == E_OK;
}

bool MediaLibraryRdbStore::UnSubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("UnSubscribeRdbStoreObserver rdbStore is null");
        return false;
    }

    DistributedRdb::SubscribeOption option{};
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    int ret = rdbStore_->UnSubscribe(option, rdbStoreObs_.get());
    MEDIA_DEBUG_LOG("UnSubscribe ret = %d", ret);
    if (ret == E_OK) {
        rdbStoreObs_ = nullptr;
        return true;
    }

    return false;
}

void GetAllNetworkId(vector<string> &networkIds)
{
    vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    MediaLibraryDevice::GetInstance()->GetAllNetworkId(deviceList);
    for (auto& deviceInfo : deviceList) {
        networkIds.push_back(deviceInfo.networkId);
    }
}

int32_t MediaLibraryRdbStore::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Insert");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    if (MediaLibraryDevice::GetInstance()->IsHasActiveDevice()) {
        vector<string> devices = vector<string>();
        GetAllNetworkId(devices);
        SyncPushTable(bundleName_, cmd.GetTableName(), rowId, devices);
    }

    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    int32_t ret = NativeRdb::E_ERROR;
    if (cmd.GetTableName() == MEDIALIBRARY_TABLE || cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        ValuesBucket valuesBucket;
        valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        ret = rdbStore_->Update(deletedRows, cmd.GetTableName(), valuesBucket,
            cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetWhereArgs());
        CloudSyncHelper::GetInstance()->StartSync();
    } else {
        ret = rdbStore_->Delete(deletedRows, cmd.GetTableName(), cmd.GetAbsRdbPredicates()->GetWhereClause(),
            cmd.GetAbsRdbPredicates()->GetWhereArgs());
    }
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    vector<string> devices = vector<string>();
    GetAllNetworkId(devices);
    SyncPushTable(bundleName_, cmd.GetTableName(), deletedRows, devices);

    return ret;
}

int32_t MediaLibraryRdbStore::Update(MediaLibraryCommand &cmd, int32_t &changedRows)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Update(changedRows, cmd.GetTableName(), cmd.GetValueBucket(),
        cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Update failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    vector<string> devices = vector<string>();
    GetAllNetworkId(devices);
    SyncPushTable(bundleName_, cmd.GetTableName(), changedRows, devices);
    return ret;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(MediaLibraryCommand &cmd,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }
    if (cmd.GetTableName() == MEDIALIBRARY_TABLE || cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
        string dirtyFilterCondition = "dirty <> " + std::to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED));
        if (!strQueryCondition.empty()) {
            dirtyFilterCondition += " AND ";
            strQueryCondition = dirtyFilterCondition + strQueryCondition;
        } else {
            strQueryCondition = dirtyFilterCondition;
        }
        cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    }
    auto *predicates = cmd.GetAbsRdbPredicates();
#ifdef ML_DEBUG
    MEDIA_DEBUG_LOG("tablename = %s", cmd.GetTableName().c_str());
    for (auto &col : columns) {
        MEDIA_DEBUG_LOG("col = %s", col.c_str());
    }
    MEDIA_DEBUG_LOG("whereClause = %s", predicates->GetWhereClause().c_str());
    for (auto &arg : predicates->GetWhereArgs()) {
        MEDIA_DEBUG_LOG("whereArgs = %s", arg.c_str());
    }
    MEDIA_DEBUG_LOG("limit = %d", predicates->GetLimit());
#endif

    return rdbStore_->Query(*predicates, columns);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(const AbsRdbPredicates &predicates,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }
    return rdbStore_->Query(predicates, columns);
}

int32_t MediaLibraryRdbStore::ExecuteSql(const string &sql)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

void MediaLibraryRdbStore::BuildValuesSql(const NativeRdb::ValuesBucket &values, vector<ValueObject> &bindArgs,
    string &sql)
{
    map<string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    sql.append("(");
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql.append(((iter == valuesMap.begin()) ? "" : ", "));
        sql.append(iter->first);               // columnName
        bindArgs.push_back(iter->second); // columnValue
    }

    sql.append(") select ");
    for (size_t i = 0; i < valuesMap.size(); i++) {
        sql.append(((i == 0) ? "?" : ", ?"));
    }
    sql.append(" ");
}

void MediaLibraryRdbStore::BuildQuerySql(const AbsRdbPredicates &predicates, const vector<string> &columns,
    vector<ValueObject> &bindArgs, string &sql)
{
    sql.append(SqliteSqlBuilder::BuildQueryString(predicates, columns));
    for (auto &arg : predicates.GetWhereArgs()) {
        bindArgs.emplace_back(arg);
    }
}

/**
 * Returns last insert row id. If insert succeed but no new rows inserted, then return -1.
 * Return E_HAS_DB_ERROR on error cases.
 */
int32_t MediaLibraryRdbStore::ExecuteForLastInsertedRowId(const string &sql, const vector<ValueObject> &bindArgs)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int64_t lastInsertRowId = 0;
    int32_t err = rdbStore_->ExecuteForLastInsertedRowId(lastInsertRowId, sql, bindArgs);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute insert, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return lastInsertRowId;
}

int32_t MediaLibraryRdbStore::Delete(const AbsRdbPredicates &predicates)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    int err = E_ERR;
    int32_t deletedRows = 0;
    if (predicates.GetTableName() == MEDIALIBRARY_TABLE || predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        ValuesBucket valuesBucket;
        valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        err = rdbStore_->Update(deletedRows, valuesBucket, predicates);
        CloudSyncHelper::GetInstance()->StartSync();
    } else {
        err = rdbStore_->Delete(deletedRows, predicates);
    }

    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute delete, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return deletedRows;
}

/**
 * Return changed rows on success, or negative values on error cases.
 */
int32_t MediaLibraryRdbStore::Update(int32_t &changedRows, const ValuesBucket &values,
    const AbsRdbPredicates &predicates)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int err = rdbStore_->Update(changedRows, values, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute update, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return changedRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QuerySql(const string &sql, const vector<string> &selectionArgs)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return nullptr;
    }

    return rdbStore_->QuerySql(sql, selectionArgs);
}

int32_t MediaLibraryRdbStore::BeginTransaction()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    unique_lock<mutex> cvLock(transactionMutex_);
    if (isInTransaction_.load()) {
        transactionCV_.wait_for(cvLock, chrono::milliseconds(RDB_TRANSACTION_WAIT_MS),
            [this] () { return !(isInTransaction_.load()); });
    }

    if (rdbStore_->IsInTransaction()) {
        MEDIA_ERR_LOG("RdbStore is still in transaction");
        return E_HAS_DB_ERROR;
    }

    isInTransaction_.store(true);
    int32_t errCode = rdbStore_->BeginTransaction();
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Start Transaction failed, errCode=%{public}d", errCode);
        isInTransaction_.store(false);
        transactionCV_.notify_one();
        return E_HAS_DB_ERROR;
    }

    return E_OK;
}

int32_t MediaLibraryRdbStore::Commit()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    if (!(isInTransaction_.load()) || !(rdbStore_->IsInTransaction())) {
        MEDIA_ERR_LOG("no transaction now");
        return E_HAS_DB_ERROR;
    }

    int32_t errCode = rdbStore_->Commit();
    isInTransaction_.store(false);
    transactionCV_.notify_all();
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("commit failed, errCode=%{public}d", errCode);
        return E_HAS_DB_ERROR;
    }

    return E_OK;
}

int32_t MediaLibraryRdbStore::RollBack()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    if (!(isInTransaction_.load()) || !(rdbStore_->IsInTransaction())) {
        MEDIA_ERR_LOG("no transaction now");
        return E_HAS_DB_ERROR;
    }

    int32_t errCode = rdbStore_->RollBack();
    isInTransaction_.store(false);
    transactionCV_.notify_all();
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rollback failed, errCode=%{public}d", errCode);
        return E_HAS_DB_ERROR;
    }

    return E_OK;
}

shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::GetRaw() const
{
    return rdbStore_;
}

string MediaLibraryRdbStore::ObtainTableName(MediaLibraryCommand &cmd)
{
    const string &networkId = cmd.GetOprnDevice();
    int errCode = E_ERR;
    if (!networkId.empty()) {
        return rdbStore_->ObtainDistributedTableName(networkId, cmd.GetTableName(), errCode);
    }

    return cmd.GetTableName();
}

bool MediaLibraryRdbStore::SyncPullTable(const string &bundleName, const string &tableName,
    int32_t rowId, vector<string> &devices)
{
    MediaLibrarySyncOpts syncOpts;
    SetSyncOpts(syncOpts, bundleName, tableName, rowId);
    return MediaLibrarySyncOperation::SyncPullTable(syncOpts, devices);
}

bool MediaLibraryRdbStore::SyncPushTable(const string &bundleName, const string &tableName,
    int32_t rowId, vector<string> &devices, bool isBlock)
{
    MediaLibrarySyncOpts syncOpts;
    SetSyncOpts(syncOpts, bundleName, tableName, rowId);
    return MediaLibrarySyncOperation::SyncPushTable(syncOpts, devices, isBlock);
}

void MediaLibraryRdbStore::SetSyncOpts(MediaLibrarySyncOpts &syncOpts, const string &bundleName,
    const string &tableName, int32_t rowId)
{
    syncOpts.table = tableName;
    syncOpts.bundleName = bundleName;
    if (rowId >= 0) {
        syncOpts.row = to_string(rowId);
    }
    syncOpts.rdbStore = rdbStore_;
}

inline void BuildInsertSystemAlbumSql(const ValuesBucket &values, const AbsRdbPredicates &predicates,
    string &sql, vector<ValueObject> &bindArgs)
{
    // Build insert sql
    sql.append("INSERT").append(" OR ROLLBACK ").append(" INTO ").append(PhotoAlbumColumns::TABLE).append(" ");
    MediaLibraryRdbStore::BuildValuesSql(values, bindArgs, sql);
    sql.append(" WHERE NOT EXISTS (");
    MediaLibraryRdbStore::BuildQuerySql(predicates, { PhotoAlbumColumns::ALBUM_ID }, bindArgs, sql);
    sql.append(");");
}

int32_t PrepareSystemAlbums(RdbStore &store)
{
    ValuesBucket values;
    int32_t err = E_FAIL;
    store.BeginTransaction();
    for (int32_t i = PhotoAlbumSubType::SYSTEM_START; i <= PhotoAlbumSubType::SYSTEM_END; i++) {
        values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::SYSTEM);
        values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, i);

        AbsRdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(i));

        string sql;
        vector<ValueObject> bindArgs;
        BuildInsertSystemAlbumSql(values, predicates, sql, bindArgs);
        err = store.ExecuteSql(sql, bindArgs);
        if (err != E_OK) {
            store.RollBack();
            return err;
        }
        values.Clear();
    }
    store.Commit();
    return E_OK;
}

int32_t MediaLibraryDataCallBack::PrepareDir(RdbStore &store)
{
    DirValuesBucket cameraDir = {
        CAMERA_DIRECTORY_TYPE_VALUES, CAMERA_DIR_VALUES, CAMERA_TYPE_VALUES, CAMERA_EXTENSION_VALUES
    };
    DirValuesBucket videoDir = {
        VIDEO_DIRECTORY_TYPE_VALUES, VIDEO_DIR_VALUES, VIDEO_TYPE_VALUES, VIDEO_EXTENSION_VALUES
    };
    DirValuesBucket pictureDir = {
        PIC_DIRECTORY_TYPE_VALUES, PIC_DIR_VALUES, PIC_TYPE_VALUES, PIC_EXTENSION_VALUES
    };
    DirValuesBucket audioDir = {
        AUDIO_DIRECTORY_TYPE_VALUES, AUDIO_DIR_VALUES, AUDIO_TYPE_VALUES, AUDIO_EXTENSION_VALUES
    };
    DirValuesBucket documentDir = {
        DOC_DIRECTORY_TYPE_VALUES, DOC_DIR_VALUES, DOC_TYPE_VALUES, DOC_EXTENSION_VALUES
    };
    DirValuesBucket downloadDir = {
        DOWNLOAD_DIRECTORY_TYPE_VALUES, DOWNLOAD_DIR_VALUES, DOWNLOAD_TYPE_VALUES, DOWNLOAD_EXTENSION_VALUES
    };

    vector<DirValuesBucket> dirValuesBuckets = {
        cameraDir, videoDir, pictureDir, audioDir, documentDir, downloadDir
    };

    for (const auto& dirValuesBucket : dirValuesBuckets) {
        if (InsertDirValues(dirValuesBucket, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("PrepareDir failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::InsertDirValues(const DirValuesBucket &dirValuesBucket, RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(DIRECTORY_DB_DIRECTORY_TYPE, dirValuesBucket.directoryType);
    valuesBucket.PutString(DIRECTORY_DB_DIRECTORY, dirValuesBucket.dirValues);
    valuesBucket.PutString(DIRECTORY_DB_MEDIA_TYPE, dirValuesBucket.typeValues);
    valuesBucket.PutString(DIRECTORY_DB_EXTENSION, dirValuesBucket.extensionValues);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("insert dir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareSmartAlbum(RdbStore &store)
{
    SmartAlbumValuesBucket trashAlbum = {
        TRASH_ALBUM_ID_VALUES, TRASH_ALBUM_NAME_VALUES, TRASH_ALBUM_TYPE_VALUES
    };

    SmartAlbumValuesBucket favAlbum = {
        FAVOURITE_ALBUM_ID_VALUES, FAVOURTIE_ALBUM_NAME_VALUES, FAVOURITE_ALBUM_TYPE_VALUES
    };

    vector<SmartAlbumValuesBucket> smartAlbumValuesBuckets = {
        trashAlbum, favAlbum
    };

    for (const auto& smartAlbum : smartAlbumValuesBuckets) {
        if (InsertSmartAlbumValues(smartAlbum, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Prepare smartAlbum failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::InsertSmartAlbumValues(const SmartAlbumValuesBucket &smartAlbum, RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(SMARTALBUM_DB_ID, smartAlbum.albumId);
    valuesBucket.PutString(SMARTALBUM_DB_NAME, smartAlbum.albumName);
    valuesBucket.PutInt(SMARTALBUM_DB_ALBUM_TYPE, smartAlbum.albumType);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, SMARTALBUM_TABLE, valuesBucket);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareUniqueMemberTable(RdbStore &store)
{
    string queryRowSql = "SELECT COUNT(*) as count FROM " + ASSET_UNIQUE_NUMBER_TABLE;
    auto resultSet = store.QuerySql(queryRowSql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get AssetUniqueNumberTable count");
        return NativeRdb::E_ERROR;
    }
    if (GetInt32Val("count", resultSet) != 0) {
        MEDIA_DEBUG_LOG("AssetUniqueNumberTable is already inited");
        return E_OK;
    }

    UniqueMemberValuesBucket imageBucket = { IMAGE_ASSET_TYPE, 0 };
    UniqueMemberValuesBucket videoBucket = { VIDEO_ASSET_TYPE, 0 };
    UniqueMemberValuesBucket audioBucket = { AUDIO_ASSET_TYPE, 0 };

    vector<UniqueMemberValuesBucket> uniqueNumberValueBuckets = {
        imageBucket, videoBucket, audioBucket
    };

    for (const auto& uniqueNumberValueBucket : uniqueNumberValueBuckets) {
        if (InsertUniqueMemberTableValues(uniqueNumberValueBucket, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Prepare smartAlbum failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::InsertUniqueMemberTableValues(const UniqueMemberValuesBucket &uniqueMemberValues,
    RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString(ASSET_MEDIA_TYPE, uniqueMemberValues.assetMediaType);
    valuesBucket.PutInt(UNIQUE_NUMBER, uniqueMemberValues.startNumber);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, ASSET_UNIQUE_NUMBER_TABLE, valuesBucket);
    return insertResult;
}

static const string &TriggerDeleteAlbumClearMap()
{
    static const string TRIGGER_CLEAR_MAP = BaseColumn::CreateTrigger() + "photo_album_clear_map" +
    " AFTER DELETE ON " + PhotoAlbumColumns::TABLE +
    " BEGIN " +
        "DELETE FROM " + PhotoMap::TABLE +
        " WHERE " + PhotoMap::ALBUM_ID + "=" + "OLD." + PhotoAlbumColumns::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_CLEAR_MAP;
}

static const string &TriggerAddAssets()
{
    static const string TRIGGER_ADD_ASSETS = BaseColumn::CreateTrigger() + "photo_album_insert_asset" +
    " AFTER INSERT ON " + PhotoMap::TABLE +
    " BEGIN " +
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
            PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1 " +
        "WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + "NEW." + PhotoMap::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_ADD_ASSETS;
}

static const string &TriggerRemoveAssets()
{
    static const string TRIGGER_REMOVE_ASSETS = BaseColumn::CreateTrigger() + "photo_album_delete_asset" +
    " AFTER DELETE ON " + PhotoMap::TABLE +
    " BEGIN " +
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
            PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1 " +
        "WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + "OLD." + PhotoMap::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_REMOVE_ASSETS;
}

static const string &TriggerDeletePhotoClearMap()
{
    static const string TRIGGER_DELETE_ASSETS = BaseColumn::CreateTrigger() + "delete_photo_clear_map" +
    " AFTER DELETE ON " + PhotoColumn::PHOTOS_TABLE +
    " BEGIN " +
        "DELETE FROM " + PhotoMap::TABLE +
        " WHERE " + PhotoMap::ASSET_ID + "=" + "OLD." + MediaColumn::MEDIA_ID + ";" +
    " END;";
    return TRIGGER_DELETE_ASSETS;
}

static const string &QueryAlbumJoinMap()
{
    static const string QUERY_ALBUM_JOIN_MAP = " SELECT " + PhotoAlbumColumns::ALBUM_ID +
        " FROM " + PhotoAlbumColumns::TABLE + " INNER JOIN " + PhotoMap::TABLE + " ON " +
            PhotoAlbumColumns::ALBUM_ID + " = " + PhotoMap::ALBUM_ID + " AND " +
            PhotoMap::ASSET_ID + " = " + "NEW." + MediaColumn::MEDIA_ID;
    return QUERY_ALBUM_JOIN_MAP;
}

static const string &SetHiddenUpdateCount()
{
    // Photos.hidden 1 -> 0
    static const string SET_HIDDEN_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(OLD." + MediaColumn::MEDIA_HIDDEN + " - NEW." + MediaColumn::MEDIA_HIDDEN + " > 0)" +
        ");";
    return SET_HIDDEN_UPDATE_COUNT;
}

static const string &SetTrashUpdateCount()
{
    // Photos.date_trashed timestamp -> 0
    static const string SET_TRASH_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") = 0" + " AND " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(" +
                    "SIGN(OLD." + MediaColumn::MEDIA_DATE_TRASHED + ") - " +
                    "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") > 0" +
                ")" +
        ");";
    return SET_TRASH_UPDATE_COUNT;
}

static const string &UnSetHiddenUpdateCount()
{
    // Photos.hidden 0 -> 1
    static const string UNSET_HIDDEN_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 1" + " AND " +
                "(NEW." + MediaColumn::MEDIA_HIDDEN + " - OLD." + MediaColumn::MEDIA_HIDDEN + " > 0)" +
        ");";
    return UNSET_HIDDEN_UPDATE_COUNT;
}

static const string &UnSetTrashUpdateCount()
{
    // Photos.date_trashed 0 -> timestamp
    static const string UNSET_TRASH_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") = 1" + " AND " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(" +
                    "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") - "
                    "SIGN(OLD." + MediaColumn::MEDIA_DATE_TRASHED + ") > 0" +
                ")" +
        ");";
    return UNSET_TRASH_UPDATE_COUNT;
}

static const string &TriggerUpdateUserAlbumCount()
{
    static const string TRIGGER_UPDATE_USER_ALBUM_COUNT = BaseColumn::CreateTrigger() + "update_user_album_count" +
        " AFTER UPDATE ON " + PhotoColumn::PHOTOS_TABLE +
        " BEGIN " +
            SetHiddenUpdateCount() +
            SetTrashUpdateCount() +
            UnSetHiddenUpdateCount() +
            UnSetTrashUpdateCount() +
        " END;";
    return TRIGGER_UPDATE_USER_ALBUM_COUNT;
}

static int32_t ExecuteSql(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_MEDIA_TABLE,
        PhotoColumn::CREATE_PHOTO_TABLE,
        PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_FDIRTY_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_INSERT_CLOUD_SYNC,
        AudioColumn::CREATE_AUDIO_TABLE,
        CREATE_SMARTALBUM_TABLE,
        CREATE_SMARTALBUMMAP_TABLE,
        CREATE_DEVICE_TABLE,
        CREATE_CATEGORY_SMARTALBUMMAP_TABLE,
        CREATE_ASSET_UNIQUE_NUMBER_TABLE,
        CREATE_IMAGE_VIEW,
        CREATE_VIDEO_VIEW,
        CREATE_AUDIO_VIEW,
        CREATE_ALBUM_VIEW,
        CREATE_SMARTALBUMASSETS_VIEW,
        CREATE_ASSETMAP_VIEW,
        CREATE_MEDIATYPE_DIRECTORY_TABLE,
        CREATE_BUNDLE_PREMISSION_TABLE,
        CREATE_MEDIALIBRARY_ERROR_TABLE,
        CREATE_REMOTE_THUMBNAIL_TABLE,
        CREATE_FILES_DELETE_TRIGGER,
        CREATE_FILES_MDIRTY_TRIGGER,
        CREATE_FILES_FDIRTY_TRIGGER,
        CREATE_INSERT_CLOUD_SYNC_TRIGGER,
        PhotoAlbumColumns::CREATE_TABLE,
        PhotoAlbumColumns::INDEX_ALBUM_TYPES,
        PhotoMap::CREATE_TABLE,
        TriggerDeleteAlbumClearMap(),
        TriggerAddAssets(),
        TriggerRemoveAssets(),
        TriggerDeletePhotoClearMap(),
        TriggerUpdateUserAlbumCount(),
    };

    for (const string& sqlStr : executeSqlStrs) {
        if (store.ExecuteSql(sqlStr) != NativeRdb::E_OK) {
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    if (ExecuteSql(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareSystemAlbums(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareDir(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareSmartAlbum(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareUniqueMemberTable(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    isDistributedTables = true;
    return NativeRdb::E_OK;
}

int32_t VersionAddCloud(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    const std::string alterCloudId = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_CLOUD_ID +" TEXT";
    int32_t result = store.ExecuteSql(alterCloudId);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb cloud_id error %{private}d", result);
    }
    const std::string alterDirty = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_DIRTY +" INT DEFAULT 0";
    result = store.ExecuteSql(alterDirty);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb dirty error %{private}d", result);
    }
    const std::string alterPosition = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_POSITION +" INT DEFAULT 1";
    result = store.ExecuteSql(alterPosition);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb position error %{private}d", result);
    }
    return NativeRdb::E_OK;
}

int32_t AddMetaModifiedColumn(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    const std::string alterMetaModified =
        "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN " +
        MEDIA_DATA_DB_META_DATE_MODIFIED + " BIGINT DEFAULT 0";
    int32_t result = store.ExecuteSql(alterMetaModified);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb meta_date_modified error %{private}d", result);
    }
    const std::string alterSyncing = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_SYNCING + " INT DEFAULT 0";
    result = store.ExecuteSql(alterSyncing);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb syncing error %{private}d", result);
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    MEDIA_DEBUG_LOG("OnUpgrade old:%d, new:%d", oldVersion, newVersion);
    if (oldVersion < MEDIA_RDB_VERSION_ADD_CLOUD) {
        VersionAddCloud(store, oldVersion, newVersion);
    }
    if (oldVersion < MEDIA_RDB_VERSION_ADD_META_MODIFED) {
        AddMetaModifiedColumn(store, oldVersion, newVersion);
    }
    return NativeRdb::E_OK;
}

bool MediaLibraryDataCallBack::HasDistributedTables()
{
    return isDistributedTables;
}

MediaLibraryRdbStoreObserver::MediaLibraryRdbStoreObserver(const string &bundleName)
{
    bundleName_ = bundleName;
    isNotifyDeviceChange_ = false;

    if (timer_ == nullptr) {
        timer_ = make_unique<OHOS::Utils::Timer>(bundleName_);
        timerId_ = timer_->Register(bind(&MediaLibraryRdbStoreObserver::NotifyDeviceChange, this),
            NOTIFY_TIME_INTERVAL);
        timer_->Setup();
    }
}

MediaLibraryRdbStoreObserver::~MediaLibraryRdbStoreObserver()
{
    if (timer_ != nullptr) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
}

void MediaLibraryRdbStoreObserver::OnChange(const vector<string> &devices)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreObserver OnChange call");
    if (devices.empty() || bundleName_.empty()) {
        return;
    }
    MediaLibraryDevice::GetInstance()->NotifyRemoteFileChange();
}

void MediaLibraryRdbStoreObserver::NotifyDeviceChange()
{
    if (isNotifyDeviceChange_) {
        MediaLibraryDevice::GetInstance()->NotifyDeviceChange();
        isNotifyDeviceChange_ = false;
    }
}

TransactionOperations::TransactionOperations()
{
    rdbStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
}

TransactionOperations::~TransactionOperations()
{
    if (isStart && !isFinish) {
        TransactionRollback();
    }
}

int32_t TransactionOperations::Start()
{
    if (isStart || isFinish) {
        return E_OK;
    }
    isStart = true;
    return BeginTransaction();
}

void TransactionOperations::Finish()
{
    if (!isStart) {
        return;
    }
    if (!isFinish) {
        int32_t ret = TransactionCommit();
        if (ret == E_OK) {
            isFinish = true;
        } else {
            MEDIA_ERR_LOG("Failed to commit transaction, errCode=%{public}d", ret);
        }
    }
}

int32_t TransactionOperations::BeginTransaction()
{
    if (rdbStore_ == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore_->BeginTransaction();
}

int32_t TransactionOperations::TransactionCommit()
{
    if (rdbStore_ == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore_->Commit();
}

int32_t TransactionOperations::TransactionRollback()
{
    if (rdbStore_ == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore_->RollBack();
}
} // namespace OHOS::Media
