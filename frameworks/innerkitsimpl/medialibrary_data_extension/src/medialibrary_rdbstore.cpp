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

#include "media_column.h"
#include "media_log.h"
#include "medialibrary_device.h"
#include "medialibrary_errno.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_tracer.h"
#include "result_set_utils.h"
#include "sqlite_database_utils.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media {
std::shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::rdbStore_;

MediaLibraryRdbStore::MediaLibraryRdbStore(const shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    string databaseDir = context->GetDatabaseDir();
    string name = MEDIA_DATA_ABILITY_DB_NAME;
    int32_t errCode = 0;
    std::string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, name, errCode);
    config_.SetName(std::move(name));
    config_.SetPath(std::move(realPath));
    config_.SetBundleName(context->GetBundleName());
    config_.SetArea(context->GetArea());
    config_.SetReadConSize(RDB_CONNECT_NUM);
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
            DocumentColumn::DOCUMENTS_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE,
            CATEGORY_SMARTALBUM_MAP_TABLE });
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

    return ret == E_OK ? true : false;
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
        std::vector<std::string> devices = std::vector<std::string>();
        if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
            MEDIA_ERR_LOG("SyncPushTable Error");
        }
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

    int32_t ret = rdbStore_->Delete(deletedRows, cmd.GetTableName(), cmd.GetAbsRdbPredicates()->GetWhereClause(),
        cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

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

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

    return ret;
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(MediaLibraryCommand &cmd,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
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

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(const AbsRdbPredicates &predicates,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }
    return rdbStore_->Query(predicates, columns);
}

int32_t MediaLibraryRdbStore::ExecuteSql(const std::string &sql)
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

void BuildValuesSql(const NativeRdb::ValuesBucket &values, vector<ValueObject> &bindArgs, string &sql)
{
    map<string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    sql.append("(");
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql.append(((iter == valuesMap.begin()) ? "" : ","));
        sql.append(iter->first);               // columnName
        bindArgs.push_back(iter->second); // columnValue
    }

    sql.append(") select ");
    for (size_t i = 0; i < valuesMap.size(); i++) {
        sql.append(((i == 0) ? "?" : ",?"));
    }
    sql.append(" ");
}

void BuildQuerySql(const AbsRdbPredicates &predicates, const vector<string> &columns,
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
int32_t MediaLibraryRdbStore::InsertWithWhereExists(const string &table, const NativeRdb::ValuesBucket &values,
    const bool exists, const AbsRdbPredicates &predicates)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    // Build insert sql
    string sql;
    vector<ValueObject> bindArgs;
    sql.append("INSERT").append(" OR ROLLBACK ").append(" INTO ").append(table).append(" ");
    BuildValuesSql(values, bindArgs, sql);
    sql.append((exists ? (" WHERE EXISTS (") : (" WHERE NOT EXISTS (")));
    BuildQuerySql(predicates, { }, bindArgs, sql);
    sql.append(");");
    MEDIA_DEBUG_LOG("InsertSql: %{private}s", sql.c_str());

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

    int32_t deletedRows = 0;
    int err = rdbStore_->Delete(deletedRows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute delete, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return deletedRows;
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QuerySql(const std::string &sql)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return nullptr;
    }

    return rdbStore_->QuerySql(sql);
}

std::shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::GetRaw() const
{
    return rdbStore_;
}

std::string MediaLibraryRdbStore::ObtainTableName(MediaLibraryCommand &cmd)
{
    const std::string &networkId = cmd.GetOprnDevice();
    int errCode = E_ERR;
    if (!networkId.empty()) {
        return rdbStore_->ObtainDistributedTableName(networkId, cmd.GetTableName(), errCode);
    }

    return cmd.GetTableName();
}

bool MediaLibraryRdbStore::SyncPullTable(const std::string &bundleName, const std::string &tableName,
    const std::vector<std::string> &devices)
{
    std::vector<std::string> devList(devices);
    return MediaLibrarySyncTable::SyncPullTable(rdbStore_, bundleName, tableName, devList);
}

bool MediaLibraryRdbStore::SyncPushTable(const std::string &bundleName, const std::string &tableName,
    const std::vector<std::string> &devices, bool isBlock)
{
    std::vector<std::string> devList(devices);
    return MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName, tableName, devList, isBlock);
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

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    vector<string> executeSqlStrs = {
        CREATE_MEDIA_TABLE,
        PhotoColumn::CREATE_PHOTO_TABLE,
        AudioColumn::CREATE_AUDIO_TABLE,
        DocumentColumn::CREATE_DOCUMENT_TABLE,
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
        PhotoAlbumColumns::CREATE_TABLE,
        PhotoMap::CREATE_TABLE,
        PhotoAlbumColumns::TRIGGER_UPDATE_ALBUM_URI,
        PhotoAlbumColumns::TRIGGER_CLEAR_MAP,
        PhotoMap::INDEX_PRIMARY_KEY,
    };

    for (const string& sqlStr : executeSqlStrs) {
        if (store.ExecuteSql(sqlStr) != NativeRdb::E_OK) {
            return NativeRdb::E_ERROR;
        }
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

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
#ifdef RDB_UPGRADE_MOCK
    const std::string ALTER_MOCK_COLUMN = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN upgrade_test_column INT DEFAULT 0";
    MEDIA_DEBUG_LOG("OnUpgrade |Rdb Verison %{private}d => %{private}d", oldVersion, newVersion);
    int32_t result = NativeRdb::E_ERROR;
    result = store.ExecuteSql(ALTER_MOCK_COLUMN);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb error %{private}d", result);
    }
#endif
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
} // namespace OHOS::Media
