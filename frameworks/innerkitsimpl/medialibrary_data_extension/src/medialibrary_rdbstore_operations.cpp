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

#include "medialibrary_rdbstore_operations.h"

#include "media_log.h"
#include "medialibrary_sync_table.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

MediaLibraryRdbStoreOperations::MediaLibraryRdbStoreOperations(const shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    string databaseDir = context->GetDatabaseDir();
    string relativePath = MEDIA_DATA_ABILITY_DB_NAME;

    config_ = RdbStoreConfig(databaseDir + "/" + relativePath);
    config_.SetBundleName(context->GetBundleName());
    config_.SetName(MEDIA_DATA_ABILITY_DB_NAME);
    config_.SetRelativePath(relativePath);
    config_.SetEncryptLevel(ENCRYPTION_LEVEL);
    config_.SetAppModuleName(context->GetHapModuleInfo()->moduleName);
    Init();
}

void MediaLibraryRdbStoreOperations::Init()
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::Init");

    if (rdbStore_ != nullptr) {
        return;
    }

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack{};
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("InitMediaRdbStore GetRdbStore is failed ");
        return;
    }

    if (rdbDataCallBack.GetDistributedTables()) {
        auto ret = rdbStore_->SetDistributedTables(
            {MEDIALIBRARY_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE});
        MEDIA_INFO_LOG("InitMediaLibraryRdbStore ret = %{private}d", ret);
    }

    if (!SubscribeRdbStoreObserver()) {
        MEDIA_ERR_LOG("subscribe rdb observer err");
        return;
    }

    MEDIA_INFO_LOG("InitMediaLibraryRdbStore SUCCESS");
}

MediaLibraryRdbStoreOperations::~MediaLibraryRdbStoreOperations()
{
    Stop();
}

void MediaLibraryRdbStoreOperations::Stop()
{
    if (rdbStore_ == nullptr) {
        return;
    }

    SubscribeRdbStoreObserver();
}

bool MediaLibraryRdbStoreOperations::SubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryRdbStoreOperations SubscribeRdbStoreObserver rdbStore is null");
        return false;
    }
    rdbStoreObs_ = make_shared<MediaLibraryRdbStoreObserver>(bundleName_);
    if (rdbStoreObs_ == nullptr) {
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->Subscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations Subscribe ret = %d", ret);

    return ret;
}

bool MediaLibraryRdbStoreOperations::UnSubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryRdbStoreOperations UnSubscribeRdbStoreObserver rdbStore is null");
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->UnSubscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations UnSubscribe ret = %d", ret);
    if (ret) {
        rdbStoreObs_ = nullptr;
    }

    return ret;
}

int32_t MediaLibraryRdbStoreOperations::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::Insert");

    if (rdbStore_ == nullptr) {
        return DATA_ABILITY_FAIL;
    }

    int32_t ret = rdbStore_->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }
    MEDIA_ERR_LOG("[lqh]rdbStore_->Insert end, rowId = %lld, ret = %{public}d", rowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStoreOperations::Delete(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::Delete");

    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return DATA_ABILITY_FAIL;
    }

    if (cmd.GetAbsRdbPredicates() == nullptr) {
        MEDIA_ERR_LOG("AbsRdbPredicates in input param(cmd) is nullptr.");
        return DATA_ABILITY_FAIL;
    }

    // "Delete" function the code before refactoring uses
    // a more simple "Detele" function in rdb_store.h
    // return rdbStore_->Delete(rowId, *(cmd.GetAbsRdbPredicates()))
    int32_t ret = rdbStore_->Delete(rowId, cmd.GetTableName(), cmd.GetAbsRdbPredicates()->GetWhereClause(),
                                    cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

    return ret;
}

int32_t MediaLibraryRdbStoreOperations::Update(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::Update");
    if (rdbStore_ == nullptr) {
        return DATA_ABILITY_FAIL;
    }

    if (cmd.GetAbsRdbPredicates() == nullptr) {
        MEDIA_ERR_LOG("AbsRdbPredicates in input param(cmd) is nullptr.");
        return DATA_ABILITY_FAIL;
    }

    // "Update" function the code before refactoring uses
    // a more simple "Detele" function in rdb_store.h
    // return rdbStore_->Update(rowId, cmd.GetValueBucket(), *(cmd.GetAbsRdbPredicates()))
    int32_t ret = rdbStore_->Update(rowId, cmd.GetTableName(), cmd.GetValueBucket(),
                                    cmd.GetAbsRdbPredicates()->GetWhereClause(),
                                    cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Update failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

    return ret;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaLibraryRdbStoreOperations::Query(MediaLibraryCommand &cmd,
                                                                                     const vector<string> &columns)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::Query");

    if (rdbStore_ == nullptr) {
        return nullptr;
    }

    if (cmd.GetAbsRdbPredicates() == nullptr) {
        MEDIA_ERR_LOG("AbsRdbPredicates in input param(cmd) is nullptr.");
        return nullptr;
    }

    auto predicates = cmd.GetAbsRdbPredicates();

    MEDIA_INFO_LOG("======================================");
    MEDIA_INFO_LOG("[lqh] tablename = %s", cmd.GetTableName().c_str());
    MEDIA_INFO_LOG("[lqh] ObtainTableName = %s", ObtainTableName(cmd).c_str());
    for (auto &col : columns) {
        MEDIA_INFO_LOG("[lqh] col = %s", col.c_str());
    }
    MEDIA_INFO_LOG("[lqh] whereClause = %s", predicates->GetWhereClause().c_str());
    for (auto &arg : predicates->GetWhereArgs()) {
        MEDIA_INFO_LOG("[lqh] whereArgs = %s", arg.c_str());
    }
    MEDIA_INFO_LOG("[lqh] groupBy = %s", predicates->GetGroup().c_str());
    MEDIA_INFO_LOG("[lqh] orderBy = %s", predicates->GetOrder().c_str());
    MEDIA_INFO_LOG("[lqh] limit = %d", predicates->GetLimit());
    MEDIA_INFO_LOG("======================================");

    // auto ret = rdbStore_->Query(errCode, predicates->IsDistinct(), ObtainTableName(cmd), columns,
    //     predicates->GetWhereClause(), predicates->GetWhereArgs(), predicates->GetGroup(), "", predicates->GetOrder(),
    //     std::to_string(predicates->GetLimit()));
    // MEDIA_INFO_LOG("errCode = %{public}d", errCode);
    auto ret = rdbStore_->Query(*predicates, columns);
    if (ret != nullptr) {
        int count;
        ret->GetRowCount(count);
        MEDIA_INFO_LOG("GetRowCount() = %{public}d", count);
    }
    return ret;
}

int32_t MediaLibraryRdbStoreOperations::ExecuteSql(const std::string &sql)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreOperations::ExecuteSql");

    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return DATA_ABILITY_FAIL;
    }

    int32_t ret = rdbStore_->ExecuteSql(sql);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    return ret;
}

std::string MediaLibraryRdbStoreOperations::ObtainTableName(MediaLibraryCommand &cmd)
{
    const std::string &deviceId = cmd.GetOprnDevice();
    if (!deviceId.empty()) {
        return rdbStore_->ObtainDistributedTableName(deviceId, cmd.GetTableName());
    }

    return cmd.GetTableName();
}

bool MediaLibraryRdbStoreOperations::SyncPullAllTable(const std::string &bundleName)
{
    return MediaLibrarySyncTable::SyncPullAllTable(rdbStore_, bundleName);
}

bool MediaLibraryRdbStoreOperations::SyncPullAllTableByDeviceId(const std::string &bundleName,
                                                                std::vector<std::string> &devices)
{
    return MediaLibrarySyncTable::SyncPullAllTableByDeviceId(rdbStore_, bundleName, devices);
}

bool MediaLibraryRdbStoreOperations::SyncPullTable(const std::string &bundleName, const std::string &tableName,
                                                   std::vector<std::string> &devices, bool isLast)
{
    return MediaLibrarySyncTable::SyncPullTable(rdbStore_, bundleName, tableName, devices, isLast);
}

bool MediaLibraryRdbStoreOperations::SyncPushTable(const std::string &bundleName, const std::string &tableName,
                                                   std::vector<std::string> &devices, bool isLast)
{
    return MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName, tableName, devices, isLast);
}

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    int32_t error_code = NativeRdb::E_ERROR;
    error_code = store.ExecuteSql(CREATE_MEDIA_TABLE);
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_SMARTALBUM_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_SMARTALBUMMAP_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_DEVICE_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_CATEGORY_SMARTALBUMMAP_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_IMAGE_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_VIDEO_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_AUDIO_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_ABLUM_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_SMARTABLUMASSETS_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_ASSETMAP_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        isDistributedTables = true;
    }
    return error_code;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
#ifdef RDB_UPGRADE_MOCK
    const std::string ALTER_MOCK_COLUMN =
        "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN upgrade_test_column INT DEFAULT 0";
    MEDIA_INFO_LOG("OnUpgrade |Rdb Version %{private}d => %{private}d", oldVersion, newVersion);
    int32_t error_code = NativeRdb::E_ERROR;
    error_code = store.ExecuteSql(ALTER_MOCK_COLUMN);
    if (error_code != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Upgrade rdb error %{private}d", error_code);
    }
#endif
    return E_OK;
}

bool MediaLibraryDataCallBack::GetDistributedTables() { return isDistributedTables; }

MediaLibraryRdbStoreObserver::MediaLibraryRdbStoreObserver(string &bundleName)
{
    bundleName_ = bundleName;
    isNotifyDeviceChange_ = false;

    if (timer_ == nullptr) {
        timer_ = make_unique<OHOS::Utils::Timer>(bundleName_);
        timerId_ =
            timer_->Register(bind(&MediaLibraryRdbStoreObserver::NotifyDeviceChange, this), NOTIFY_TIME_INTERVAL);
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
    // MediaLibraryDevice::GetInstance()->NotifyRemoteFileChange();
    // for (auto &deviceId : devices) {
    //     // MediaLibraryDevice::GetInstance()->UpdateDevicieSyncStatus(deviceId, DEVICE_SYNCSTATUS_COMPLETE,
    //     bundleName_); isNotifyDeviceChange_ = true;
    // }
}

void MediaLibraryRdbStoreObserver::NotifyDeviceChange()
{
    if (isNotifyDeviceChange_) {
        // MediaLibraryDevice::GetInstance()->NotifyDeviceChange();
        isNotifyDeviceChange_ = false;
    }
}

} // namespace Media
} // namespace OHOS
