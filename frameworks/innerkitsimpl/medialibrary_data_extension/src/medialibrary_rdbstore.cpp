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

#include "medialibrary_rdbstore.h"

#include "media_log.h"
#include "medialibrary_sync_table.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

MediaLibraryRdbStore::MediaLibraryRdbStore(const shared_ptr<OHOS::AbilityRuntime::Context> &context)
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

void MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Init");

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

MediaLibraryRdbStore::~MediaLibraryRdbStore()
{
    Stop();
}

void MediaLibraryRdbStore::Stop()
{
    if (rdbStore_ == nullptr) {
        return;
    }

    UnSubscribeRdbStoreObserver();
}

bool MediaLibraryRdbStore::SubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryRdbStore SubscribeRdbStoreObserver rdbStore is null");
        return false;
    }
    rdbStoreObs_ = make_shared<MediaLibraryRdbStoreObserver>(bundleName_);
    if (rdbStoreObs_ == nullptr) {
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->Subscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryRdbStore Subscribe ret = %d", ret);

    return ret;
}

bool MediaLibraryRdbStore::UnSubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryRdbStore UnSubscribeRdbStoreObserver rdbStore is null");
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->UnSubscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryRdbStore UnSubscribe ret = %d", ret);
    if (ret) {
        rdbStoreObs_ = nullptr;
    }

    return ret;
}

int32_t MediaLibraryRdbStore::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Insert");

    if (rdbStore_ == nullptr) {
        return DATA_ABILITY_FAIL;
    }

    int32_t ret = rdbStore_->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    if (ret != NativeRdb::E_OK) {
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

int32_t MediaLibraryRdbStore::Delete(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Delete");

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
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

    return ret;
}

int32_t MediaLibraryRdbStore::Update(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Update");
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

    // for distributed rdb
    // tablename = ObtainTableName(cmd);
    int32_t ret = rdbStore_->Update(rowId, cmd.GetTableName(), cmd.GetValueBucket(),
                                    cmd.GetAbsRdbPredicates()->GetWhereClause(),
                                    cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Update failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }

    return ret;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaLibraryRdbStore::Query(MediaLibraryCommand &cmd,
                                                                           const vector<string> &columns)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Query");

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

int32_t MediaLibraryRdbStore::ExecuteSql(const std::string &sql)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStore::ExecuteSql");

    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return DATA_ABILITY_FAIL;
    }

    int32_t ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        return DATA_ABILITY_FAIL;
    }

    return ret;
}

std::string MediaLibraryRdbStore::ObtainTableName(MediaLibraryCommand &cmd)
{
    const std::string &deviceId = cmd.GetOprnDevice();
    if (!deviceId.empty()) {
        return rdbStore_->ObtainDistributedTableName(deviceId, cmd.GetTableName());
    }

    return cmd.GetTableName();
}

bool MediaLibraryRdbStore::SyncPullAllTable(const std::string &bundleName)
{
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullAllTable(rdbStore_, bundleName);
}

bool MediaLibraryRdbStore::SyncPullAllTableByDeviceId(const std::string &bundleName,
                                                                std::vector<std::string> &devices)
{
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullAllTableByDeviceId(rdbStore_, bundleName, devices);
}

bool MediaLibraryRdbStore::SyncPullTable(const std::string &bundleName, const std::string &tableName,
                                                   std::vector<std::string> &devices, bool isLast)
{
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullTable(rdbStore_, bundleName, tableName, devices, isLast);
}

bool MediaLibraryRdbStore::SyncPushTable(const std::string &bundleName, const std::string &tableName,
                                                   std::vector<std::string> &devices, bool isLast)
{
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPushTable(rdbStore_, bundleName, tableName, devices, isLast);
}

int32_t MediaLibraryDataCallBack::PrepareCameraDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, CAMERA_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, CAMERA_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, CAMERA_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, CAMERA_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PrepareCameraDir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareVideoDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, VIDEO_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, VIDEO_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, VIDEO_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, VIDEO_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PrepareVideoDir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PreparePictureDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, PIC_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, PIC_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, PIC_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, PIC_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PreparePictureDir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareAudioDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, AUDIO_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, AUDIO_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, AUDIO_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, AUDIO_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PrepareAudioDir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareDocumentDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, DOC_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, DOC_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, DOC_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, DOC_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PrepareDocumentDir outRowId: %{public}ld, insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareDownloadDir(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, DOWNLOAD_DIRECTORY_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, DOWNLOAD_DIR_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, DOWNLOAD_TYPE_VALUES);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, DOWNLOAD_EXTENSION_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("PrepareDownloadDir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareDir(RdbStore &store)
{
    if (PrepareCameraDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareCameraDir failed");
        return NativeRdb::E_ERROR;
    }
    if (PrepareVideoDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareVideoDir failed");
        return NativeRdb::E_ERROR;
    }
    if (PreparePictureDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PreparePictureDir failed");
        return NativeRdb::E_ERROR;
    }
    if (PrepareAudioDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareAudioDir failed");
        return NativeRdb::E_ERROR;
    }
    if (PrepareDocumentDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareDocumentDir failed");
        return NativeRdb::E_ERROR;
    }
    if (PrepareDownloadDir(store) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareDownloadDir failed");
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::PrepareTrash(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(SMARTALBUM_DB_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.PutString(SMARTALBUM_DB_NAME, TRASH_ALBUM_NAME_VALUES);
    valuesBucket.PutInt(SMARTALBUM_DB_ALBUM_TYPE, TRASH_ALBUM_TYPE_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, SMARTALBUM_TABLE, valuesBucket);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareFavourite(RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(SMARTALBUM_DB_ID, FAVOURITE_ALBUM_ID_VALUES);
    valuesBucket.PutString(SMARTALBUM_DB_NAME, FAVOURTIE_ALBUM_NAME_VALUES);
    valuesBucket.PutInt(SMARTALBUM_DB_ALBUM_TYPE, FAVOURITE_ALBUM_TYPE_VALUES);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, SMARTALBUM_TABLE, valuesBucket);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareSmartAlbum(RdbStore &store)
{
    int32_t err = NativeRdb::E_ERROR;
    err = PrepareTrash(store);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareTrash failed, err: %{public}d", err);
        return NativeRdb::E_ERROR;
    }
    err = PrepareFavourite(store);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("PrepareFavourite failed, err: %{public}d", err);
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
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
        error_code= store.ExecuteSql(CREATE_ABLUM_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code= store.ExecuteSql(CREATE_SMARTABLUMASSETS_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code= store.ExecuteSql(CREATE_ASSETMAP_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_MEDIATYPE_DIRECTORY_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = PrepareDir(store);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = PrepareSmartAlbum(store);
    }
    if (error_code == NativeRdb::E_OK) {
        isDistributedTables = true;
    }
    return error_code;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
#ifdef RDB_UPGRADE_MOCK
    const std::string ALTER_MOCK_COLUMN = "ALTER TABLE " + MEDIALIBRARY_TABLE +
                                          " ADD COLUMN upgrade_test_column INT DEFAULT 0";
    MEDIA_INFO_LOG("OnUpgrade |Rdb Verison %{private}d => %{private}d", oldVersion, newVersion);
    int32_t error_code = NativeRdb::E_ERROR;
    error_code = store.ExecuteSql(ALTER_MOCK_COLUMN);
    if (error_code != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Upgrade rdb error %{private}d", error_code);
    }
#endif
    return NativeRdb::E_OK;
}

bool MediaLibraryDataCallBack::GetDistributedTables()
{
    return isDistributedTables;
}


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
