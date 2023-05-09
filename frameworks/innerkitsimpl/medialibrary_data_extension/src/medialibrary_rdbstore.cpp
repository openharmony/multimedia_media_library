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

#include "media_log.h"
#include "medialibrary_device.h"
#include "medialibrary_errno.h"
#include "medialibrary_sync_table.h"
#include "sqlite_database_utils.h"
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
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
    config_.SetName(name);
    config_.SetPath(realPath);
    config_.SetBundleName(context->GetBundleName());
    config_.SetArea(context->GetArea());
    config_.SetSecurityLevel(SecurityLevel::S3);
    MEDIA_INFO_LOG("rdb config: name: %{private}s realPath: %{private}s bundleName: %{private}s area: %{private}d",
        name.c_str(), realPath.c_str(), context->GetBundleName().c_str(), context->GetArea());
    Init();
}

void MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("Init rdb store");
    if (rdbStore_ != nullptr) {
        return;
    }

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack;
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("GetRdbStore is failed ");
        return;
    }

    if (rdbDataCallBack.HasDistributedTables()) {
        int ret = rdbStore_->SetDistributedTables(
            {MEDIALIBRARY_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE});
        MEDIA_DEBUG_LOG("ret = %{private}d", ret);
    }

    if (!SubscribeRdbStoreObserver()) {
        MEDIA_ERR_LOG("subscribe rdb observer err");
        return;
    }

    MEDIA_INFO_LOG("SUCCESS");
}

MediaLibraryRdbStore::~MediaLibraryRdbStore()
{}

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

    DistributedRdb::SubscribeOption option;
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

    DistributedRdb::SubscribeOption option;
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
    MEDIA_DEBUG_LOG("Insert");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    std::vector<std::string> devices = std::vector<std::string>();
    if (!SyncPushTable(bundleName_, cmd.GetTableName(), devices)) {
        MEDIA_ERR_LOG("SyncPushTable Error");
    }
    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::Delete(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_DEBUG_LOG("Delete");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Delete(rowId, cmd.GetTableName(), cmd.GetAbsRdbPredicates()->GetWhereClause(),
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

int32_t MediaLibraryRdbStore::Update(MediaLibraryCommand &cmd, int32_t &rowId)
{
    MEDIA_DEBUG_LOG("Update");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Update(rowId, cmd.GetTableName(), cmd.GetValueBucket(),
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

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaLibraryRdbStore::Query(MediaLibraryCommand &cmd,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }

    auto predicates = cmd.GetAbsRdbPredicates();
    return rdbStore_->Query(*predicates, columns);
}

int32_t MediaLibraryRdbStore::ExecuteSql(const std::string &sql)
{
    MEDIA_DEBUG_LOG("ExecuteSql");

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

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaLibraryRdbStore::QuerySql(const std::string &sql)
{
    MEDIA_DEBUG_LOG("ExecuteSql");

    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return nullptr;
    }

    auto ret = rdbStore_->QuerySql(sql);
    if (ret != nullptr) {
        int count;
        ret->GetRowCount(count);
        MEDIA_DEBUG_LOG("GetRowCount() = %{public}d", count);
    }
    return ret;
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

bool MediaLibraryRdbStore::SyncPullAllTableByDeviceId(const std::string &bundleName, std::vector<std::string> &devices)
{
    return MediaLibrarySyncTable::SyncPullAllTableByDeviceId(rdbStore_, bundleName, devices);
}

bool MediaLibraryRdbStore::SyncPullTable(const std::string &bundleName, const std::string &tableName,
                                         const std::vector<std::string> &devices, bool isLast)
{
    std::vector<std::string> devList(devices);
    return MediaLibrarySyncTable::SyncPullTable(rdbStore_, bundleName, tableName, devList, isLast);
}

bool MediaLibraryRdbStore::SyncPushTable(const std::string &bundleName, const std::string &tableName,
                                         const std::vector<std::string> &devices, bool isLast)
{
    std::vector<std::string> devList(devices);
    return MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName, tableName, devList, isLast);
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

    for (auto dirValuesBucket : dirValuesBuckets) {
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
    valuesBucket.PutInt(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, dirValuesBucket.directoryType);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, dirValuesBucket.dirValues);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, dirValuesBucket.typeValues);
    valuesBucket.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, dirValuesBucket.extensionValues);
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

    for (auto smartAlbum : smartAlbumValuesBuckets) {
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

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    vector<string> executeSqlStrs = {
        CREATE_MEDIA_TABLE,
        CREATE_SMARTALBUM_TABLE,
        CREATE_SMARTALBUMMAP_TABLE,
        CREATE_DEVICE_TABLE,
        CREATE_CATEGORY_SMARTALBUMMAP_TABLE,
        CREATE_IMAGE_VIEW,
        CREATE_VIDEO_VIEW,
        CREATE_AUDIO_VIEW,
        CREATE_ABLUM_VIEW,
        CREATE_SMARTABLUMASSETS_VIEW,
        CREATE_ASSETMAP_VIEW,
        CREATE_MEDIATYPE_DIRECTORY_TABLE,
        CREATE_BUNDLE_PREMISSION_TABLE,
    };

    for (string sqlStr : executeSqlStrs) {
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
} // namespace Media
} // namespace OHOS
