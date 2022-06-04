/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_DATA_MANAGER_H
#define OHOS_MEDIALIBRARY_DATA_MANAGER_H

#include <string>
#include <unordered_map>

#include "ability.h"
#include "ability_loader.h"
#include "abs_rdb_predicates.h"
#include "data_ability_predicates.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "dir_asset.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "foundation/aafwk/standard/frameworks/kits/appkit/native/ability_runtime/context/context.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "result_set.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"
#include "hilog/log.h"
#include "medialibrary_thumbnail.h"
#include "distributed_kv_data_manager.h"
#include "timer.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "result_set_bridge.h"

namespace OHOS {
namespace Media {
// kvstore constants
    const DistributedKv::AppId KVSTORE_APPID { "com.ohos.medialibrary.MediaLibraryDataA" };
    const DistributedKv::StoreId KVSTORE_STOREID { "ringtone" };
    enum TableType {
        TYPE_DATA,
        TYPE_SMARTALBUM,
        TYPE_SMARTALBUM_MAP,
        TYPE_ALBUM_TABLE,
        TYPE_SMARTALBUMASSETS_TABLE,
        TYPE_ACTIVE_DEVICE,
        TYPE_ALL_DEVICE,
        TYPE_ASSETSMAP_TABLE,
        TYPE_DIR_TABLE
    };
    class MediaLibraryInitCallback;
    class MediaLibraryDeviceStateCallback;
    class MediaLibraryRdbStoreObserver;
    class MediaLibraryDataManager {
    public:
        EXPORT MediaLibraryDataManager();
        EXPORT ~MediaLibraryDataManager();
        static std::shared_ptr<MediaLibraryDataManager> GetInstance();

        EXPORT int32_t InitMediaLibraryRdbStore();
        EXPORT void InitialiseKvStore();
        EXPORT int32_t Insert(const Uri &uri, const DataShare::DataShareValuesBucket &value);
        EXPORT int32_t Delete(const Uri &uri, const DataShare::DataSharePredicates &predicates);
        EXPORT int32_t BatchInsert(const Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values);
        EXPORT int32_t Update(const Uri &uri, const DataShare::DataShareValuesBucket &value,
                       const DataShare::DataSharePredicates &predicates);
        EXPORT std::shared_ptr<DataShare::ResultSetBridge> Query(const Uri &uri,
            const std::vector<std::string> &columns,
            const DataShare::DataSharePredicates &predicates);
        EXPORT std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryRdb(const Uri &uri,
            const std::vector<std::string> &columns,
            const DataShare::DataSharePredicates &predicates);
        EXPORT int32_t OpenFile(const Uri &uri, const std::string &mode);
        EXPORT std::string GetType(const Uri &uri);

        std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

        void InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
        void ClearMediaLibraryMgr();

    private:
        static constexpr const char DEVICE_BUNDLENAME[] = "com.ohos.medialibrary.MediaLibraryDataA";
        std::string GetOperationType(const std::string &uri);
        void ScanFile(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore1);
        void InitDeviceData();
        bool SubscribeRdbStoreObserver();
        bool UnSubscribeRdbStoreObserver();
        bool QuerySync(const std::string &deviceId, const std::string &tableName);
        bool QuerySync();
		
        bool CheckFileNameValid(const DataShareValuesBucket &value);
        sptr<AppExecFwk::IBundleMgr> GetSysBundleManager();
        std::string GetClientBundleName();
        bool CheckClientPermission(const std::string& permissionStr);
        std::string GetClientBundle(int uid);
        void NeedQuerySync(const std::string &networkId, TableType tabletype);
        int32_t PreCheckInsert(const std::string &uri, const DataShare::DataShareValuesBucket &value);
        void MakeDirQuerySetMap(std::unordered_map<std::string, DirAsset> &outDirQuerySetMap);

        static const std::string PERMISSION_NAME_READ_MEDIA;
        static const std::string PERMISSION_NAME_WRITE_MEDIA;
        std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
        DistributedKv::DistributedKvDataManager dataManager_;
        std::shared_ptr<MediaLibraryThumbnail> mediaThumbnail_;
        std::shared_ptr<MediaLibraryDeviceStateCallback> deviceStateCallback_;
        std::shared_ptr<MediaLibraryInitCallback> deviceInitCallback_;
        std::shared_ptr<MediaLibraryRdbStoreObserver> rdbStoreObs_;
        bool isRdbStoreInitialized;
        std::shared_ptr<OHOS::AbilityRuntime::Context> context_ = nullptr;
        std::string bundleName_;
        OHOS::sptr<AppExecFwk::IBundleMgr> bundleMgr_;
        static std::mutex mutex_;
        static std::shared_ptr<MediaLibraryDataManager> instance_;
        std::unordered_map<std::string, DirAsset> dirQuerySetMap_;
};

class MediaLibraryDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
    bool GetDistributedTables();
    int32_t PrepareDir(NativeRdb::RdbStore &store);
    int32_t PrepareCameraDir(NativeRdb::RdbStore &store);
    int32_t PrepareVideoDir(NativeRdb::RdbStore &store);
    int32_t PreparePictureDir(NativeRdb::RdbStore &store);
    int32_t PrepareAudioDir(NativeRdb::RdbStore &store);
    int32_t PrepareDocumentDir(NativeRdb::RdbStore &store);
    int32_t PrepareDownloadDir(NativeRdb::RdbStore &store);
    int32_t PrepareSmartAlbum(NativeRdb::RdbStore &store);
    int32_t PrepareFavourite(NativeRdb::RdbStore &store);
    int32_t PrepareTrash(NativeRdb::RdbStore &store);
private:
    bool isDistributedTables = false;
};

// Scanner callback objects
class ScanFileCallback : public IMediaScannerAppCallback {
public:
    ScanFileCallback() = default;
    ~ScanFileCallback() = default;
    void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
};

class MediaLibraryInitCallback : public OHOS::DistributedHardware::DmInitCallback {
public:
    virtual ~MediaLibraryInitCallback() {}
    void OnRemoteDied() override;
};

class MediaLibraryDeviceStateCallback : public OHOS::DistributedHardware::DeviceStateCallback {
public:
    explicit MediaLibraryDeviceStateCallback(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, std::string &bundleName)
        : bundleName_(bundleName), rdbStore_(rdbStore) {}
    virtual ~MediaLibraryDeviceStateCallback() {};
    void OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
private:
    std::string bundleName_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
};

class MediaLibraryRdbStoreObserver : public NativeRdb::RdbStore::RdbStoreObserver {
public:
    explicit MediaLibraryRdbStoreObserver(std::string &bundleName);
    virtual ~MediaLibraryRdbStoreObserver();
    void OnChange(const std::vector<std::string>& devices) override;
private:
    void NotifyDeviceChange();
private:
    static constexpr int NOTIFY_TIME_INTERVAL = 10000;
    std::unique_ptr<OHOS::Utils::Timer> timer_ {nullptr};
    uint32_t timerId_ {0};
    std::string bundleName_;
    bool isNotifyDeviceChange_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DATA_ABILITY_H