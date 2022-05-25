/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DATA_ABILITY_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DATA_ABILITY_H_

#include <string>

#include "ability.h"
#include "ability_loader.h"
#include "abs_rdb_predicates.h"
#include "data_ability_predicates.h"
#include "device_manager.h"
#include "distributed_kv_data_manager.h"
#include "device_manager_callback.h"
#include "hilog/log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_ability_utils.h"
#include "medialibrary_device.h"
#include "medialibrary_thumbnail.h"
#include "medialibrary_device_info.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "medialibrary_query_operations.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "result_set.h"
#include "timer.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"

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
        TYPE_ASSETSMAP_TABLE
    };
    class MediaLibraryRdbStoreObserver;
    class MediaLibraryDataAbility : public AppExecFwk::Ability {
    public:
        EXPORT MediaLibraryDataAbility();
        EXPORT ~MediaLibraryDataAbility();

        EXPORT int32_t InitMediaLibraryRdbStore();
        EXPORT void InitialiseKvStore();
        EXPORT int32_t Insert(const Uri &uri, const NativeRdb::ValuesBucket &value) override;
        EXPORT int32_t Delete(const Uri &uri, const NativeRdb::DataAbilityPredicates &predicates) override;
        EXPORT int32_t BatchInsert(const Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values) override;
        EXPORT int32_t Update(const Uri &uri, const NativeRdb::ValuesBucket &value,
                       const NativeRdb::DataAbilityPredicates &predicates) override;
        EXPORT std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(const Uri &uri,
            const std::vector<std::string> &columns,
            const NativeRdb::DataAbilityPredicates &predicates) override;
        EXPORT int32_t OpenFile(const Uri &uri, const std::string &mode) override;
        EXPORT std::string GetType(const Uri &uri) override;
    protected:
        void OnStart(const AAFwk::Want &want) override;
        void OnStop() override;

    private:
        std::string GetOperationType(const std::string &uri);
        void ScanFile(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore1);
        void InitDeviceData();
        bool SubscribeRdbStoreObserver();
        bool UnSubscribeRdbStoreObserver();
        bool QuerySync(const std::string &deviceId, const std::string &tableName);
        bool QuerySync();

        bool CheckFileNameValid(const ValuesBucket &value);
        sptr<AppExecFwk::IBundleMgr> GetSysBundleManager();
        std::string GetClientBundleName();
        bool CheckClientPermission(const std::string& permissionStr);
        std::string GetClientBundle(int uid);

        int32_t PreCheckInsert(const std::string &uri, const NativeRdb::ValuesBucket &value);
        bool ParseThumbnailInfo(std::string &uriString, Size &size);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> GenThumbnail(std::shared_ptr<MediaLibraryThumbnail> thumbnail,
            std::string &rowId, Size &size, std::string &networkId);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryBySmartTableType(TableType tabletype,
            std::string strQueryCondition, NativeRdb::DataAbilityPredicates predicates,
            std::vector<std::string> columns);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryByViewType(TableType tabletype,
            std::string strQueryCondition, NativeRdb::DataAbilityPredicates predicates,
            std::vector<string> columns);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryDeviceInfo(std::string strQueryCondition,
            NativeRdb::DataAbilityPredicates predicates, std::vector<string> columns);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryAlbum(std::string strQueryCondition,
            NativeRdb::DataAbilityPredicates predicates, std::vector<std::string> columns, std::string networkId);
        std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFile(std::string strQueryCondition,
            NativeRdb::DataAbilityPredicates predicates, std::vector<std::string> columns, std::string networkId);
        std::string ObtionCondition(std::string &strQueryCondition, const std::vector<std::string> &whereArgs);
        void SplitKeyValue(const std::string& keyValue, std::string &key, std::string &value);
        void SplitKeys(const std::string& query, std::vector<std::string>& keys);
        void DealWithUriString(std::string &uriString, TableType &tabletype,
            std::string &strQueryCondition, std::string::size_type &pos, std::string &strRow);

        static const std::string PERMISSION_NAME_READ_MEDIA;
        static const std::string PERMISSION_NAME_WRITE_MEDIA;
        std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
        DistributedKv::DistributedKvDataManager dataManager_;
        std::shared_ptr<IMediaScannerClient> scannerClient_;
        std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
        std::shared_ptr<MediaLibraryThumbnail> mediaThumbnail_;
        std::shared_ptr<MediaLibraryRdbStoreObserver> rdbStoreObs_;
        bool isRdbStoreInitialized;
        std::string bundleName_;
        OHOS::sptr<AppExecFwk::IBundleMgr> bundleMgr_;
};

class MediaLibraryDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
    bool GetDistributedTables();
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

#endif  // FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DATA_ABILITY_H_
