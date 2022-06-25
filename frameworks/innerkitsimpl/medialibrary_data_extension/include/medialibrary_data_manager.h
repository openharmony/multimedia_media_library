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

#ifndef OHOS_MEDIALIBRARY_DATA_MANAGER_H
#define OHOS_MEDIALIBRARY_DATA_MANAGER_H

#include <string>
#include <unordered_map>

#include "ability.h"
#include "abs_rdb_predicates.h"
#include "data_ability_predicates.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "dir_asset.h"
#include "distributed_kv_data_manager.h"
#include "foundation/ability/ability_runtime/frameworks/kits/appkit/native/ability_runtime/context/context.h"
#include "hilog/log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "result_set.h"
#include "result_set_bridge.h"
#include "timer.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"

#include "media_data_ability_const.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_thumbnail.h"

namespace OHOS {
namespace Media {
    class MediaLibraryDataManager {
    public:
        EXPORT MediaLibraryDataManager();
        EXPORT ~MediaLibraryDataManager();
        static std::shared_ptr<MediaLibraryDataManager> GetInstance();

        EXPORT int32_t InitMediaLibraryRdbStore();
        EXPORT void InitialiseKvStore();

// Medialibrary接口使用必读

// 1、insert和update接口有ValueBucket，delete接口没有
// 2、insert不要再做成大杂烩总入口，napi的调用处，如果是delete就用delete的接口，update就用update的接口；
// 3、对于fileId或者albumId，如果有ValueBucket则可以将id放在ValueBucket的MEDIA_DATA_DB_ID项里，
//   或者放在ValueBucket里面的MEDIA_DATA_DB_URI项的最后一个/的后面；如果没有ValueBucket（比如对于delete）
//   则只能将id放在入参uri的最后一个/后面
// 4、尽量不要直接使用rdbStore，虽然可以通过uniStore_->GetRdbStoreRaw获取到，但是请尽可能使用下层的uniStore_来操作数据库

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
        void InitDeviceData();
        bool QuerySync(const std::string &deviceId, const std::string &tableName);
        bool QuerySync();

        bool CheckFileNameValid(const DataShareValuesBucket &value);
        sptr<AppExecFwk::IBundleMgr> GetSysBundleManager();
        std::string GetClientBundleName();
        std::string GetClientBundle(int uid);
        void NeedQuerySync(const std::string &networkId, OperationObject oprnObject);
        void MakeDirQuerySetMap(std::unordered_map<std::string, DirAsset> &outDirQuerySetMap);

        std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
        DistributedKv::DistributedKvDataManager dataManager_;
        std::shared_ptr<MediaLibraryThumbnail> mediaThumbnail_;
        MediaLibrarySyncTable syncTable_;
        bool isRdbStoreInitialized;
        std::shared_ptr<OHOS::AbilityRuntime::Context> context_ = nullptr;
        std::string bundleName_;
        OHOS::sptr<AppExecFwk::IBundleMgr> bundleMgr_;
        static std::mutex mutex_;
        static std::shared_ptr<MediaLibraryDataManager> instance_;
        std::unordered_map<std::string, DirAsset> dirQuerySetMap_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DATA_ABILITY_H