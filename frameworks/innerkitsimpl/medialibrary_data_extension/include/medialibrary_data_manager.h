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
#include <shared_mutex>

#include "ability_context.h"
#include "context/context.h"
#include "dir_asset.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "distributed_kv_data_manager.h"
#include "imedia_scanner_callback.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "rdb_store.h"
#include "result_set_bridge.h"
#include "uri.h"
#include "values_bucket.h"
#include "thumbnail_service.h"

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS {
namespace AbilityRuntime {
class MediaDataShareExtAbility;
}
namespace Media {
using OHOS::AbilityRuntime::MediaDataShareExtAbility;
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
    EXPORT std::shared_ptr<DataShare::ResultSetBridge> Query(const Uri &uri, const std::vector<std::string> &columns,
        const DataShare::DataSharePredicates &predicates);
    EXPORT std::shared_ptr<NativeRdb::AbsSharedResultSet>
    QueryRdb(const Uri &uri, const std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    EXPORT int32_t OpenFile(const Uri &uri, const std::string &mode);
    EXPORT std::string GetType(const Uri &uri);
    EXPORT void NotifyChange(const Uri &uri);
    EXPORT int32_t GenerateThumbnails();
    EXPORT void InterruptBgworker();
    EXPORT int32_t DoAging();

    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

    void InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
        const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext);
    void ClearMediaLibraryMgr();
    void MakeDirQuerySetMap(std::unordered_map<std::string, DirAsset> &outDirQuerySetMap);
    void CreateThumbnailAsync(const std::string &uri);
    std::unordered_map<std::string, DirAsset> GetDirQuerySetMap() const;
    std::shared_ptr<MediaDataShareExtAbility> GetOwner();
    void SetOwner(const std::shared_ptr<MediaDataShareExtAbility> &datashareExtension);

private:
    bool QuerySync(const std::string &networkId, const std::string &tableName);
    int32_t HandleThumbnailOperations(MediaLibraryCommand &cmd);
    bool CheckFileNameValid(const DataShare::DataShareValuesBucket &value);
    void NeedQuerySync(const std::string &networkId, OperationObject oprnObject);
    void ScanFile(const NativeRdb::ValuesBucket &values, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore1);
    void InitDeviceData();
    void InitialiseThumbnailService(const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext);
    std::shared_ptr<DataShare::ResultSetBridge> GenThumbnail(const std::string &uri);
    int32_t CreateThumbnail(const NativeRdb::ValuesBucket &values);
    int32_t LcdDistributeAging();
    int32_t DistributeDeviceAging();
    std::shared_ptr<ThumbnailService> thumbnailService_;

    std::shared_mutex mgrSharedMutex_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<OHOS::AbilityRuntime::Context> context_;
    std::string bundleName_{BUNDLE_NAME};
    OHOS::sptr<AppExecFwk::IBundleMgr> bundleMgr_;
    static std::mutex mutex_;
    static std::shared_ptr<MediaLibraryDataManager> instance_;
    std::unordered_map<std::string, DirAsset> dirQuerySetMap_;
    std::atomic<int> refCnt_{0};
    std::shared_ptr<MediaDataShareExtAbility> extension_;
};

// Scanner callback objects
class ScanFileCallback : public IMediaScannerCallback {
public:
    ScanFileCallback() = default;
    ~ScanFileCallback() = default;
    int32_t OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DATA_ABILITY_H
