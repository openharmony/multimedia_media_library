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

#include "ability_context.h"
#include "context/context.h"
#include "dir_asset.h"
#include "distributed_kv_data_manager.h"
#include "imedia_scanner_client.h"
#include "media_data_ability_const.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_thumbnail.h"
#include "result_set_bridge.h"
#include "uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
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

    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

    void InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
    void ClearMediaLibraryMgr();
    void MakeDirQuerySetMap(std::unordered_map<std::string, DirAsset> &outDirQuerySetMap);
    std::unordered_map<std::string, DirAsset> GetDirQuerySetMap() const;

private:
    void InitDeviceData();
    bool QuerySync(const std::string &networkId, const std::string &tableName);

    bool CheckFileNameValid(const DataShare::DataShareValuesBucket &value);
    sptr<AppExecFwk::IBundleMgr> GetSysBundleManager();
    std::string GetClientBundleName();
    std::string GetClientBundle(int uid);
    void NeedQuerySync(const std::string &networkId, OperationObject oprnObject);

    std::mutex mgrMutex_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<MediaLibraryThumbnail> mediaThumbnail_;
    std::shared_ptr<OHOS::AbilityRuntime::Context> context_;
    std::string bundleName_{BUNDLE_NAME};
    OHOS::sptr<AppExecFwk::IBundleMgr> bundleMgr_;
    static std::mutex mutex_;
    static std::shared_ptr<MediaLibraryDataManager> instance_;
    std::unordered_map<std::string, DirAsset> dirQuerySetMap_;
    std::atomic<int> refCnt_{0};
};

// Scanner callback objects
class ScanFileCallback : public IMediaScannerAppCallback {
public:
    ScanFileCallback() = default;
    ~ScanFileCallback() = default;
    void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override {};
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DATA_ABILITY_H
