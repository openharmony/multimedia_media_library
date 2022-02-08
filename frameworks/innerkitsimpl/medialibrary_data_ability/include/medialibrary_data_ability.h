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

#ifndef OHOS_MEDIALIBRARY_DATA_ABILITY_H
#define OHOS_MEDIALIBRARY_DATA_ABILITY_H

#include <string>

#include "ability.h"
#include "ability_loader.h"
#include "data_ability_predicates.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "media_data_ability_const.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "media_log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "result_set.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"
#include "hilog/log.h"
#include "medialibrary_thumbnail.h"
#include "distributed_kv_data_manager.h"

namespace OHOS {
namespace Media {
// kvstore constants
    const DistributedKv::AppId KVSTORE_APPID { "soundmanager" };
    const DistributedKv::StoreId KVSTORE_STOREID { "ringtone" };
    enum TableType {
        TYPE_DATA,
        TYPE_SMARTALBUM,
        TYPE_SMARTALBUM_MAP,
        TYPE_ALBUM_TABLE,
        TYPE_SMARTALBUMASSETS_TABLE,
        TYPE_ASSETSMAP_TABLE
    };
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
        bool CheckFileNameValid(const ValuesBucket &value);

        static const std::string PERMISSION_NAME_READ_MEDIA;
        static const std::string PERMISSION_NAME_WRITE_MEDIA;
        std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
        DistributedKv::DistributedKvDataManager dataManager_;
        std::shared_ptr<IMediaScannerClient> scannerClient_;
        std::shared_ptr<NativeRdb::RdbStore> rdbStore;
        std::shared_ptr<NativeRdb::RdbStore> smartAlbumrdbStore;
        std::shared_ptr<NativeRdb::RdbStore> smartAlbumMaprdbStore;
        std::shared_ptr<MediaLibraryThumbnail> mediaThumbnail_;

        bool isRdbStoreInitialized;
};

class MediaLibraryDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
};

// Scanner callback objects
class ScanFileCallback : public IMediaScannerAppCallback {
public:
    ScanFileCallback() = default;
    ~ScanFileCallback() = default;
    void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DATA_ABILITY_H
