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
#include "media_data_ability_const.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_data_ability_utils.h"
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

namespace OHOS {
namespace Media {
class MediaLibraryDataAbility : public AppExecFwk::Ability {
public:
    MediaLibraryDataAbility();
    ~MediaLibraryDataAbility();

    int32_t InitMediaLibraryRdbStore();
    int32_t Insert(const Uri &uri, const NativeRdb::ValuesBucket &value) override;
    int32_t Delete(const Uri &uri, const NativeRdb::DataAbilityPredicates &predicates) override;
    int32_t BatchInsert(const Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values) override;
    int32_t Update(const Uri &uri, const NativeRdb::ValuesBucket &value,
            const NativeRdb::DataAbilityPredicates &predicates) override;
    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(const Uri &uri, const std::vector<std::string> &columns,
            const NativeRdb::DataAbilityPredicates &predicates) override;
    int32_t OpenFile(const Uri &uri, const std::string &mode) override;

protected:
    void OnStart(const AAFwk::Want& want) override;
    void OnStop() override;

private:
    std::string GetOperationType(const std::string &uri);
    void ScanFile(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);

    std::shared_ptr<IMediaScannerClient> scannerClient_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore;
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
