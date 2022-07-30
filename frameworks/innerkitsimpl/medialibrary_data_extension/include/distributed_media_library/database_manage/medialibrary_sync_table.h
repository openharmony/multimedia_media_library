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

#ifndef OHOS_MEDIALIBRARY_SYNC_TABLE_H
#define OHOS_MEDIALIBRARY_SYNC_TABLE_H

#include <string>
#include "abs_rdb_predicates.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "distributed_kv_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_device.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;

class MediaLibrarySyncTable {
public:
    MediaLibrarySyncTable() = delete;
    ~MediaLibrarySyncTable() = delete;

    static bool SyncPullAllTableByDeviceId(const shared_ptr<RdbStore> &rdbStore,
                                    const std::string &bundleName, std::vector<std::string> &devices);
    static bool SyncPullTable(const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName,
                       const std::string &tableName, std::vector<std::string> &devices, bool isLast = false);
    static bool SyncPushTable(const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName,
                       const std::string &tableName, std::vector<std::string> &devices, bool isBlock = false);

private:
    static constexpr int RETRY_COUNT = 3;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SYNC_TABLE_H
