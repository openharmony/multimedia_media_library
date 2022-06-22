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

#include "medialibrary_sync_table.h"
#include "hitrace_meter.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
constexpr int TABLE_NUM = 4;
static std::array<std::string, TABLE_NUM> table_arr = {
    MEDIALIBRARY_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE
};

bool MediaLibrarySyncTable::SyncPullAllTableByDeviceId(
    const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName, std::vector<std::string> &devices)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable rdbStore is null");
        return false;
    }

    for (auto &table_name : table_arr) {
        auto ret = SyncPullTable(rdbStore, bundleName, table_name, devices);
        if (!ret) {
            MEDIA_ERR_LOG("sync pull table %{public}s failed, err %{public}d", table_name.c_str(), ret);
        }
    }

    return true;
}

bool MediaLibrarySyncTable::SyncPullTable(
    const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName, const std::string &tableName,
    std::vector<std::string> &devices, bool isLast)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "Rdb Store is not initialized");
    // start sync
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PULL;
    option.isBlock = true;

    NativeRdb::AbsRdbPredicates predicate(tableName.c_str());
    (devices.size() > 0) ? predicate.InDevices(devices) : predicate.InAllDevices();

    DistributedRdb::SyncCallback callback = [&isLast](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPullTable deviceId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPullTable device = %{private}s syncResult = %{public}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            if (isLast) {
                MediaLibraryDevice::GetInstance()->UpdateDevicieSyncStatus(iter->first, DEVICE_SYNCSTATUS_COMPLETE);
            }
            MEDIA_ERR_LOG("SyncPullTable device = %{private}s success", iter->first.c_str());
        }
    };

    uint32_t count = 0;
    while (count++ < RETRY_COUNT) {
        StartTrace(HITRACE_TAG_OHOS, "abilityHelper->Query");
        auto ret = rdbStore->Sync(option, predicate, callback);
        FinishTrace(HITRACE_TAG_OHOS);
        if (ret) {
            return ret;
        }
    }
    return false;
}

bool MediaLibrarySyncTable::SyncPushTable(const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName,
                                          const std::string &tableName, std::vector<std::string> &devices, bool isBlock)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "Rdb Store is not initialized");
    // start sync
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PUSH;
    option.isBlock = isBlock;

    NativeRdb::AbsRdbPredicates predicate(tableName.c_str());
    (devices.size() > 0) ? predicate.InDevices(devices) : predicate.InAllDevices();

    DistributedRdb::SyncCallback callback = [&](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPushTable deviceId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPushTable device = %{private}s syncResult = %{public}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            MEDIA_INFO_LOG("SyncPushTable device = %{private}s success", iter->first.c_str());
        }
    };

    StartTrace(HITRACE_TAG_OHOS, "SyncPushTable rdbStore->Sync");
    bool ret = rdbStore->Sync(option, predicate, callback);
    FinishTrace(HITRACE_TAG_OHOS);

    return ret;
}
} // namespace Media
} // namespace OHOS
