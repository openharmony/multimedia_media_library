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
#define MLOG_TAG "Distributed"

#include "medialibrary_sync_table.h"
#include "media_log.h"
#include "medialibrary_tracer.h"
#include "medialibrary_errno.h"

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

    DistributedRdb::SyncCallback callback = [tableName](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPullTable networkId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPullTable tableName = %{public}s device = %{private}s syncResult = %{private}d",
                    tableName.c_str(), iter->first.c_str(), iter->second);
                continue;
            }
            if (tableName == MEDIALIBRARY_TABLE) {
                MediaLibraryDevice::GetInstance()->UpdateDeviceSyncStatus(iter->first, DEVICE_SYNCSTATUS_COMPLETE);
            }
            MEDIA_ERR_LOG("SyncPullTable tableName = %{public}s device = %{private}s success",
                tableName.c_str(), iter->first.c_str());
        }
    };

    uint32_t count = 0;
    while (count++ < RETRY_COUNT) {
        MediaLibraryTracer tracer;
        tracer.Start("abilityHelper->Query");
        int ret = rdbStore->Sync(option, predicate, callback);
        if (ret == E_OK) {
            return true;
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

    DistributedRdb::SyncCallback callback = [tableName](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPushTable networkId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPushTable tableName = %{public}s device = %{private}s syncResult = %{private}d",
                    tableName.c_str(), iter->first.c_str(), iter->second);
                continue;
            }
            MEDIA_INFO_LOG("SyncPushTable tableName = %{public}s, device = %{private}s success",
                tableName.c_str(), iter->first.c_str());
        }
    };

    MediaLibraryTracer tracer;
    tracer.Start("SyncPushTable rdbStore->Sync");
    int ret = rdbStore->Sync(option, predicate, callback);

    return ret == E_OK;
}
} // namespace Media
} // namespace OHOS
