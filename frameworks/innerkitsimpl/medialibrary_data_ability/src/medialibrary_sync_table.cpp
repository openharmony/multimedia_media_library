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
#include "bytrace.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;

MediaLibrarySyncTable::MediaLibrarySyncTable()
{
}

MediaLibrarySyncTable::~MediaLibrarySyncTable()
{
}

bool MediaLibrarySyncTable::SyncPullAllTable(const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName)
{
    MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable IN");
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable rdbStore is null");
        return false;
    }

    std::vector<std::string> devices;
    auto ret = SyncPullTable(rdbStore, bundleName, MEDIALIBRARY_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncFilesTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, SMARTALBUM_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, SMARTALBUM_MAP_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumMapTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, CATEGORY_SMARTALBUM_MAP_TABLE, devices, true);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumMapTable error!");
        return false;
    }

    MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable OUT");
    return true;
}

bool MediaLibrarySyncTable::SyncPullAllTableByDeviceId(
    const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName, std::vector<std::string> &devices)
{
    MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable IN");
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable rdbStore is null");
        return false;
    }

    auto ret = SyncPullTable(rdbStore, bundleName, MEDIALIBRARY_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncFilesTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, SMARTALBUM_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, SMARTALBUM_MAP_TABLE, devices);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumMapTable error!");
        return false;
    }
    ret = SyncPullTable(rdbStore, bundleName, CATEGORY_SMARTALBUM_MAP_TABLE, devices, true);
    if (!ret) {
        MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable SyncSmartAlbumMapTable error!");
        return false;
    }

    MEDIA_ERR_LOG("MediaLibrarySyncTable SyncPullAllTable OUT");
    return true;
}

bool MediaLibrarySyncTable::SyncPullTable(
    const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName, const std::string &tableName,
    std::vector<std::string> &devices, bool isLast)
{
    MEDIA_ERR_LOG("SyncPullTable table = %{public}s, isLast = %{public}d", tableName.c_str(), isLast);
    // start sync
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PULL;
    option.isBlock = true;

    NativeRdb::AbsRdbPredicates predicate(tableName.c_str());
    (devices.size() > 0) ? predicate.InDevices(devices) : predicate.InAllDevices();

    DistributedRdb::SyncCallback callback = [&bundleName, &isLast](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPullTable deviceId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPullTable device = %{public}s syncResult = %{public}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            if (isLast) {
                MediaLibraryDevice::GetInstance()->UpdateDevicieSyncStatus(iter->first, DEVICE_SYNCSTATUS_COMPLETE,
                                                                           bundleName);
            }
            MEDIA_ERR_LOG("SyncPullTable device = %{public}s success", iter->first.c_str());
        }
    };

    uint32_t count = 0;
    while (count++ < RETRY_COUNT) {
        MEDIA_ERR_LOG("SyncPullTable before Sync");
        StartTrace(BYTRACE_TAG_OHOS, "abilityHelper->Query");
        auto ret = rdbStore->Sync(option, predicate, callback);
        FinishTrace(BYTRACE_TAG_OHOS);
        MEDIA_ERR_LOG("SyncPullTable after Sync");
        if (ret) {
            return ret;
        }
    }
    return false;
}

bool MediaLibrarySyncTable::SyncPushTable(const shared_ptr<RdbStore> &rdbStore, const std::string &bundleName,
                                          const std::string &tableName, std::vector<std::string> &devices, bool isBlock)
{
    MEDIA_ERR_LOG("SyncPushTable table = %{public}s", tableName.c_str());
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
                MEDIA_ERR_LOG("SyncPushTable device = %{public}s syncResult = %{public}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            MEDIA_ERR_LOG("SyncPushTable device = %{public}s success", iter->first.c_str());
        }
    };

    StartTrace(BYTRACE_TAG_OHOS, "SyncPushTable rdbStore->Sync");
    bool ret = rdbStore->Sync(option, predicate, callback);
    FinishTrace(BYTRACE_TAG_OHOS);

    return ret;
}
} // namespace Media
} // namespace OHOS