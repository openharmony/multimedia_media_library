/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "medialibrary_sync_operation.h"
#include "datashare_helper.h"
#include "device_manager.h"
#include "media_log.h"
#include "medialibrary_tracer.h"
#include "media_column.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedKv;
namespace {
    static constexpr int RETRY_COUNT = 3;
    static constexpr int32_t WAIT_FOR_MS = 1000;
}

static vector<string> table_arr = {
    MEDIALIBRARY_TABLE, PhotoColumn::PHOTOS_TABLE, AudioColumn::AUDIOS_TABLE,
    DocumentColumn::DOCUMENTS_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE
};

void MediaLibrarySyncCallback::SyncCompleted(const map<string, DistributedKv::Status> &results)
{
    for (auto &item : results) {
        if (item.second == Status::SUCCESS) {
            MEDIA_DEBUG_LOG("MediaLibrarySyncOperation::SyncCompleted OK");
            unique_lock<mutex> lock(status_.mtx_);
            status_.isSyncComplete_ = true;
            break;
        }
    }
    status_.cond_.notify_one();
}

bool MediaLibrarySyncCallback::WaitFor()
{
    unique_lock<mutex> lock(status_.mtx_);
    bool ret = status_.cond_.wait_for(lock, chrono::milliseconds(WAIT_FOR_MS),
        [this]() { return status_.isSyncComplete_; });
    if (!ret) {
        MEDIA_INFO_LOG("MediaLibrarySyncOperation::SyncPullKvstore wait_for timeout");
    } else {
        MEDIA_DEBUG_LOG("MediaLibrarySyncOperation::SyncPullKvstore wait_for SyncCompleted");
    }
    return ret;
}

bool MediaLibrarySyncOperation::SyncPullAllTableByNetworkId(MediaLibrarySyncOpts &syncOpts, vector<string> &devices)
{
    if (syncOpts.rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibrarySyncOperation SyncPullAllTable rdbStore is null");
        return false;
    }

    for (auto &table_name : table_arr) {
        syncOpts.table = table_name;
        auto ret = SyncPullTable(syncOpts, devices);
        if (!ret) {
            MEDIA_ERR_LOG("sync pull table %{public}s failed, err %{public}d", table_name.c_str(), ret);
        }
    }
    return true;
}

static string GetDeviceUdidByNetworkId(const shared_ptr<RdbStore> &rdbStore, const string &networkId)
{
    vector<string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    absPredDevice.EqualTo(DEVICE_DB_NETWORK_ID, networkId);
    auto queryResultSet = rdbStore->QueryByStep(absPredDevice, columns);

    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetDeviceUdidByNetworkId Rdb failed");
        return "";
    }

    if (count <= 0) {
        MEDIA_ERR_LOG("GetDeviceUdidByNetworkId there is no device_udid record");
        return "";
    }

    ret = queryResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetDeviceUdidByNetworkId Rdb failed");
        return "";
    }

    return get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_UDID, queryResultSet, TYPE_STRING));
}

static bool UpdateDeviceSyncStatus(const shared_ptr<RdbStore> &rdbStore, const string &networkId, int32_t syncStatus)
{
    string deviceUdid = GetDeviceUdidByNetworkId(rdbStore, networkId);
    if (deviceUdid.empty()) {
        MEDIA_ERR_LOG("UpdateDeviceSyncStatus Get device_udid failed");
        return false;
    }

    vector<string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    absPredDevice.EqualTo(DEVICE_DB_UDID, deviceUdid);
    auto queryResultSet = rdbStore->QueryByStep(absPredDevice, columns);

    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret == NativeRdb::E_OK) {
        if (count > 0) {
            ValuesBucket valuesBucket;
            valuesBucket.PutString(DEVICE_DB_UDID, deviceUdid);
            valuesBucket.PutInt(DEVICE_DB_SYNC_STATUS, syncStatus);

            int32_t updatedRows(0);
            vector<string> whereArgs = {deviceUdid};
            int32_t updateResult = rdbStore->Update(updatedRows, DEVICE_TABLE,
                valuesBucket, DEVICE_DB_UDID + " = ?", whereArgs);
            if (updateResult != E_OK) {
                MEDIA_ERR_LOG("UpdateDeviceSyncStatus Update failed");
                return false;
            }

            return (updatedRows > 0) ? true : false;
        }
    }

    return false;
}

static bool SyncPullTableCallbackExec(const MediaLibrarySyncOpts &syncOpts, const string &networkId, int syncResult)
{
    if (networkId.empty()) {
        MEDIA_ERR_LOG("SyncPullTable networkId is empty");
        return false;
    }
    if (syncResult != 0) {
        MEDIA_ERR_LOG("SyncPullTable tableName = %{public}s device = %{private}s syncResult = %{private}d",
                      syncOpts.table.c_str(), networkId.c_str(), syncResult);
        return false;
    }
    if (syncOpts.table == MEDIALIBRARY_TABLE) {
        UpdateDeviceSyncStatus(syncOpts.rdbStore, networkId, DEVICE_SYNCSTATUS_COMPLETE);
    }
    return true;
}

bool MediaLibrarySyncOperation::SyncPullTable(MediaLibrarySyncOpts &syncOpts, vector<string> &devices)
{
    CHECK_AND_RETURN_RET_LOG(syncOpts.rdbStore != nullptr, false, "Rdb Store is not initialized");
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PULL;
    option.isBlock = true;

    vector<string> onlineDevices;
    GetOnlineDevices(syncOpts.bundleName, devices, onlineDevices);
    if (onlineDevices.size() == 0) {
        MEDIA_ERR_LOG("SyncPullTable there is no online device");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicate(syncOpts.table);
    (onlineDevices.size() > 0) ? predicate.InDevices(onlineDevices) : predicate.InAllDevices();
    if (syncOpts.table == MEDIALIBRARY_TABLE && !syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_TIME_PENDING, to_string(0))->And()->EqualTo(MEDIA_DATA_DB_ID, syncOpts.row);
    } else if (syncOpts.table == MEDIALIBRARY_TABLE && syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_TIME_PENDING, to_string(0));
    } else if (!syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_ID, syncOpts.row);
    }

    DistributedRdb::SyncCallback callback = [syncOpts](const DistributedRdb::SyncResult& syncResult) {
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (!SyncPullTableCallbackExec(syncOpts, iter->first, iter->second)) {
                continue;
            }
        }
    };

    uint32_t count = 0;
    int ret = -1;
    while (count++ < RETRY_COUNT) {
        MediaLibraryTracer tracer;
        tracer.Start("abilityHelper->Query");
        ret = syncOpts.rdbStore->Sync(option, predicate, callback);
        if (ret == E_OK) {
            break;
        } else if (count == RETRY_COUNT) {
            return false;
        }
    }

    return true;
}

static bool SyncPushTableCallbackExec(const MediaLibrarySyncOpts &syncOpts, const string &networkId, int syncResult)
{
    if (networkId.empty()) {
        MEDIA_ERR_LOG("SyncPushTable networkId is empty");
        return false;
    }
    if (syncResult != 0) {
        MEDIA_ERR_LOG("SyncPushTable tableName = %{public}s device = %{private}s syncResult = %{private}d",
                      syncOpts.table.c_str(), networkId.c_str(), syncResult);
        return false;
    }
    return true;
}

bool MediaLibrarySyncOperation::SyncPushTable(MediaLibrarySyncOpts &syncOpts, vector<string> &devices, bool isBlock)
{
    CHECK_AND_RETURN_RET_LOG(syncOpts.rdbStore != nullptr, false, "Rdb Store is not initialized");
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PUSH;
    option.isBlock = isBlock;

    vector<string> onlineDevices;
    GetOnlineDevices(syncOpts.bundleName, devices, onlineDevices);
    if (onlineDevices.size() == 0) {
        MEDIA_ERR_LOG("SyncPushTable there is no online device");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicate(syncOpts.table);
    (onlineDevices.size() > 0) ? predicate.InDevices(onlineDevices) : predicate.InAllDevices();
    if (syncOpts.table == MEDIALIBRARY_TABLE && !syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_TIME_PENDING, to_string(0))->And()->EqualTo(MEDIA_DATA_DB_ID, syncOpts.row);
    } else if (syncOpts.table == MEDIALIBRARY_TABLE && syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_TIME_PENDING, to_string(0));
    } else if (!syncOpts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_ID, syncOpts.row);
    }

    DistributedRdb::SyncCallback callback = [syncOpts](const DistributedRdb::SyncResult& syncResult) {
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (!SyncPushTableCallbackExec(syncOpts, iter->first, iter->second)) {
                continue;
            }
            MEDIA_INFO_LOG("SyncPushTable tableName = %{public}s, device = %{private}s success",
                syncOpts.table.c_str(), iter->first.c_str());
        }
    };

    MediaLibraryTracer tracer;
    tracer.Start("SyncPushTable rdbStore->Sync");
    int ret = syncOpts.rdbStore->Sync(option, predicate, callback);

    return ret == E_OK;
}

void MediaLibrarySyncOperation::GetOnlineDevices(const string &bundleName,
    const vector<string> &originalDevices, vector<string> &onlineDevices)
{
    vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    string extra = "";
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetTrustedDeviceList(bundleName, extra, deviceList);
    if (ret != 0) {
        MEDIA_ERR_LOG("get trusted device list failed, ret %{public}d", ret);
        return;
    }

    for (auto &device : originalDevices) {
        for (auto &deviceInfo : deviceList) {
            string networkId = deviceInfo.networkId;
            if (networkId.compare(device) == 0) {
                onlineDevices.push_back(device);
            }
        }
    }
}

Status MediaLibrarySyncOperation::SyncPullKvstore(const shared_ptr<SingleKvStore> &kvStore,
    const string &key, const string &networkId)
{
    MEDIA_DEBUG_LOG("networkId is %{private}s key is %{private}s",
        networkId.c_str(), key.c_str());
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is null");
        return DistributedKv::Status::ERROR;
    }
    if (networkId.empty()) {
        MEDIA_ERR_LOG("networkId empty error");
        return DistributedKv::Status::ERROR;
    }

    DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    dataQuery.Limit(1, 0); // for force to sync single key
    vector<string> devices = { networkId };
    MediaLibraryTracer tracer;
    tracer.Start("SyncPullKvstore kvStore->SyncPull");
    auto callback = make_shared<MediaLibrarySyncCallback>();
    Status status = kvStore->Sync(devices, OHOS::DistributedKv::SyncMode::PULL, dataQuery, callback);
    if (!callback->WaitFor()) {
        MEDIA_DEBUG_LOG("wait_for timeout");
        status = Status::ERROR;
    }
    return status;
}

Status MediaLibrarySyncOperation::SyncPushKvstore(const shared_ptr<SingleKvStore> &kvStore,
    const string &key, const string &networkId)
{
    MEDIA_DEBUG_LOG("networkId is %{private}s", networkId.c_str());
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is null");
        return Status::ERROR;
    }
    if (networkId.empty()) {
        MEDIA_ERR_LOG("networkId empty error");
        return Status::ERROR;
    }
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    vector<string> devices = { networkId };
    MediaLibraryTracer tracer;
    tracer.Start("SyncPushKvstore kvStore->SyncPush");
    return kvStore->Sync(devices, OHOS::DistributedKv::SyncMode::PUSH, dataQuery);
}
} // namespace Media
} // namespace OHOS
