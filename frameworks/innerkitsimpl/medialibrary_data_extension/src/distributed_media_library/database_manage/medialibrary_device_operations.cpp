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

#include "medialibrary_device_operations.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const int64_t AGING_DEVICE_INTERVAL = 14 * 24 * 60 * 60LL;

bool MediaLibraryDeviceOperations::InsertDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const OHOS::Media::MediaLibraryDeviceInfo &deviceInfo, const std::string &bundleName)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbstore is nullptr");
        return false;
    }
    unique_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    absPredDevice.EqualTo(DEVICE_DB_UDID, deviceInfo.deviceUdid);
    queryResultSet = rdbStore->Query(absPredDevice, columns);

    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    MEDIA_INFO_LOG("MediaLibraryDeviceOperations::InsertDeviceInfo ret = %{public}d, count = %{public}d", ret, count);
    if (ret == NativeRdb::E_OK) {
        if (count > 0) {
            // 更新数据库
            ValuesBucket valuesBucket;
            valuesBucket.PutString(DEVICE_DB_UDID, deviceInfo.deviceUdid);
            valuesBucket.PutString(DEVICE_DB_NETWORK_ID, deviceInfo.networkId);
            valuesBucket.PutInt(DEVICE_DB_SYNC_STATUS, 0);
            valuesBucket.PutLong(DEVICE_DB_DATE_MODIFIED, 0);
            return MediaLibraryDeviceDb::UpdateDeviceInfo(valuesBucket, rdbStore) == E_SUCCESS;
        } else {
            // 插入数据库
            ValuesBucket valuesBucket;
            valuesBucket.PutString(DEVICE_DB_UDID, deviceInfo.deviceUdid);
            valuesBucket.PutString(DEVICE_DB_NETWORK_ID, deviceInfo.networkId);
            valuesBucket.PutString(DEVICE_DB_NAME, deviceInfo.deviceName);
            valuesBucket.PutString(DEVICE_DB_IP, std::string());
            valuesBucket.PutString(DEVICE_DB_SELF_ID, deviceInfo.selfId);
            valuesBucket.PutInt(DEVICE_DB_TYPE, (int32_t) deviceInfo.deviceTypeId);
            valuesBucket.PutString(DEVICE_DB_PREPATH, std::string());
            int64_t now = MediaFileUtils::UTCTimeSeconds();
            valuesBucket.PutLong(DEVICE_DB_DATE_ADDED, now);
            return MediaLibraryDeviceDb::InsertDeviceInfo(valuesBucket, rdbStore) >= 0;
        }
    }
    return false;
}

bool MediaLibraryDeviceOperations::UpdateDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const OHOS::Media::MediaLibraryDeviceInfo &deviceInfo, const std::string &bundleName)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    absPredDevice.EqualTo(DEVICE_DB_UDID, deviceInfo.deviceUdid);
    MEDIA_INFO_LOG("MediaLibraryDeviceOperations::UpdateDeviceInfo dev id = %{private}s",
        deviceInfo.deviceUdid.c_str());
    queryResultSet = rdbStore->Query(absPredDevice, columns);

    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret == NativeRdb::E_OK) {
        if (count > 0) {
            // 更新数据库
            ValuesBucket valuesBucket;
            valuesBucket.PutString(DEVICE_DB_UDID, deviceInfo.deviceUdid);
            valuesBucket.PutString(DEVICE_DB_NETWORK_ID, deviceInfo.networkId);
            int idx = -1;
            ret = queryResultSet->GoToFirstRow();
            if (ret != NativeRdb::E_OK) {
                return false;
            }

            ret = queryResultSet->GetColumnIndex(DEVICE_DB_DATE_MODIFIED, idx);
            if (ret != NativeRdb::E_OK) {
                return false;
            }

            int64_t modifiedTime = 0;
            queryResultSet->GetLong(idx, modifiedTime);
            if (modifiedTime == 0) {
                int64_t now = MediaFileUtils::UTCTimeSeconds();
                valuesBucket.PutLong(DEVICE_DB_DATE_MODIFIED, now);
            }
            return MediaLibraryDeviceDb::UpdateDeviceInfo(valuesBucket, rdbStore) == E_SUCCESS;
        }
    }
    return false;
}

bool MediaLibraryDeviceOperations::DeleteDeviceInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                                    const std::string &udid)
{
    return MediaLibraryDeviceDb::DeleteDeviceInfo(udid, rdbStore);
}

bool MediaLibraryDeviceOperations::UpdateSyncStatus(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const std::string &udid, int32_t syncStatus)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);

    absPredDevice.EqualTo(DEVICE_DB_UDID, udid);
    queryResultSet = rdbStore->Query(absPredDevice, columns);

    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret == NativeRdb::E_OK) {
        if (count > 0) {
            // 更新数据库
            ValuesBucket valuesBucket;
            valuesBucket.PutString(DEVICE_DB_UDID, udid);
            valuesBucket.PutInt(DEVICE_DB_SYNC_STATUS, syncStatus);
            MEDIA_INFO_LOG("MediaLibraryDeviceOperations::UpdateSyncStatus");
            return MediaLibraryDeviceDb::UpdateDeviceInfo(valuesBucket, rdbStore) == E_SUCCESS;
        }
    }
    return false;
}

bool MediaLibraryDeviceOperations::GetSyncStatusById(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                                     const std::string &udid,
                                                     int32_t &syncStatus)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);

    absPredDevice.EqualTo(DEVICE_DB_UDID, udid);
    queryResultSet = rdbStore->Query(absPredDevice, columns);
    if (queryResultSet == nullptr) {
        return false;
    }

    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexId;
        queryResultSet->GetColumnIndex(DEVICE_DB_SYNC_STATUS, columnIndexId);
        queryResultSet->GetInt(columnIndexId, syncStatus);
    }
    MEDIA_INFO_LOG("MediaLibraryDeviceOperations::GetSyncStatusById syncStatus = %{public}d", syncStatus);
    return true;
}

bool MediaLibraryDeviceOperations::QueryDeviceTable(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                                    std::map<std::string, std::set<int>> &excludeMap)
{
    const int SHORT_UDID_LEN = 8;
    unique_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    queryResultSet = rdbStore->Query(absPredDevice, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDeviceOperations::QueryDeviceTable fail");
        return false;
    }

    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexId;
        std::string selfId;
        queryResultSet->GetColumnIndex(DEVICE_DB_SELF_ID, columnIndexId);
        queryResultSet->GetString(columnIndexId, selfId);
        if (selfId.length() > SHORT_UDID_LEN) {
            std::string shortUdid = selfId.substr(0, SHORT_UDID_LEN);
            std::string randNumber = selfId.substr(SHORT_UDID_LEN);
            if (!randNumber.empty()) {
                auto &data = excludeMap[shortUdid];
                data.insert(atoi(randNumber.c_str()));
            }
        }
    }
    return true;
}

bool MediaLibraryDeviceOperations::GetAllDeviceData(
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    vector<MediaLibraryDeviceInfo> &outDeviceList)
{
    shared_ptr<AbsSharedResultSet> queryResultSet;
    std::vector<std::string> columns;
    AbsRdbPredicates absPredDevice(DEVICE_TABLE);
    queryResultSet = rdbStore->Query(absPredDevice, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDeviceOperations::GetAllDeviceData fail");
        return false;
    }

    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        MediaLibraryDeviceInfo deviceInfo;
        deviceInfo.networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, queryResultSet,
            TYPE_STRING));
        deviceInfo.deviceTypeId = static_cast<DistributedHardware::DmDeviceType>(get<int32_t>(
            ResultSetUtils::GetValFromColumn(DEVICE_DB_TYPE, queryResultSet, TYPE_INT32)));
        deviceInfo.deviceUdid = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_UDID, queryResultSet,
            TYPE_STRING));
        deviceInfo.selfId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_SELF_ID, queryResultSet,
            TYPE_STRING));
        outDeviceList.push_back(deviceInfo);
    }
    return true;
}

bool MediaLibraryDeviceOperations::GetAgingDeviceData(
    const shared_ptr<RdbStore> &rdbStore, vector<MediaLibraryDeviceInfo> &outDeviceList)
{
    vector<string> columns;
    int64_t agingTime = MediaFileUtils::UTCTimeSeconds() - AGING_DEVICE_INTERVAL;

    MEDIA_INFO_LOG("GetAgingDeviceData less than %{public}" PRId64, agingTime);
    AbsRdbPredicates absPredevice(DEVICE_TABLE);
    absPredevice.GreaterThan(DEVICE_DB_DATE_MODIFIED, to_string(0))->And()->
        LessThan(DEVICE_DB_DATE_MODIFIED, to_string(agingTime));
    shared_ptr<AbsSharedResultSet> queryResultSet = rdbStore->Query(absPredevice, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("GetAgingDeviceData fail");
        return false;
    }
    auto ret = queryResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to fetch first record, ret = %{public}d", ret);
        return false;
    }

    MediaLibraryDeviceInfo deviceInfo;
    do {
        deviceInfo.networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, queryResultSet,
            TYPE_STRING));
        deviceInfo.deviceTypeId = (DistributedHardware::DmDeviceType)(get<int32_t>(ResultSetUtils::GetValFromColumn(
            DEVICE_DB_TYPE, queryResultSet, TYPE_INT32)));
        deviceInfo.deviceUdid = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_UDID, queryResultSet,
            TYPE_STRING));
        deviceInfo.selfId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_SELF_ID, queryResultSet,
            TYPE_STRING));
        outDeviceList.push_back(deviceInfo);
    } while (queryResultSet->GoToNextRow() == NativeRdb::E_OK);

    MEDIA_ERR_LOG("GetAgingDeviceData OUT, deviceSize = %{public}d", static_cast<int>(outDeviceList.size()));
    return true;
}

bool MediaLibraryDeviceOperations::GetAllDeviceUdid(const shared_ptr<RdbStore> &rdbStore,
    vector<string> &deviceUdids)
{
    vector<string> columns;
    AbsRdbPredicates absPreDevice(DEVICE_TABLE);
    shared_ptr<AbsSharedResultSet> queryResultSet = rdbStore->Query(absPreDevice, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDeviceOperations::GetAllDeviceUdid fail");
        return false;
    }
    auto ret = queryResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        return true;
    }
    do {
        string udid = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_UDID, queryResultSet,
            TYPE_STRING));
        deviceUdids.push_back(udid);
    } while (queryResultSet->GoToNextRow() == NativeRdb::E_OK);

    MEDIA_DEBUG_LOG("MediaLibraryDeviceOperations::GetAllDeviceUdid OUT");
    return true;
}
} // namespace Media
} // namespace OHOS
