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

#ifndef OHOS_MEDIALIBRARY_DEVICE_H
#define OHOS_MEDIALIBRARY_DEVICE_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>

#include "device_manager.h"
#include "device_manager_callback.h"
#include "devices_info_interact.h"
#include "distributed_kv_data_manager.h"
#include "event_handler.h"
#include "medialibrary_db_const.h"
#include "medialibrary_device_info.h"
#include "medialibrary_device_operations.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "single_kvstore.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
static constexpr int DEFAULT_DEV_SECURITY_LEVEL = 1;
class MediaLibraryDevice : public DistributedHardware::DeviceStateCallback,
                            public DistributedHardware::DmInitCallback,
                            public std::enable_shared_from_this<MediaLibraryDevice> {
public:
    virtual ~MediaLibraryDevice();
    MediaLibraryDevice(const MediaLibraryDevice&) = delete;
    MediaLibraryDevice(MediaLibraryDevice&&) = delete;
    MediaLibraryDevice& operator=(const MediaLibraryDevice&) = delete;
    MediaLibraryDevice& operator=(MediaLibraryDevice&&) = delete;
    static std::shared_ptr<MediaLibraryDevice> GetInstance();
    void Start();
    void Stop();
    void OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnRemoteDied() override;

    void GetAllDeviceId(std::vector<OHOS::DistributedHardware::DmDeviceInfo> &deviceList);
    bool InitDeviceRdbStore(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    void NotifyDeviceChange();
    void NotifyRemoteFileChange();
    bool UpdateDeviceSyncStatus(const std::string &networkId, int32_t syncStatus);
    bool GetDevicieSyncStatus(const std::string &networkId, int32_t &syncStatus);
    std::string GetNetworkIdBySelfId(const std::string &selfId);
    std::string GetUdidByNetworkId(std::string &networkId);
    void OnSyncCompleted(const std::string &devId, const DistributedKv::Status staus);
    void OnGetDevSecLevel(const std::string &udid, const int32_t level);
    void GetDeviceInfoMap(std::unordered_map<std::string, OHOS::Media::MediaLibraryDeviceInfo> &outDeviceMap);
    bool QueryAgingDeviceInfos(std::vector<MediaLibraryDeviceInfo> &outDeviceInfos);
    bool QueryAllDeviceUdid(vector<string> &deviceUdids);
    bool DeleteDeviceInfo(const std::string &udid);
    MediaLibraryDevice();

    void GetMediaLibraryDeviceInfo(const OHOS::DistributedHardware::DmDeviceInfo &dmInfo,
                                   OHOS::Media::MediaLibraryDeviceInfo& mlInfo);
    bool QueryDeviceTable();
    void ClearAllDevices();
    bool IsHasDevice(const std::string &deviceUdid);
    void RegisterToDM();
    void UnRegisterFromDM();
    void DevOnlineProcess(const DistributedHardware::DmDeviceInfo &devInfo);
    void TryToGetTargetDevMLInfos(const std::string &udid, const std::string &networkId);
private:
    static constexpr int SHORT_UDID_LEN = 8;
    static constexpr int RANDOM_NUM = 999;

    static std::shared_ptr<MediaLibraryDevice> mlDMInstance_;
    std::shared_ptr<AppExecFwk::EventHandler> deviceHandler_;
    std::mutex devMtx_;
    std::unordered_map<std::string, OHOS::Media::MediaLibraryDeviceInfo> deviceInfoMap_;
    std::map<std::string, std::set<int>> excludeMap_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::shared_ptr<DevicesInfoInteract> devsInfoInter_;
    std::string bundleName_;
    std::mutex cvMtx_;
    std::condition_variable kvSyncDoneCv_;
    std::string localUdid_;
    int32_t localDevLev_ {DEFAULT_DEV_SECURITY_LEVEL};
    std::atomic<bool> localSecLevelGot_ {false};
    std::mutex gotSecLevelMtx_;
    std::condition_variable localSecLevelDoneCv_;
    volatile bool isStart = false;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DEVICE_H
