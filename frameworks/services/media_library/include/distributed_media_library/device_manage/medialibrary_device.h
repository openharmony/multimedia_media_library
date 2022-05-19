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

#include <string>
#include <unordered_map>
#include "data_ability_helper.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "device_profile_agent.h"
#include "event_handler.h"
#include "media_data_ability_const.h"
#include "medialibrary_device_info.h"
#include "medialibrary_device_operations.h"
#include "rdb_errno.h"
#include "rdb_helper.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;

class MediaLibraryDevice : public DistributedHardware::DeviceStateCallback,
                            public DistributedHardware::DmInitCallback,
                            public std::enable_shared_from_this<MediaLibraryDevice> {
public:
    MediaLibraryDevice();
    ~MediaLibraryDevice();
    static std::shared_ptr<MediaLibraryDevice> GetInstance();
    void Start();
    void Stop();
    void OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnRemoteDied() override;

    void SetAbilityContext(const std::shared_ptr<OHOS::AppExecFwk::Context> &context);
    void GetAllDeviceId(std::vector<OHOS::DistributedHardware::DmDeviceInfo> &deviceList);
    bool InitDeviceRdbStore(const shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &bundleName);
    void ClearAllDevices();
    void NotifyDeviceChange();
    void NotifyRemoteFileChange();
    bool UpdateDevicieSyncStatus(const std::string &deviceId, int32_t syncStatus);
    bool GetDevicieSyncStatus(const std::string &deviceId, int32_t &syncStatus);
    string GetNetworkIdBySelfId(const std::string &selfId);

private:
    std::string GetUdidByNetworkId(const std::string &deviceId);
    void GetMediaLibraryDeviceInfo(const OHOS::DistributedHardware::DmDeviceInfo &dmInfo,
                                   OHOS::Media::MediaLibraryDeviceInfo& mlInfo);
    bool QueryDeviceTable();
    bool IsHasDevice(const std::string &deviceUdid);
    void RegisterToDM();
    void UnRegisterFromDM();
private:
    static constexpr int SHORT_UDID_LEN = 8;
    static constexpr int RANDOM_NUM = 999;

    static std::shared_ptr<MediaLibraryDevice> mlDMInstance_;
    std::unique_ptr<MediaLibraryDeviceOperations> mediaLibraryDeviceOperations_;
    std::shared_ptr<AppExecFwk::DataAbilityHelper> dataAbilityhelper_;
    std::shared_ptr<AppExecFwk::EventHandler> mediaLibraryDeviceHandler_;
    std::mutex deviceLock_;
    std::unordered_map<std::string, OHOS::Media::MediaLibraryDeviceInfo> deviceInfoMap_;
    std::map<std::string, std::set<int>> excludeMap_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::unique_ptr<DeviceProfileAgent> dpa_;
    std::string bundleName_ { "com.ohos.medialibrary.MediaLibraryDataA" };
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DEVICE_H
