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

#include "medialibrary_device.h"
#include "datashare_helper.h"
#include "device_permission_verification.h"
#include "device_auth.h"
#include "media_log.h"
#include "medialibrary_sync_table.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
std::shared_ptr<MediaLibraryDevice> MediaLibraryDevice::mlDMInstance_ = nullptr;

MediaLibraryDevice::MediaLibraryDevice()
{
    MEDIA_DEBUG_LOG("MediaLibraryDevice::constructor");
}

MediaLibraryDevice::~MediaLibraryDevice()
{
    MEDIA_DEBUG_LOG("MediaLibraryDevice::deconstructor");
}

void MediaLibraryDevice::Start()
{
    MEDIA_DEBUG_LOG("MediaLibraryDevice::start");
    bundleName_ = BUNDLE_NAME;
    if (mediaLibraryDeviceOperations_ == nullptr) {
        mediaLibraryDeviceOperations_ = std::make_unique<MediaLibraryDeviceOperations>();
    }

    if (mediaLibraryDeviceHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("MediaLibraryDevice");
        mediaLibraryDeviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    devsInfoInter_ = make_unique<DevicesInfoInteract>();
    if (devsInfoInter_ != nullptr) {
        devsInfoInter_->Init();
        std::string local = "";
        devsInfoInter_->PutMLDeviceInfos(GetUdidByNetworkId(local));
    }
    RegisterToDM();
}

void MediaLibraryDevice::Stop()
{
    MEDIA_INFO_LOG("Stop enter");
    UnRegisterFromDM();
    ClearAllDevices();
    mediaLibraryDeviceOperations_ = nullptr;
    dataShareHelper_ = nullptr;
    devsInfoInter_ = nullptr;
}

std::shared_ptr<MediaLibraryDevice> MediaLibraryDevice::GetInstance()
{
    static std::once_flag onceFlag;
    std::call_once(onceFlag, []() mutable {
        mlDMInstance_ = std::shared_ptr<MediaLibraryDevice>(new(std::nothrow) MediaLibraryDevice());
        if (mlDMInstance_ != nullptr) {
            mlDMInstance_ ->Start();
        }
    });
    return mlDMInstance_;
}

void MediaLibraryDevice::SetAbilityContext(const std::shared_ptr<AbilityRuntime::Context> &context)
{
    dataShareHelper_ = DataShareHelper::Creator(context, MEDIALIBRARY_DATA_URI);
    MEDIA_INFO_LOG("MediaLibraryDevice::SetAbilityContext create dataAbilityhelper %{private}d",
        (dataShareHelper_ != nullptr));
}

void MediaLibraryDevice::GetAllDeviceId(
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> &deviceList)
{
    std::string extra = "";
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetTrustedDeviceList(bundleName_, extra, deviceList);
    if (ret != 0) {
        MEDIA_ERR_LOG("get trusted device list failed, ret %{public}d", ret);
    }
}
void MediaLibraryDevice::OnSyncCompleted(const std::string &devId, const DistributedKv::Status status)
{
    MEDIA_INFO_LOG("OnSyncCompleted devid %{private}s, status %{public}d", devId.c_str(), status);
    std::unique_lock<std::mutex> lock(cvMtx_);
    kvSyncDoneCv_.notify_one();
}

void MediaLibraryDevice::DevOnlineProcess(const DistributedHardware::DmDeviceInfo &devInfo)
{
    MediaLibraryDeviceInfo mldevInfo;
    GetMediaLibraryDeviceInfo(devInfo, mldevInfo);

    DevicePermissionVerification authVerify;
    if (!authVerify.CheckPermission(mldevInfo.deviceUdid)) {
        MEDIA_ERR_LOG("this dev has permission denied!");
        return;
    }

    if (mediaLibraryDeviceOperations_ != nullptr &&
        !mediaLibraryDeviceOperations_->InsertDeviceInfo(rdbStore_, mldevInfo, bundleName_)) {
        MEDIA_ERR_LOG("OnDeviceOnline InsertDeviceInfo failed!");
        return;
    }
    MediaLibrarySyncTable syncTable;
    std::vector<std::string> devices = { mldevInfo.deviceId };
    syncTable.SyncPullAllTableByDeviceId(rdbStore_, bundleName_, devices);

    if (devsInfoInter_ != nullptr) {
        if (!devsInfoInter_->GetMLDeviceInfos(mldevInfo.deviceUdid, mldevInfo.versionId)) {
            MEDIA_INFO_LOG("get ml infos failed, so try to sync pull first, wait...");
        }
    }
    lock_guard<mutex> autoLock(deviceLock_);
    deviceInfoMap_[devInfo.deviceId] = mldevInfo;
    MEDIA_INFO_LOG("OnDeviceOnline cid %{public}s media library version %{public}s",
        mldevInfo.deviceId.c_str(), mldevInfo.versionId.c_str());
}

void MediaLibraryDevice::OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("OnDeviceOnline deviceId = %{private}s", deviceInfo.deviceId);
    if (mediaLibraryDeviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("OnDeviceOnline mediaLibraryDeviceHandler null");
        return;
    }

    auto nodeOnline = [this, deviceInfo]() {
        DevOnlineProcess(deviceInfo);
        NotifyDeviceChange();
    };
    if (!mediaLibraryDeviceHandler_->PostTask(nodeOnline)) {
        MEDIA_ERR_LOG("OnDeviceOnline handler postTask failed");
    }
}

void MediaLibraryDevice::OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("OnDeviceOffline deviceId = %{private}s", deviceInfo.deviceId);

    if (mediaLibraryDeviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("OnDeviceOffline mediaLibraryDeviceHandler null");
        return;
    }
    auto nodeOffline = [this, deviceInfo]() {
        lock_guard<mutex> autoLock(deviceLock_);
        std::string devId = deviceInfo.deviceId;
        auto info = deviceInfoMap_.find(devId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("OnDeviceOffline can not find deviceId:%{private}s", devId.c_str());
            return;
        }
        if (mediaLibraryDeviceOperations_ != nullptr) {
            mediaLibraryDeviceOperations_->UpdateDeviceInfo(rdbStore_, info->second, bundleName_);
        }
        deviceInfoMap_.erase(devId);

        // 设备变更通知
        NotifyDeviceChange();
    };
    if (!mediaLibraryDeviceHandler_->PostTask(nodeOffline)) {
        MEDIA_ERR_LOG("OnDeviceOffline handler postTask failed");
    }
}

void MediaLibraryDevice::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("MediaLibraryDevice OnDeviceChanged called deviceId = %{private}s", deviceInfo.deviceId);
}

void MediaLibraryDevice::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("MediaLibraryDevice OnDeviceReady called deviceId = %{private}s", deviceInfo.deviceId);
}

void MediaLibraryDevice::ClearAllDevices()
{
    lock_guard<mutex> autoLock(deviceLock_);
    deviceInfoMap_.clear();
    excludeMap_.clear();
}

void MediaLibraryDevice::NotifyDeviceChange()
{
    auto contextUri = make_unique<Uri>(MEDIALIBRARY_DEVICE_URI);
    if (dataShareHelper_ != nullptr) {
        dataShareHelper_->NotifyChange(*contextUri);
        MEDIA_INFO_LOG("MediaLibraryDevice NotifyDeviceChange complete");
    }
}

void MediaLibraryDevice::NotifyRemoteFileChange()
{
    auto contextUri = make_unique<Uri>(MEDIALIBRARY_REMOTEFILE_URI);
    if (dataShareHelper_ != nullptr) {
        dataShareHelper_->NotifyChange(*contextUri);
        MEDIA_INFO_LOG("MediaLibraryDevice NotifyRemoteFileChange complete");
    }
}

bool MediaLibraryDevice::IsHasDevice(const string &deviceUdid)
{
    for (auto &[_, info] : deviceInfoMap_) {
        if (!deviceUdid.compare(info.deviceUdid)) {
            return true;
        }
    }
    return false;
}

bool MediaLibraryDevice::InitDeviceRdbStore(const shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    rdbStore_ = rdbStore;

    if (!QueryDeviceTable()) {
        MEDIA_ERR_LOG("MediaLibraryDevice InitDeviceRdbStore QueryDeviceTable fail!");
        return false;
    }
    // 获取同一网络中的所有设备Id
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    GetAllDeviceId(deviceList);
    MEDIA_ERR_LOG("MediaLibraryDevice InitDeviceRdbStore deviceList size = %{public}d", (int) deviceList.size());
    for (auto& deviceInfo : deviceList) {
        DevOnlineProcess(deviceInfo);
    }

    std::vector<OHOS::Media::MediaLibraryDeviceInfo> deviceDataBaseList;
    mediaLibraryDeviceOperations_->GetAllDeviceDatas(rdbStore, deviceDataBaseList);
    MEDIA_INFO_LOG("MediaLibraryDevice InitDeviceRdbStore deviceDataBaseList size = %{public}d",
        (int) deviceDataBaseList.size());
    for (OHOS::Media::MediaLibraryDeviceInfo deviceInfo : deviceDataBaseList) {
        if (!IsHasDevice(deviceInfo.deviceUdid)) {
            if (mediaLibraryDeviceOperations_ != nullptr) {
                mediaLibraryDeviceOperations_->UpdateDeviceInfo(rdbStore_, deviceInfo, bundleName_);
            }
        }
    }
    MEDIA_INFO_LOG("MediaLibraryDevice InitDeviceRdbStore OUT deviceInfoMap size = %{public}d",
        (int) deviceInfoMap_.size());
    return true;
}

bool MediaLibraryDevice::UpdateDevicieSyncStatus(const std::string &deviceId, int32_t syncStatus)
{
    if (mediaLibraryDeviceOperations_ != nullptr) {
        lock_guard<mutex> autoLock(deviceLock_);
        auto info = deviceInfoMap_.find(deviceId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("UpdateDevicieSyncStatus can not find deviceId:%{private}s", deviceId.c_str());
            return false;
        }
        return mediaLibraryDeviceOperations_->UpdateSyncStatus(rdbStore_, info->second.deviceUdid, syncStatus,
                                                               bundleName_);
    }
    return false;
}

bool MediaLibraryDevice::GetDevicieSyncStatus(const std::string &deviceId, int32_t &syncStatus)
{
    if (mediaLibraryDeviceOperations_ != nullptr) {
        lock_guard<mutex> autoLock(deviceLock_);
        auto info = deviceInfoMap_.find(deviceId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("GetDevicieSyncStatus can not find deviceId:%{private}s", deviceId.c_str());
            return false;
        }
        return mediaLibraryDeviceOperations_->GetSyncStatusById(rdbStore_, deviceId, syncStatus,
                                                                bundleName_);
    }
    return false;
}

std::string MediaLibraryDevice::GetUdidByNetworkId(const std::string &deviceId)
{
    if (deviceId.empty()) {
        constexpr int32_t DEVICE_ID_SIZE = 65;
        char localDeviceId[DEVICE_ID_SIZE] = {0};
        GetDevUdid(localDeviceId, DEVICE_ID_SIZE);
        std::string localUdid = std::string(localDeviceId);
        MEDIA_INFO_LOG("get local udid %{private}s", localUdid.c_str());
        if (localUdid.empty()) {
            MEDIA_ERR_LOG("get local udid failed");
        }
        return localUdid;
    }
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    std::string deviceUdid;
    auto ret = deviceManager.GetUdidByNetworkId(bundleName_, deviceId, deviceUdid);
    if (ret != 0) {
        MEDIA_INFO_LOG("GetDeviceUdid error deviceId = %{private}s", deviceId.c_str());
        return std::string();
    }
    return deviceUdid;
}

void MediaLibraryDevice::GetMediaLibraryDeviceInfo(const DistributedHardware::DmDeviceInfo &dmInfo,
    MediaLibraryDeviceInfo& mlInfo)
{
    mlInfo.deviceId = dmInfo.deviceId;
    mlInfo.deviceName = dmInfo.deviceName;
    mlInfo.deviceTypeId = dmInfo.deviceTypeId;
    mlInfo.deviceUdid = GetUdidByNetworkId(mlInfo.deviceId);
}

string MediaLibraryDevice::GetNetworkIdBySelfId(const std::string &selfId)
{
    for (auto &[_, info] : deviceInfoMap_) {
        if (!selfId.compare(info.selfId)) {
            return info.selfId;
        }
    }
    MEDIA_ERR_LOG("GetNetworkIdBySelfId can not find selfId:%{private}s", selfId.c_str());
    return "";
}

bool MediaLibraryDevice::QueryDeviceTable()
{
    if (rdbStore_ != nullptr && mediaLibraryDeviceOperations_ != nullptr) {
        excludeMap_.clear();
        return mediaLibraryDeviceOperations_->QueryDeviceTable(rdbStore_, excludeMap_);
    }
    return false;
}

void MediaLibraryDevice::OnRemoteDied()
{
    MEDIA_INFO_LOG("dm instance died");
    UnRegisterFromDM();
    RegisterToDM();
}

void MediaLibraryDevice::RegisterToDM()
{
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    int errCode = deviceManager.InitDeviceManager(bundleName_, shared_from_this());
    if (errCode != 0) {
        MEDIA_ERR_LOG("RegisterToDm InitDeviceManager failed %{public}d", errCode);
    }

    std::string extra = "";
    errCode = deviceManager.RegisterDevStateCallback(bundleName_, extra, shared_from_this());
    if (errCode != 0) {
        MEDIA_ERR_LOG("RegisterDevStateCallback failed errCode %{public}d", errCode);
    }
    MEDIA_INFO_LOG("RegisterToDM success!");
}

void MediaLibraryDevice::UnRegisterFromDM()
{
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    int errCode = deviceManager.UnRegisterDevStateCallback(bundleName_);
    if (errCode != 0) {
        MEDIA_ERR_LOG("UnRegisterDevStateCallback failed errCode %{public}d", errCode);
    }
    errCode = deviceManager.UnInitDeviceManager(bundleName_);
    if (errCode != 0) {
        MEDIA_ERR_LOG("UnInitDeviceManager failed errCode %{public}d", errCode);
    }
    MEDIA_INFO_LOG("UnRegisterFromDM success");
}
} // namespace Media
} // namespace OHOS
