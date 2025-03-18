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

#include "medialibrary_device.h"
#include "device_permission_verification.h"
#include "device_auth.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_sync_operation.h"
#include "medialibrary_tracer.h"
#include "data_secondary_directory_uri.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
std::shared_ptr<MediaLibraryDevice> MediaLibraryDevice::mlDMInstance_ = nullptr;

constexpr int TRIM_LENGTH = 4;
constexpr int MIN_ACTIVE_DEVICE_NUMBER = 0;
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
    RegisterToDM();
    if (deviceHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("MediaLibraryDevice");
        deviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    devsInfoInter_ = make_shared<DevicesInfoInteract>();
    if (devsInfoInter_ != nullptr) {
        devsInfoInter_->Init();
        std::string local = "";
        localUdid_ = GetUdidByNetworkId(local);
        devsInfoInter_->PutMLDeviceInfos(localUdid_);
        isStart = true;
    } else {
        MEDIA_ERR_LOG("init devsInfoInter failed");
    }
}

void MediaLibraryDevice::Stop()
{
    MEDIA_DEBUG_LOG("Stop enter");
    UnRegisterFromDM();
    ClearAllDevices();
    isStart = false;
    devsInfoInter_ = nullptr;
    kvSyncDoneCv_.notify_all();
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

void MediaLibraryDevice::GetAllNetworkId(
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
    MEDIA_INFO_LOG("OnSyncCompleted dev id %{private}s, status %{public}d", devId.c_str(), status);
    std::unique_lock<std::mutex> lock(cvMtx_);
    kvSyncDoneCv_.notify_one();
}

void MediaLibraryDevice::TryToGetTargetDevMLInfos(const std::string &udid, const std::string &networkId)
{
    static constexpr int SLEEP_WAITOUT = 500;
    if (devsInfoInter_ == nullptr) {
        MEDIA_ERR_LOG("devsInfoInter_ is nullptr");
        return;
    }
    std::string version;
    bool ret = devsInfoInter_->GetMLDeviceInfos(udid, version);
    if (!ret) {
        MEDIA_INFO_LOG("get ml infos failed, so try to sync pull first, wait...");
        devsInfoInter_->SyncMLDeviceInfos(udid, networkId);
        {
            std::unique_lock<std::mutex> lock(cvMtx_);
            if (kvSyncDoneCv_.wait_for(lock, std::chrono::milliseconds(SLEEP_WAITOUT)) == std::cv_status::timeout) {
                MEDIA_DEBUG_LOG("get ml infos sync timeout");
            }
            if (!isStart) {
                MEDIA_ERR_LOG("MediaLibraryDevice is stopped, this thread will exit");
                return;
            }
        }
        MEDIA_DEBUG_LOG("get ml infos sync done, wakeup, try to get again");
        ret = devsInfoInter_->GetMLDeviceInfos(udid, version);
        if (!ret) {
            MEDIA_ERR_LOG("get ml infos failed again, maybe target dev have never init");
            return;
        }
    }
    lock_guard<std::mutex> lock(devMtx_);
    deviceInfoMap_[networkId].versionId = version;
    MEDIA_INFO_LOG("get dev %{private}s ml infos, version %{private}s",
        networkId.substr(0, TRIM_LENGTH).c_str(), version.c_str());
}

void MediaLibraryDevice::OnGetDevSecLevel(const std::string &udid, const int32_t devLevel)
{
    MEDIA_INFO_LOG("get dev %{public}s sec level %{public}d", udid.substr(0, TRIM_LENGTH).c_str(), devLevel);
    if (udid == localUdid_) {
        localDevLev_ = devLevel;
        localSecLevelGot_.store(true);
        localSecLevelDoneCv_.notify_all();
        MEDIA_INFO_LOG("get local dev sec level %{public}d, notify all wait pids", devLevel);
        return;
    }
    {
        std::unique_lock<std::mutex> cvlock(gotSecLevelMtx_);
        localSecLevelDoneCv_.wait(cvlock, [this] () { return localSecLevelGot_.load(); });
        MEDIA_INFO_LOG("wakeup, get other dev sec level %{public}d", devLevel);
    }

    if (localDevLev_ < devLevel || devLevel <= 0) {
        MEDIA_ERR_LOG("local dev's sec lev %{public}d is lower than dev %{private}s %{public}d, or level invalid!",
            localDevLev_, udid.substr(0, TRIM_LENGTH).c_str(), devLevel);
        return;
    }

    MediaLibraryDeviceInfo mldevInfo;
    bool findTargetDev {false};
    {
        lock_guard<mutex> lock(devMtx_);
        for (auto &[_, mlinfo] : deviceInfoMap_) {
            if (mlinfo.deviceUdid == udid) {
                mldevInfo = mlinfo;
                findTargetDev = true;
                break;
            }
        }
    }
    if (!findTargetDev) {
        MEDIA_ERR_LOG("not find this dev %{private}s in device map table", udid.substr(0, TRIM_LENGTH).c_str());
        return;
    }

    if (!MediaLibraryDeviceOperations::InsertDeviceInfo(rdbStore_, mldevInfo, bundleName_)) {
        MEDIA_ERR_LOG("OnDeviceOnline InsertDeviceInfo failed!");
        return;
    }

    lock_guard<mutex> lock(devMtx_);
    mldevInfo.devSecLevel = devLevel;
    deviceInfoMap_[mldevInfo.networkId] = mldevInfo;
}

void MediaLibraryDevice::DevOnlineProcess(const DistributedHardware::DmDeviceInfo &devInfo)
{
    if (!localSecLevelGot_.load()) {
        DevicePermissionVerification::ReqDestDevSecLevel(localUdid_);
    }
    MediaLibraryDeviceInfo mldevInfo;
    GetMediaLibraryDeviceInfo(devInfo, mldevInfo);
    {
        lock_guard<mutex> autoLock(devMtx_);
        deviceInfoMap_[devInfo.networkId] = mldevInfo;
    }

    if (!DevicePermissionVerification::CheckPermission(mldevInfo.deviceUdid)) {
        MEDIA_ERR_LOG("this dev has permission denied!");
        return;
    }

    MediaLibrarySyncOpts syncOpts;
    syncOpts.rdbStore = rdbStore_;
    syncOpts.kvStore = kvStore_;
    syncOpts.bundleName = bundleName_;
    std::vector<std::string> devices = { mldevInfo.networkId };
    MediaLibrarySyncOperation::SyncPullAllTableByNetworkId(syncOpts, devices);

    auto getTargetMLInfoTask = std::make_unique<std::thread>(
        [this, deviceUdid = mldevInfo.deviceUdid, networkId = mldevInfo.networkId]() {
        this->TryToGetTargetDevMLInfos(deviceUdid, networkId);
    });
    getTargetMLInfoTask->detach();
}

void MediaLibraryDevice::OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("dev online network id %{private}s", deviceInfo.networkId);
}

void MediaLibraryDevice::OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("OnDeviceOffline networkId = %{private}s", deviceInfo.networkId);

    if (deviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("OnDeviceOffline mediaLibraryDeviceHandler null");
        return;
    }
    auto nodeOffline = [this, deviceInfo]() {
        lock_guard<mutex> autoLock(devMtx_);
        std::string networkId = deviceInfo.networkId;
        auto info = deviceInfoMap_.find(networkId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("OnDeviceOffline can not find networkId:%{private}s", networkId.c_str());
            return;
        }

        MediaLibraryDeviceOperations::UpdateDeviceInfo(rdbStore_, info->second, bundleName_);
        deviceInfoMap_.erase(networkId);

        // 设备变更通知
        NotifyDeviceChange();
    };
    if (!deviceHandler_->PostTask(nodeOffline)) {
        MEDIA_ERR_LOG("OnDeviceOffline handler postTask failed");
    }
}

void MediaLibraryDevice::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("MediaLibraryDevice OnDeviceChanged called networkId = %{private}s", deviceInfo.networkId);
}

void MediaLibraryDevice::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_INFO_LOG("OnDeviceReady network id %{private}s", deviceInfo.networkId);
    if (deviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryDeviceHandler null");
        return;
    }

    auto nodeOnline = [this, deviceInfo]() {
        DevOnlineProcess(deviceInfo);
        NotifyDeviceChange();
    };
    if (!deviceHandler_->PostTask(nodeOnline)) {
        MEDIA_ERR_LOG("handler postTask failed");
    }
}

void MediaLibraryDevice::ClearAllDevices()
{
    lock_guard<mutex> autoLock(devMtx_);
    deviceInfoMap_.clear();
    excludeMap_.clear();
}

void MediaLibraryDevice::NotifyDeviceChange()
{
    auto contextUri = make_unique<Uri>(MEDIALIBRARY_DEVICE_URI);
    MediaLibraryDataManager::GetInstance()->NotifyChange(*contextUri);
}

void MediaLibraryDevice::NotifyRemoteFileChange()
{
    auto contextUri = make_unique<Uri>(MEDIALIBRARY_REMOTEFILE_URI);
    MediaLibraryDataManager::GetInstance()->NotifyChange(*contextUri);
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
    GetAllNetworkId(deviceList);
    MEDIA_INFO_LOG("MediaLibraryDevice InitDeviceRdbStore deviceList size = %{public}d", (int) deviceList.size());
    for (auto& deviceInfo : deviceList) {
        DevOnlineProcess(deviceInfo);
    }

    std::vector<OHOS::Media::MediaLibraryDeviceInfo> deviceDataBaseList;
    MediaLibraryDeviceOperations::GetAllDeviceData(rdbStore, deviceDataBaseList);
    for (auto deviceInfo : deviceDataBaseList) {
        if (!IsHasDevice(deviceInfo.deviceUdid)) {
            MediaLibraryDeviceOperations::UpdateDeviceInfo(rdbStore_, deviceInfo, bundleName_);
        }
    }
    MEDIA_INFO_LOG("deviceInfoMap size = %{public}d, deviceDataBaseList size = %{public}d",
        (int) deviceInfoMap_.size(), (int) deviceDataBaseList.size());
    return true;
}

bool MediaLibraryDevice::InitDeviceKvStore(const shared_ptr<DistributedKv::SingleKvStore> &kvStore)
{
    kvStore_ = kvStore;
    return kvStore_ != nullptr;
}

bool MediaLibraryDevice::UpdateDeviceSyncStatus(const std::string &networkId,
    const string &tableName, int32_t syncStatus)
{
    std::string udid;
    {
        lock_guard<mutex> autoLock(devMtx_);
        auto iter = deviceInfoMap_.find(networkId);
        if (iter == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("UpdateDeviceSyncStatus can not find networkId:%{private}s", networkId.c_str());
            return false;
        }
        udid = iter->second.deviceUdid;
    }
    return MediaLibraryDeviceOperations::UpdateSyncStatus(rdbStore_, udid, tableName, syncStatus);
}

bool MediaLibraryDevice::GetDeviceSyncStatus(const std::string &networkId, const std::string &tableName,
    int32_t &syncStatus)
{
    std::string udid;
    {
        lock_guard<mutex> autoLock(devMtx_);
        auto info = deviceInfoMap_.find(networkId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("GetDeviceSyncStatus can not find networkId:%{private}s", networkId.c_str());
            return false;
        }
        udid = info->second.deviceUdid;
    }
    return MediaLibraryDeviceOperations::GetSyncStatusById(rdbStore_, udid, tableName, syncStatus);
}

std::string MediaLibraryDevice::GetUdidByNetworkId(std::string &networkId)
{
    auto &deviceManager = DistributedHardware::DeviceManager::GetInstance();
    if (networkId.empty()) {
        OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
        auto ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
        if (ret != ERR_OK) {
            MEDIA_ERR_LOG("get local device info failed, ret %{public}d", ret);
            return "";
        }
        networkId = deviceInfo.networkId;
    }

    std::string deviceUdid;
    auto ret = deviceManager.GetUdidByNetworkId(bundleName_, networkId, deviceUdid);
    if (ret != 0) {
        MEDIA_INFO_LOG("GetDeviceUdid error networkId = %{private}s, ret %{public}d", networkId.c_str(), ret);
        return std::string();
    }
    return deviceUdid;
}

void MediaLibraryDevice::GetMediaLibraryDeviceInfo(const DistributedHardware::DmDeviceInfo &dmInfo,
    MediaLibraryDeviceInfo& mlInfo)
{
    mlInfo.networkId = dmInfo.networkId;
    mlInfo.deviceName = dmInfo.deviceName;
    mlInfo.deviceTypeId = dmInfo.deviceTypeId;
    mlInfo.deviceUdid = GetUdidByNetworkId(mlInfo.networkId);
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
    if (rdbStore_ == nullptr) {
        return false;
    }
    excludeMap_.clear();
    return MediaLibraryDeviceOperations::QueryDeviceTable(rdbStore_, excludeMap_);
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

void MediaLibraryDevice::GetDeviceInfoMap(unordered_map<string, MediaLibraryDeviceInfo> &outDeviceMap)
{
    outDeviceMap = deviceInfoMap_;
}

bool MediaLibraryDevice::QueryAgingDeviceInfos(vector<MediaLibraryDeviceInfo> &outDeviceInfos)
{
    return MediaLibraryDeviceOperations::GetAgingDeviceData(rdbStore_, outDeviceInfos);
}

bool MediaLibraryDevice::QueryAllDeviceUdid(vector<string> &deviceUdids)
{
    return MediaLibraryDeviceOperations::GetAllDeviceUdid(rdbStore_, deviceUdids);
}

bool MediaLibraryDevice::DeleteDeviceInfo(const string &udid)
{
    return MediaLibraryDeviceOperations::DeleteDeviceInfo(rdbStore_, udid);
}

bool MediaLibraryDevice::IsHasActiveDevice()
{
    lock_guard<mutex> autoLock(devMtx_);
    int deviceNumber = deviceInfoMap_.size();
    if (deviceNumber > MIN_ACTIVE_DEVICE_NUMBER) {
        MEDIA_DEBUG_LOG("device number = %{public}d", deviceNumber);
        return true;
    } else {
        return false;
    }
}
} // namespace Media
} // namespace OHOS