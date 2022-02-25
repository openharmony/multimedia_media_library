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

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;

MediaLibraryDevice::MediaLibraryDevice()
{
    if (mediaLibraryDeviceOperations_ == nullptr) {
        mediaLibraryDeviceOperations_ = std::make_unique<MediaLibraryDeviceOperations>();
    }

    if (mediaLibraryDeviceHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("MediaLibraryDevice");
        mediaLibraryDeviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
}

MediaLibraryDevice::~MediaLibraryDevice()
{
    mediaLibraryDeviceOperations_ = nullptr;
    dataAbilityhelper_ = nullptr;
}

MediaLibraryDevice *MediaLibraryDevice::GetInstance()
{
    static MediaLibraryDevice mediaLibraryDevice;
    return &mediaLibraryDevice;
}

void MediaLibraryDevice::SetAbilityContext(const std::shared_ptr<Context> &context)
{
    dataAbilityhelper_ = OHOS::AppExecFwk::DataAbilityHelper::Creator(context);
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice::SetAbilityContext create dataAbilityhelper %{public}d",
        (dataAbilityhelper_ != nullptr));
}

void MediaLibraryDevice::GetAllDeviceId(
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> &deviceList, std::string &bundleName)
{
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice::GetAllDeviceId IN");
    std::string extra = "";
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    deviceManager.GetTrustedDeviceList(bundleName, extra, deviceList);
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice::GetAllDeviceId OUT");
}

void MediaLibraryDevice::OnDeviceOnline(
    const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo, const std::string &bundleName)
{
    MEDIA_ERR_LOG("@@@@@OnDeviceOnline deviceId = %{public}s", deviceInfo.deviceId);

    if (mediaLibraryDeviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("@@@@@OnDeviceOnline mediaLibraryDeviceHandler null");
        return;
    }
    auto nodeOnline = [this, deviceInfo, bundleName]() {
        // 更新数据库
        if (mediaLibraryDeviceOperations_ != nullptr) {
            OHOS::Media::MediaLibraryDeviceInfo mediaLibraryDeviceInfo;
            GetMediaLibraryDeviceInfo(deviceInfo, mediaLibraryDeviceInfo, bundleName);
            if (!mediaLibraryDeviceOperations_->InsertDeviceInfo(rdbStore_, mediaLibraryDeviceInfo, bundleName)) {
                MEDIA_ERR_LOG("@@@@@OnDeviceOnline InsertDeviceInfo failed!");
                return;
            }
            lock_guard<mutex> autoLock(deviceLock_);
            deviceInfoMap_[deviceInfo.deviceId] = mediaLibraryDeviceInfo;
        } else {
            MEDIA_ERR_LOG("@@@@@OnDeviceOnline InsertDeviceInfo failed mediaLibraryDeviceOperations_ = null !");
            return;
        }
        // 设备变更通知
        NotifyDeviceChange();
    };
    if (!mediaLibraryDeviceHandler_->PostTask(nodeOnline)) {
        MEDIA_ERR_LOG("@@@@@OnDeviceOnline handler postTask failed");
    }
}

void MediaLibraryDevice::OnDeviceOffline(
    const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo, const std::string &bundleName)
{
    MEDIA_ERR_LOG("@@@@@OnDeviceOffline deviceId = %{public}s", deviceInfo.deviceId);

    if (mediaLibraryDeviceHandler_ == nullptr) {
        MEDIA_ERR_LOG("@@@@@OnDeviceOffline mediaLibraryDeviceHandler null");
        return;
    }
    auto nodeOffline = [this, deviceInfo, bundleName]() {
        lock_guard<mutex> autoLock(deviceLock_);
        std::string devId = deviceInfo.deviceId;
        auto info = deviceInfoMap_.find(devId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("@@@@@OnDeviceOffline can not find deviceId:%{public}s", devId.c_str());
            return;
        }
        if (mediaLibraryDeviceOperations_ != nullptr) {
            mediaLibraryDeviceOperations_->UpdateDeviceInfo(rdbStore_, info->second, bundleName);
        }
        deviceInfoMap_.erase(devId);

        // 设备变更通知
        NotifyDeviceChange();
    };
    if (!mediaLibraryDeviceHandler_->PostTask(nodeOffline)) {
        MEDIA_ERR_LOG("@@@@@OnDeviceOffline handler postTask failed");
    }
}

void MediaLibraryDevice::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice OnDeviceChanged called deviceId = %{public}s", deviceInfo.deviceId);
}

void MediaLibraryDevice::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice OnDeviceReady called deviceId = %{public}s", deviceInfo.deviceId);
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
    if (dataAbilityhelper_ != nullptr) {
        dataAbilityhelper_->NotifyChange(*contextUri);
        MEDIA_INFO_LOG("@@@@@MediaLibraryDevice NotifyDeviceChange complete");
    }
}

bool MediaLibraryDevice::IsHasDevice(string deviceUdid)
{
    map<string, MediaLibraryDeviceInfo>::iterator iter;
    iter = deviceInfoMap_.begin();
    while(iter != deviceInfoMap_.end()) {
        MEDIA_ERR_LOG("@@@@@GetNetworkIdBySelfId iter->second.selfId:%{public}s", iter->second.deviceUdid.c_str());
        if (deviceUdid.compare (iter->second.deviceUdid) == 0) {
            return true;
        }
        iter++;
    }
    return false;
}

bool MediaLibraryDevice::InitDeviceRdbStore(const shared_ptr<NativeRdb::RdbStore> &rdbStore, std::string &bundleName)
{
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice InitDeviceRdbStore IN");
    rdbStore_ = rdbStore;
    if (!QueryDeviceTable()) {
        MEDIA_ERR_LOG("@@@@@MediaLibraryDevice InitDeviceRdbStore QueryDeviceTable fail!");
        return false;
    }
    // 获取同一网络中的所有设备Id
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    GetAllDeviceId(deviceList, bundleName);
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice InitDeviceRdbStore deviceList size = %{public}d", (int) deviceList.size());
    for (auto& deviceInfo : deviceList) {
        OHOS::Media::MediaLibraryDeviceInfo mediaLibraryDeviceInfo;
        GetMediaLibraryDeviceInfo(deviceInfo, mediaLibraryDeviceInfo, bundleName);
        if (mediaLibraryDeviceOperations_ != nullptr &&
            mediaLibraryDeviceOperations_->InsertDeviceInfo(rdbStore_, mediaLibraryDeviceInfo, bundleName)) {
            lock_guard<mutex> autoLock(deviceLock_);
            deviceInfoMap_[deviceInfo.deviceId] = mediaLibraryDeviceInfo;
        }
    }

    std::vector<OHOS::Media::MediaLibraryDeviceInfo> deviceDataBaseList;
    mediaLibraryDeviceOperations_->GetAllDeviceDatas(rdbStore, deviceDataBaseList);
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice InitDeviceRdbStore deviceDataBaseList size = %{public}d", (int) deviceDataBaseList.size());
    for (OHOS::Media::MediaLibraryDeviceInfo deviceInfo : deviceDataBaseList) {
        if (!IsHasDevice(deviceInfo.deviceUdid)) {
            if (mediaLibraryDeviceOperations_ != nullptr) {
                mediaLibraryDeviceOperations_->UpdateDeviceInfo(rdbStore_, deviceInfo, bundleName);
            }
        }
    }
    MEDIA_ERR_LOG("@@@@@MediaLibraryDevice InitDeviceRdbStore OUT deviceInfoMap size = %{public}d",
        (int) deviceInfoMap_.size());
    return true;
}

bool MediaLibraryDevice::UpdateDevicieSyncStatus(
    const std::string &deviceId, int32_t syncStatus, const std::string &bundleName)
{
    if (mediaLibraryDeviceOperations_ != nullptr) {
        lock_guard<mutex> autoLock(deviceLock_);
        auto info = deviceInfoMap_.find(deviceId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("@@@@@UpdateDevicieSyncStatus can not find deviceId:%{public}s", deviceId.c_str());
            return false;
        }
        return mediaLibraryDeviceOperations_->UpdateSyncStatus(rdbStore_, info->second.deviceUdid, syncStatus,
                                                               bundleName);
    }
    return false;
}

bool MediaLibraryDevice::GetDevicieSyncStatus(const std::string &deviceId, int32_t &syncStatus,
                                              const std::string &bundleName)
{
    if (mediaLibraryDeviceOperations_ != nullptr) {
        lock_guard<mutex> autoLock(deviceLock_);
        auto info = deviceInfoMap_.find(deviceId);
        if (info == deviceInfoMap_.end()) {
            MEDIA_ERR_LOG("@@@@@GetDevicieSyncStatus can not find deviceId:%{public}s", deviceId.c_str());
            return false;
        }
        return mediaLibraryDeviceOperations_->GetSyncStatusById(rdbStore_, deviceId, syncStatus,
                                                                bundleName);
    }
    return false;
}

std::string MediaLibraryDevice::GetUdidByNetworkId(const std::string &deviceId, const std::string &bundleName)
{
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    std::string deviceUdid;
    auto ret = deviceManager.GetUdidByNetworkId(bundleName, deviceId, deviceUdid);
    if (ret != 0) {
        MEDIA_ERR_LOG("GetDeviceUdid error deviceId = %{public}s", deviceId.c_str());
        return std::string();
    }
    return deviceUdid;
}

void MediaLibraryDevice::GetMediaLibraryDeviceInfo(const OHOS::DistributedHardware::DmDeviceInfo &dmInfo,
                                                   OHOS::Media::MediaLibraryDeviceInfo& mlInfo,
                                                   const std::string &bundleName)
{
    mlInfo.deviceId = dmInfo.deviceId;
    mlInfo.deviceName = dmInfo.deviceName;
    mlInfo.deviceTypeId = dmInfo.deviceTypeId;
    mlInfo.deviceUdid = GetUdidByNetworkId(mlInfo.deviceId, bundleName);
    //mlInfo.selfId = GenerateSelfId(mlInfo.deviceUdid);
}

string MediaLibraryDevice::GetNetworkIdBySelfId(const std::string &selfId, const std::string &bundleName)
{
    MEDIA_ERR_LOG("@@@@@GetNetworkIdBySelfId can not find selfId:%{public}s", selfId.c_str());

    map<string, MediaLibraryDeviceInfo>::iterator iter;
    iter = deviceInfoMap_.begin();
    while(iter != deviceInfoMap_.end()) {
        MEDIA_ERR_LOG("@@@@@GetNetworkIdBySelfId iter->second.selfId:%{public}s", iter->second.selfId.c_str());
        if (selfId.compare (iter->second.selfId) == 0) {
            return iter->second.deviceId;
        }
        iter++;
    }
    return "";
}

std::string MediaLibraryDevice::GenerateSelfId(const std::string &deviceUdid)
{
    if (deviceUdid.empty()) {
        return std::string();
    }

    std::string selfId = deviceUdid;
    if (selfId.length() > SHORT_UDID_LEN) {
        selfId = deviceUdid.substr(0, SHORT_UDID_LEN);
    }

    auto &randSet = excludeMap_[selfId];
    if (randSet.empty()) {
        int32_t randNum = (int32_t) (rand() % RANDOM_NUM);
        randSet.insert(randNum);
        selfId.append(std::to_string(randNum));
        return selfId;
    }

    if ((int32_t) randSet.size() >= RANDOM_NUM) {
        int32_t randNum = (int32_t) randSet.size();
        randSet.insert(randNum);
        selfId.append(std::to_string(randNum));
    } else {
        std::vector<int32_t> tmpVec;
        for (int32_t i = 0; i < RANDOM_NUM; ++i) {
            tmpVec.push_back(i);
        }

        for (auto &id : randSet) {
            auto iter = std::find(tmpVec.begin(), tmpVec.end(), id);
            if (iter != tmpVec.end()) {
                tmpVec.erase(iter);
            }
        }
        int32_t randNum = tmpVec[(rand() % (int32_t) tmpVec.size())];
        randSet.insert(randNum);
        selfId.append(std::to_string(randNum));
    }

    return selfId;
}

bool MediaLibraryDevice::QueryDeviceTable()
{
    if (rdbStore_ != nullptr && mediaLibraryDeviceOperations_ != nullptr) {
        excludeMap_.clear();
        return mediaLibraryDeviceOperations_->QueryDeviceTable(rdbStore_, excludeMap_);
    }
    return false;
}
} // namespace Media
} // namespace OHOS
