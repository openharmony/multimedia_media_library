/* Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "device_auth.h"
#include "media_log.h"
#include "medialibrary_sync_table.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
const std::string SAME_ACCOUNT_MARK = "const.distributed_file_only_for_same_account_test";
const std::string ML_MULTIDEV_INFO_ID = "mediaLibrayMultiDevInfoFetch";
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
    dpa_ = make_unique<DeviceProfileAgent>();
    RegisterToDM();
    InitKvStore();
}

void MediaLibraryDevice::Stop()
{
    MEDIA_INFO_LOG("Stop enter");
    UnRegisterFromDM();
    ClearAllDevices();
    mediaLibraryDeviceOperations_ = nullptr;
    dataAbilityhelper_ = nullptr;
    dpa_ = nullptr;
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

void MediaLibraryDevice::InitKvStore()
{
    DistributedKv::DistributedKvDataManager kvManager;
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = true,
        .persistent = true,
        .backup = true,
        .autoSync = true,
        .securityLevel = DistributedKv::SecurityLevel::NO_LABEL,
        .syncPolicy = DistributedKv::SyncPolicy::HIGH,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION
    };
    DistributedKv::AppId appId = { BUNDLE_NAME };
    DistributedKv::StoreId storeId = { ML_MULTIDEV_INFO_ID };
    DistributedKv::Status status = kvManager.GetSingleKvStore(options, appId, storeId, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("KvStore get failed! %{public}d", status);
        return;
    }
    MEDIA_INFO_LOG("KvStore init success!");
    PutKvDB();
}

void MediaLibraryDevice::SyncKv(const std::string &udid, const std::string &devId)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return;
    }

    std::string key = udid + bundleName_;
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    std::vector<std::string> deviceIds = { devId };
    DistributedKv::Status status = kvStorePtr_->SyncWithCondition(deviceIds, DistributedKv::SyncMode::PULL, dataQuery);
    MEDIA_ERR_LOG("kvstore sync end, status %{public}d", status);
}

void MediaLibraryDevice::GetKvDB(const std::string &udid, std::string &val)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return;
    }

    std::string key = udid + bundleName_;

    DistributedKv::Key k(key);
    DistributedKv::Value v;
    DistributedKv::Status status = kvStorePtr_->Get(k, v);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("get kvstore failed %{public}d", status);
        val = MEDIA_LIBRARY_VERSION;
        return;
    }
    std::string versionInfo = v.ToString();
    nlohmann::json jsonObj = nlohmann::json::parse(versionInfo);
    if (jsonObj.is_discarded()) {
        MEDIA_ERR_LOG("parse json failed");
        val = MEDIA_LIBRARY_VERSION;
    }
    val = jsonObj.at("medialibrary_version");
    MEDIA_INFO_LOG("get kvstore success! key %{private}s, ml version info %{public}s, val %{public}s",
        key.c_str(), versionInfo.c_str(), val.c_str());
}

void MediaLibraryDevice::PutKvDB()
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return;
    }

    std::string devId = "";
    std::string key = GetUdidByNetworkId(devId) + bundleName_;
    nlohmann::json json;
    json["medialibrary_version"] = MEDIA_LIBRARY_VERSION;
    std::string val = json.dump();

    DistributedKv::Key k(key);
    DistributedKv::Value v(val);
    DistributedKv::Status status = kvStorePtr_->Put(k, v);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("put kvstore failed %{public}d", status);
        return;
    }
    MEDIA_INFO_LOG("put kvstore success!, key %{private}s, val %{private}s", key.c_str(), val.c_str());
}

void MediaLibraryDevice::SetAbilityContext(const std::shared_ptr<Context> &context)
{
    dataAbilityhelper_ = OHOS::AppExecFwk::DataAbilityHelper::Creator(context);
    MEDIA_INFO_LOG("MediaLibraryDevice::SetAbilityContext create dataAbilityhelper %{public}d",
        (dataAbilityhelper_ != nullptr));
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

bool MediaLibraryDevice::CheckPermission(const std::string &udid)
{
    if (CheckIsSameAccount()) {
        return true;
    }
    return QueryRelationship(udid); 
}

void MediaLibraryDevice::DevOnlineProcess(const DistributedHardware::DmDeviceInfo &devInfo)
{
    MediaLibraryDeviceInfo mldevInfo;
    GetMediaLibraryDeviceInfo(devInfo, mldevInfo);

    SyncKv(mldevInfo.deviceUdid, mldevInfo.deviceId);
    GetKvDB(mldevInfo.deviceUdid, mldevInfo.versionId);

    if (!CheckPermission(mldevInfo.deviceUdid)) {
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

    lock_guard<mutex> autoLock(deviceLock_);
    deviceInfoMap_[devInfo.deviceId] = mldevInfo;
    MEDIA_INFO_LOG("OnDeviceOnline cid %{public}s media library version %{public}s",
        mldevInfo.deviceId.c_str(), mldevInfo.versionId.c_str());

    NotifyDeviceChange();
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
    if (dataAbilityhelper_ != nullptr) {
        dataAbilityhelper_->NotifyChange(*contextUri);
        MEDIA_INFO_LOG("MediaLibraryDevice NotifyDeviceChange complete");
    }
}

void MediaLibraryDevice::NotifyRemoteFileChange()
{
    auto contextUri = make_unique<Uri>(MEDIALIBRARY_REMOTEFILE_URI);
    if (dataAbilityhelper_ != nullptr) {
        dataAbilityhelper_->NotifyChange(*contextUri);
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

void from_json(const nlohmann::json &jsonObject, GroupInfo &groupInfo)
{
    if (jsonObject.find(FIELD_GROUP_NAME) != jsonObject.end()) {
        groupInfo.groupName = jsonObject.at(FIELD_GROUP_NAME).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_ID) != jsonObject.end()) {
        groupInfo.groupId = jsonObject.at(FIELD_GROUP_ID).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_OWNER) != jsonObject.end()) {
        groupInfo.groupOwner = jsonObject.at(FIELD_GROUP_OWNER).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_TYPE) != jsonObject.end()) {
        groupInfo.groupType = jsonObject.at(FIELD_GROUP_TYPE).get<int32_t>();
    }
}

bool MediaLibraryDevice::QueryRelationship(const std::string &udid)
{
    int ret = InitDeviceAuthService();
    if (ret != 0) {
        MEDIA_ERR_LOG("InitDeviceAuthService failed, ret %{public}d", ret);
        return false;
    }

    auto hichainDevGroupMgr_ = GetGmInstance();
    if (hichainDevGroupMgr_ == nullptr) {
        MEDIA_ERR_LOG("failed to get hichain device group manager");
        return false;
    }

    char *returnGroupVec = nullptr;
    uint32_t groupNum = 0;
    ret = hichainDevGroupMgr_->getRelatedGroups(ANY_OS_ACCOUNT, bundleName_.c_str(), udid.c_str(),
        &returnGroupVec, &groupNum);
    if (ret != 0 || returnGroupVec == nullptr) {
        MEDIA_ERR_LOG("failed to get related groups, ret %{public}d", ret);
        return false;
    }

    if (groupNum == 0) {
        MEDIA_ERR_LOG("failed to get related groups, groupNum is %{public}u", groupNum);
        return false;
    }

    std::string groups = std::string(returnGroupVec);
    nlohmann::json jsonObject = nlohmann::json::parse(groups); // transform from cjson to cppjson
    if (jsonObject.is_discarded()) {
        MEDIA_INFO_LOG("returnGroupVec parse failed");
        return false;
    }

    std::vector<GroupInfo> groupList;
    groupList = jsonObject.get<std::vector<GroupInfo>>();
    for (auto &a : groupList) {
        MEDIA_INFO_LOG("group info:[groupName] %{public}s, [groupId] %{public}s, [groupType] %{public}d,",
                       a.groupName.c_str(), a.groupId.c_str(), a.groupType);
        if (a.groupType == PEER_TO_PEER_GROUP || a.groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
            return true;
	}
    }

    return false;
}

bool MediaLibraryDevice::CheckIsSameAccount()
{
    // because of there no same_account, only for test, del later
    bool ret = system::GetBoolParameter(SAME_ACCOUNT_MARK, false); 
    MEDIA_INFO_LOG("SAME_ACCOUNT_MARK val is %{public}d", ret);
    return ret;
}
} // namespace Media
} // namespace OHOS
