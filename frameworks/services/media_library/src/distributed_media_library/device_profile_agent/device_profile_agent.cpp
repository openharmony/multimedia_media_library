/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "device_profile_agent.h"
#include "distributed_device_profile_client.h"
#include "media_log.h"
#include "service_characteristic_profile.h"
#include "sync_options.h"

namespace OHOS {
namespace Media {
void from_json(const nlohmann::json &jsonObject, MedialibrayInfo &medialibraryInfo)
{
    if (jsonObject.find("medialibrary_version") != jsonObject.end()) {
        medialibraryInfo.version = jsonObject.at("medialibrary_version").get<int32_t>();
    }
}

DeviceProfileAgent::DeviceProfileAgent()
{
    MEDIA_INFO_LOG("DeviceProfileAgent::constructor");
    SubScribeMediaLibaryVersionEvent();
}

DeviceProfileAgent::~DeviceProfileAgent()
{
    MEDIA_INFO_LOG("DeviceProfileAgent::deconstructor");
    UnSubScribeMediaLibaryVersionEvent();
}

void DeviceProfileAgent::SubScribeMediaLibaryVersionEvent()
{
    // 订阅EVENT_SYNC_COMPLETED事件
    DeviceProfile::SubscribeInfo syncEventInfo;
    syncEventInfo.profileEvent = DeviceProfile::ProfileEvent::EVENT_SYNC_COMPLETED;
    std::list<DeviceProfile::SubscribeInfo> subscribeInfos;
    subscribeInfos.emplace_back(syncEventInfo);

    // 执行订阅接口
    std::list<DeviceProfile::ProfileEvent> fileEvents;
    int32_t ret = DeviceProfile::DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(
        subscribeInfos, shared_from_this(), fileEvents);
    MEDIA_INFO_LOG("DeviceProfileAgent::SubScribeMediaLibaryVersionEvent, ret %{public}d", ret);
}

void DeviceProfileAgent::UnSubScribeMediaLibaryVersionEvent()
{
    // 解除订阅
    std::list<DeviceProfile::ProfileEvent> subscribeInfos;
    subscribeInfos.emplace_back(DeviceProfile::ProfileEvent::EVENT_SYNC_COMPLETED);
    std::list<DeviceProfile::ProfileEvent> fileEvents;
    int32_t ret = DeviceProfile::DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(
        subscribeInfos, shared_from_this(), fileEvents);
    MEDIA_INFO_LOG("DeviceProfileAgent::UnSubScribeMediaLibaryVersionEvent, ret %{public}d", ret);
}

int32_t DeviceProfileAgent::SyncDeviceProfile(const std::string &deviceId)
{
    // 定义同步模式和范围
    // todo:此sync是阻塞的還是异步的？
    DeviceProfile::SyncOptions syncOption;
    DeviceProfile::SyncMode mode = DeviceProfile::SyncMode::PULL;
    syncOption.SetSyncMode(mode);
    syncOption.AddDevice(deviceId);

    MEDIA_INFO_LOG("DeviceProfileAgent::SyncDeviceProfile, ret %{public}s", deviceId.c_str());
    // 执行同步接口
    return DeviceProfile::DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOption, shared_from_this());
}

// 将媒体库版本信息put到dp数据库
int32_t DeviceProfileAgent::PutDeviceProfile(const int32_t version)
{
    DeviceProfile::ServiceCharacteristicProfile profile;
    profile.SetServiceId("com.ohos.medialibrary");  // system ?
    profile.SetServiceType("");
    nlohmann::json json;
    json["medialibrary_version"] = version; // "1.0";
    profile.SetCharacteristicProfileJson(json.dump());
    MEDIA_INFO_LOG("DeviceProfileAgent::PutDeviceProfile, version %{public}d", version);
    int32_t ret = DeviceProfile::DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    MEDIA_INFO_LOG("DeviceProfileAgent::PutDeviceProfile, ret %{public}d", ret);
    return ret;
}

 // 解析get到的profile
int32_t DeviceProfileAgent::GetDeviceProfile(const std::string &udid, int32_t &version)
{
    MEDIA_INFO_LOG("DeviceProfileAgent::GetDeviceProfile, udid %{public}s", udid.c_str());
    DeviceProfile::ServiceCharacteristicProfile profile;
    std::string serviceId;
    DeviceProfile::DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(udid, serviceId, profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData);

    version = jsonObject.at("medialibrary_version");
    MEDIA_INFO_LOG("DeviceProfileAgent::GetDeviceProfile, jsonData %{public}s", jsonData.c_str());
    return 0;
}
void DeviceProfileAgent::OnSyncCompleted(const DeviceProfile::SyncResult& syncResults)
{
    MEDIA_INFO_LOG("DeviceProfileAgent::OnSyncCompleted");
}

void DeviceProfileAgent::OnProfileChanged(const DeviceProfile::ProfileChangeNotification& changeNotification)
{
    MEDIA_INFO_LOG("DeviceProfileAgent::OnProfileChanged");
}
} // namespace Media
} // namespace OHOS