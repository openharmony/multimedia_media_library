/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryCommonEventUtils"

#include "common_event_utils.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "thermal_mgr_client.h"
#include "wifi_device.h"

using namespace std;

namespace OHOS {
namespace Media {
int32_t CommonEventUtils::GetThermalLevel()
{
    auto& thermalMgrClient = PowerMgr::ThermalMgrClient::GetInstance();
    return static_cast<int32_t>(thermalMgrClient.GetThermalLevel());
}

bool CommonEventUtils::IsWifiConnected()
{
    auto wifiDevicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevicePtr == nullptr) {
        MEDIA_ERR_LOG("wifiDevicePtr is null");
        return false;
    }
    bool isWifiConnected = false;
    int32_t ret = wifiDevicePtr->IsConnected(isWifiConnected);
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        MEDIA_ERR_LOG("Failed to get connected, ret: %{public}d", ret);
        return false;
    }
    if (!isWifiConnected) {
        MEDIA_WARN_LOG("Wifi is not connected, isWifiConnected: %{public}d", isWifiConnected);
    }
    return isWifiConnected;
}
} // namespace Media
} // namespace OHOS