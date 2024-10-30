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

#ifdef DEVICE_STANDBY_ENABLE
#include "medialibrary_standby_service_subscriber.h"

#include "medialibrary_data_manager.h"
#include "media_log.h"
#include "power_efficiency_manager.h"

using namespace std;

namespace OHOS {
namespace Media {

void MediaLibraryStandbyServiceSubscriber::OnPowerOverused(const std::string& module, uint32_t level)
{
    MEDIA_INFO_LOG("OnPowerOverused module:%{public}s, level:%{public}d", module.c_str(), level);
    if (level == EXTREME) {
        if (!PowerEfficiencyManager::IsChargingAndScreenOff()) {
            MEDIA_ERR_LOG("power consumption reaches 150%% of the threshold, InterruptBgworker.");
            MediaLibraryDataManager::GetInstance()->InterruptBgworker();
        }
    }
}

} // namespace Media
} // namespace OHOS
#endif