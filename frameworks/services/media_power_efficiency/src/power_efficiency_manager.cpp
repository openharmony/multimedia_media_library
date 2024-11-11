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

#include "power_efficiency_manager.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
constexpr int32_t NORMAL_INTERNVAL = 1000;
constexpr int32_t OVERLOAD_INTERNVAL = 2500;

int32_t PowerEfficiencyManager::sAlbumUpdateInterval_ = NORMAL_INTERNVAL;
PowerEfficiencyManager::PowerEfficiencyManager()
{
}

PowerEfficiencyManager::~PowerEfficiencyManager()
{
}

void PowerEfficiencyManager::UpdateAlbumUpdateInterval(bool isNormal)
{
    sAlbumUpdateInterval_ = isNormal ? NORMAL_INTERNVAL : OVERLOAD_INTERNVAL;
    MEDIA_INFO_LOG("update album interval: %{public}d", sAlbumUpdateInterval_);
}

int32_t PowerEfficiencyManager::GetAlbumUpdateInterval()
{
    return sAlbumUpdateInterval_;
}
} // namespace Media
} // namespace OHOS