/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Upgrade"

#include "media_library_upgrade_task.h"

#include "media_log.h"
#include "medialibrary_upgrade_utils.h"

namespace OHOS {
namespace Media {

int32_t UpgradeTask::Execute(NativeRdb::RdbStore& store)
{
    MEDIA_INFO_LOG("Start upgrade task: %{public}s (version %{public}d)", name_.c_str(), version_);

    int32_t ret = upgradeFunc_(store);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade failed: %{public}s, error: %{public}d", name_.c_str(), ret);
        return ret;
    }

    MEDIA_INFO_LOG("Upgrade task completed: %{public}s (version %{public}d)", name_.c_str(), version_);
    return NativeRdb::E_OK;
}

int32_t UpgradeModuleTask::Execute(NativeRdb::RdbStore& store)
{
    MEDIA_INFO_LOG("Start upgrade task: %{public}s (version %{public}d)", name_.c_str(), version_);

    auto results = upgradeFunc_(store);
    if (results.empty()) {
        MEDIA_INFO_LOG("Upgrade task completed: %{public}s (version %{public}d)", name_.c_str(), version_);
        return NativeRdb::E_OK;
    }
    for (auto result : results) {
        // 打点
        RdbUpgradeUtils::AddUpgradeDfxMessages(this->GetVersion(), result.first, result.second);
    }

    return NativeRdb::E_ERROR;
}
} // namespace Media
} // namespace OHOS