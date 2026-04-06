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

#include "media_library_upgrade_observer.h"

#include "media_log.h"

namespace OHOS {
namespace Media {

void DefaultUpgradeObserver::OnUpgradeStart(const std::shared_ptr<IUpgradeTask>& task)
{
    MEDIA_INFO_LOG("Upgrade started: %{public}s (version %{public}d)",
                   task->GetName().c_str(), task->GetVersion());
}

void DefaultUpgradeObserver::OnUpgradeComplete(const std::shared_ptr<IUpgradeTask>& task, int32_t ret)
{
    if (ret == NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Upgrade completed: %{public}s (version %{public}d)",
                       task->GetName().c_str(), task->GetVersion());
    } else {
        MEDIA_ERR_LOG("Upgrade failed: %{public}s (version %{public}d), error: %{public}d",
                      task->GetName().c_str(), task->GetVersion(), ret);
    }
}

void DefaultUpgradeObserver::OnUpgradeProgress(int32_t currentVersion,
    int32_t targetVersion, int32_t completedCount, int32_t totalCount)
{
    MEDIA_INFO_LOG("Upgrade progress: %{public}d/%{public}d tasks completed "
                   "(version %{public}d -> %{public}d)",
                   completedCount, totalCount, currentVersion, targetVersion);
}

} // namespace Media
} // namespace OHOS