/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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
#define MLOG_TAG "MediaPermissionCheck"
#include <string>
#include "media_composite_permission_check.h"

using namespace std;

namespace OHOS::Media {
void CompositePermissionCheck::AddCheck(std::shared_ptr<SinglePermissionCheck> check)
{
    std::lock_guard<std::mutex> lock(mutex_);
    compositePermChecks_.push_back(check);
}

int32_t CompositePermissionCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("CompositePermissionCheck API code=%{public}d", businessCode);
    int32_t ret = E_SUCCESS;
    for (const auto& check : compositePermChecks_) {
        ret = check->CheckPermission(businessCode, data);
        if (ret == E_SUCCESS) {
            MEDIA_INFO_LOG("CompositePermissionCheck API code=%{public}d success", businessCode);
            return E_SUCCESS;
        } else {
            MEDIA_INFO_LOG("CompositePermissionCheck API code=%{public}d check fail, Try next", businessCode);
        }
    }
    MEDIA_INFO_LOG("CompositePermissionCheck API code=%{public}d fail", businessCode);
    return ret;
}

void SinglePermissionCheck::AddCheck(std::shared_ptr<PermissionCheck> check)
{
    std::lock_guard<std::mutex> lock(mutex_);
    singlePermChecks_.push_back(check);
}

int32_t SinglePermissionCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& check : singlePermChecks_) {
        auto ret = check->CheckPermission(businessCode, data);
        if (ret != E_SUCCESS) {
            return E_PERMISSION_DENIED;
        }
    }
    return ret;
}

} // namespace OHOS::Media
