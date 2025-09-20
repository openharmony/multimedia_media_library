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
#include "media_system_api_permission_check.h"

using namespace std;

namespace OHOS::Media {
int32_t SystemApiPermissionCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("SystemApiPermissionCheck enter, API code=%{public}d", businessCode);
    CHECK_AND_RETURN_RET_LOG(PermissionUtils::IsSystemApp() || PermissionUtils::IsNativeSAApp(),
        -E_CHECK_SYSTEMAPP_FAIL, "Not system app or sa!");
    return E_SUCCESS;
}
} // namespace OHOS::Media
