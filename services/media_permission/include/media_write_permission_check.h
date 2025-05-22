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
#ifndef OHOS_MEDIALIBRARY_WRITE_PERMISSION_CHECK_H
#define OHOS_MEDIALIBRARY_WRITE_PERMISSION_CHECK_H

#include "media_permission_check.h"
#include "media_db_permission_check.h"
#include <vector>
#include <memory>

namespace OHOS::Media {
class WriteCompositePermCheck : public PermissionCheck {
private:
    std::vector<std::shared_ptr<PermissionCheck>> writeChecks_;
    std::mutex mutex_;
public:
    WriteCompositePermCheck();
    void AddCheck(std::shared_ptr<PermissionCheck> check);
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class WritePrivilegePermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class DbWritePermCheck : public PermissionCheck, public DbPermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class GrantWritePermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class MediaToolWritePermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class SecurityComponentPermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class DeprecatedWritePermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class ShortTermWritePermCheck : public PermissionCheck {
public:
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

} // namespace OHOS::Media
#endif  // OHOS_MEDIALIBRARY_WRITE_PERMISSION_CHECK_H