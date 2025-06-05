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
#ifndef OHOS_MEDIALIBRARY_PERMISSION_CHECK_H
#define OHOS_MEDIALIBRARY_PERMISSION_CHECK_H

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <memory>
#include "medialibrary_business_code.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "permission_utils.h"
#include "datashare_helper.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "parcel.h"
#include "media_permission_header_req.h"
#include "media_file_utils.h"
#include "ipc_skeleton.h"
#include "media_permission_policy_type.h"

namespace OHOS::Media {
class PermissionCheck {
protected:
    bool needPermissionCheck_ = true;
    bool GetNeedPermissionCheck() const;
    void SetNeedPermissionCheck(bool needPermissionCheck);

    static std::unordered_map<PermissionType, std::shared_ptr<PermissionCheck>> permissionRegistry;
    // API blacklist for deprecated read or write permission
    static std::unordered_set<uint32_t> deprecatedReadPermissionSet;
    static std::unordered_set<uint32_t> deprecatedWritePermissionSet;
    // API whitelist for check grant operation permission
    static std::unordered_set<uint32_t> grantOperationPermissionSet;
    // API whitelist for check media tool operation permission
    static std::unordered_set<uint32_t> mediaToolOperationPermissionSet;

    static std::shared_ptr<PermissionCheck> BuildPermissionCheckChain(uint32_t businessCode,
        const PermissionHeaderReq &data);
    static int32_t VerifyOpenFilePermissions(uint32_t businessCode, const PermissionHeaderReq &data);
public:
    virtual ~PermissionCheck() = default;
    virtual int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) = 0;
    EXPORT static int32_t VerifyPermissions(uint32_t businessCode, const PermissionHeaderReq &data);
};

inline EXPORT bool (*isCalledBySelfPtr)() = MediaFileUtils::IsCalledBySelf;
inline EXPORT pid_t (*getCallingUidPtr)() = IPCSkeleton::GetCallingUid;
} // namespace OHOS::Media
#endif  // OHOS_MEDIALIBRARY_PERMISSION_CHECK_H