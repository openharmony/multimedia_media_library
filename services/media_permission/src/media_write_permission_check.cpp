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
#include "media_write_permission_check.h"
#include "media_file_utils.h"
#include "ipc_skeleton.h"
#ifdef MEDIALIBRARY_SECURITY_OPEN
#include "sec_comp_kit.h"
#endif
#include "parameters.h"
#include "access_token.h"
#include "media_app_uri_permission_column.h"

namespace OHOS::Media {
using namespace OHOS::Security::AccessToken;
static const int32_t GRANT_PERMISSION_CALLING_UID = 5523; // foundation调用方
static const int32_t ROOT_UID = 0;
static const int32_t HDC_SHELL_UID = 2000;
static int32_t AcrossLocalAccountsPermCheck(const PermissionHeaderReq &data);
WriteCompositePermCheck::WriteCompositePermCheck()
{
    auto writePrivilegePermCheck = std::make_shared<WritePrivilegePermCheck>();
    AddCheck(writePrivilegePermCheck);

    auto dbWritePermCheck = std::make_shared<DbWritePermCheck>();
    AddCheck(dbWritePermCheck);

    auto grantWritePermCheck = std::make_shared<GrantWritePermCheck>();
    AddCheck(grantWritePermCheck);

    auto mediaToolWritePermCheck = std::make_shared<MediaToolWritePermCheck>();
    AddCheck(mediaToolWritePermCheck);

    auto securityComponentPermCheck = std::make_shared<SecurityComponentPermCheck>();
    AddCheck(securityComponentPermCheck);

    auto shortTermWritePermCheck = std::make_shared<ShortTermWritePermCheck>();
    AddCheck(shortTermWritePermCheck);

    auto deprecatedWritePermCheck = std::make_shared<DeprecatedWritePermCheck>();
    AddCheck(deprecatedWritePermCheck);
}

void WriteCompositePermCheck::AddCheck(std::shared_ptr<PermissionCheck> check)
{
    std::lock_guard<std::mutex> lock(mutex_);
    writeChecks_.push_back(check);
}

int32_t WriteCompositePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("WriteCompositePermCheck enter, API code=%{public}d", businessCode);
    int32_t err = AcrossLocalAccountsPermCheck(data);
    if (err != E_SUCCESS) {
        return E_PERMISSION_DENIED;
    }
    if (isCalledBySelfPtr() == E_OK) {
        MEDIA_INFO_LOG("WriteCompositePermCheck isCalledBySelfPtr check success");
        return E_SUCCESS;
    }
    MEDIA_INFO_LOG("WriteCompositePermCheck isCalledBySelfPtr check fail");

    for (const auto& check : writeChecks_) {
        if (check->CheckPermission(businessCode, data) == E_SUCCESS) {
            return E_SUCCESS;
        }
    }
    
    return E_PERMISSION_DENIED;
}

int32_t WritePrivilegePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("WritePrivilegePermCheck enter, API code=%{public}d", businessCode);
    return PermissionUtils::CheckCallerPermission(PERM_WRITE_IMAGEVIDEO) ? E_SUCCESS : E_PERMISSION_DENIED;
}

int32_t DbWritePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("DbWritePermCheck enter, API code=%{public}d", businessCode);
    int32_t permissionType = 0;
    auto ret = DbPermissionCheck::GetPermissionType(businessCode, data, permissionType);
    if (ret != E_SUCCESS) {
        return ret;
    }
    return (AppUriPermissionColumn::PERMISSION_TYPE_WRITE.count(permissionType)) ? E_SUCCESS : E_PERMISSION_DENIED;
}

int32_t GrantWritePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("GrantWritePermCheck enter, API code=%{public}d", businessCode);
    if (PermissionCheck::grantOperationPermissionSet.find(businessCode) ==
        PermissionCheck::grantOperationPermissionSet.end()) {
        MEDIA_INFO_LOG("Not grant operation");
        return E_PERMISSION_DENIED;
    }
    if (getCallingUidPtr() == GRANT_PERMISSION_CALLING_UID ||
        getCallingUidPtr() == ROOT_UID) {
        MEDIA_INFO_LOG("GrantWritePermCheck callingUid check success");
        return E_SUCCESS;
    }
    MEDIA_INFO_LOG("GrantWritePermCheck callingUid check fail");
    return E_PERMISSION_DENIED;
}

int32_t MediaToolWritePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("MediaToolWritePermCheck enter, API code=%{public}d", businessCode);
    if (PermissionCheck::mediaToolOperationPermissionSet.find(businessCode) ==
        PermissionCheck::mediaToolOperationPermissionSet.end()) {
        MEDIA_INFO_LOG("Not media tool operation");
        return E_PERMISSION_DENIED;
    }
    if (getCallingUidPtr() != ROOT_UID && getCallingUidPtr() != HDC_SHELL_UID) {
        MEDIA_ERR_LOG("Mediatool permission check failed: target is not root");
        return E_PERMISSION_DENIED;
    }
    if (!OHOS::system::GetBoolParameter("const.security.developermode.state", true)) {
        MEDIA_ERR_LOG("Mediatool permission check failed: target is not in developer mode");
        return E_PERMISSION_DENIED;
    }
    return E_SUCCESS;
}

int32_t SecurityComponentPermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("SecurityComponentPermCheck enter, API code=%{public}d", businessCode);
#ifdef MEDIALIBRARY_SECURITY_OPEN
    auto tokenId = PermissionUtils::GetTokenId();
    if (!Security::SecurityComponent::SecCompKit::VerifySavePermission(tokenId)) {
        MEDIA_ERR_LOG("Failed to verify save permission of security component");
        return E_PERMISSION_DENIED;
    }
    return E_SUCCESS;
#else
    MEDIA_ERR_LOG("Security component is not existed");
    return E_PERMISSION_DENIED;
#endif
};

int32_t ShortTermWritePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("ShortTermWritePermCheck enter, API code=%{public}d", businessCode);
    if (PermissionUtils::CheckPhotoCallerPermission(PERM_SHORT_TERM_WRITE_IMAGEVIDEO)) {
        AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
        int err = Security::AccessToken::AccessTokenKit::GrantPermissionForSpecifiedTime(tokenCaller,
            PERM_SHORT_TERM_WRITE_IMAGEVIDEO, SHORT_TERM_PERMISSION_DURATION_300S);
        CHECK_AND_RETURN_RET_LOG(err >= 0, err, "GrantPermissionForSpecifiedTime errCode: %{public}d", err);
        return E_SUCCESS;
    }
    return E_PERMISSION_DENIED;
}

int32_t DeprecatedWritePermCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_INFO_LOG("DeprecatedWritePermCheck enter, API code=%{public}d", businessCode);
    if (PermissionCheck::deprecatedWritePermissionSet.find(businessCode) ==
        PermissionCheck::deprecatedWritePermissionSet.end()) {
        MEDIA_INFO_LOG("Unable to use deprecated write permission");
        return E_PERMISSION_DENIED;
    }
    return PermissionUtils::CheckCallerPermission(PERMISSION_NAME_WRITE_MEDIA) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t AcrossLocalAccountsPermCheck(const PermissionHeaderReq &data)
{
    int32_t userId = data.getUserId();
    if (userId == -1) {
        return E_SUCCESS;
    }
    std::vector<std::string> perms;
    perms.push_back(PERM_INTERACT_ACROSS_LOCAL_ACCOUNTS);
    return PermissionUtils::CheckCallerPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED;
}

} // namespace OHOS::Media
