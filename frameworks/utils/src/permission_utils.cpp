/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "permission_utils.h"

#include <unordered_set>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "privacy_kit.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AppExecFwk::Constants;

sptr<AppExecFwk::IBundleMgr> PermissionUtils::bundleMgr_ = nullptr;
mutex PermissionUtils::bundleMgrMutex_;
sptr<AppExecFwk::IBundleMgr> PermissionUtils::GetSysBundleManager()
{
    if (bundleMgr_ != nullptr) {
        return bundleMgr_;
    }

    lock_guard<mutex> lock(bundleMgrMutex_);
    if (bundleMgr_ != nullptr) {
        return bundleMgr_;
    }

    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get SystemAbilityManager.");
        return nullptr;
    }

    auto bundleObj = systemAbilityMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleObj == nullptr) {
        MEDIA_ERR_LOG("Remote object is nullptr.");
        return nullptr;
    }

    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
    if (bundleMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to iface_cast");
        return nullptr;
    }
    bundleMgr_ = bundleMgr;

    return bundleMgr_;
}

void PermissionUtils::GetClientBundle(const int uid, string &bundleName, bool &isSystemApp)
{
    bundleMgr_ = GetSysBundleManager();
    if (bundleMgr_ == nullptr) {
        bundleName = "";
        isSystemApp = false;
        return;
    }
    auto result = bundleMgr_->GetBundleNameForUid(uid, bundleName);
    if (!result) {
        MEDIA_ERR_LOG("GetBundleNameForUid fail");
        bundleName = "";
    }
    isSystemApp = bundleMgr_->CheckIsSystemAppByUid(uid);
}

string PermissionUtils::GetClientBundleName()
{
    int uid = IPCSkeleton::GetCallingUid();
    string clientBundle;
    bool isSystemApp = false;
    GetClientBundle(uid, clientBundle, isSystemApp);
    return clientBundle;
}

#ifdef OHOS_DEBUG
bool inline ShouldAddPermissionRecord(const AccessTokenID &token)
{
    return (AccessTokenKit::GetTokenTypeFlag(token) == TOKEN_HAP);
}

void AddPermissionRecord(const AccessTokenID &token, const string &perm, const bool permGranted)
{
    if (!ShouldAddPermissionRecord(token)) {
        return;
    }

    int res = PrivacyKit::AddPermissionUsedRecord(token, perm, !!permGranted, !permGranted);
    if (res != 0) {
        /* Failed to add permission used record, not fatal */
        MEDIA_WARN_LOG("Failed to add permission used record: %{public}s, permGranted: %{public}d, err: %{public}d",
            perm.c_str(), permGranted, res);
    }
}
#endif

bool PermissionUtils::CheckCallerPermission(const string &permission)
{
    MediaLibraryTracer tracer;
    tracer.Start("CheckCallerPermission");

    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int res = AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    if (res != PermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("Have no media permission: %{public}s", permission.c_str());
#ifdef OHOS_DEBUG
        AddPermissionRecord(tokenCaller, permission, false);
#endif
        return false;
    }
#ifdef OHOS_DEBUG
    AddPermissionRecord(tokenCaller, permission, true);
#endif

    return true;
}

/* Check whether caller has at least one of @perms */
bool PermissionUtils::CheckHasPermission(const vector<string> &perms)
{
    if (perms.empty()) {
        return false;
    }

    for (const auto &perm : perms) {
        if (CheckCallerPermission(perm)) {
            return true;
        }
    }

    return false;
}

/* Check whether caller has all the @perms */
bool PermissionUtils::CheckCallerPermission(const vector<string> &perms)
{
    if (perms.empty()) {
        return false;
    }

    for (const auto &perm : perms) {
        if (!CheckCallerPermission(perm)) {
            return false;
        }
    }
    return true;
}

uint32_t PermissionUtils::GetTokenId()
{
    return IPCSkeleton::GetCallingTokenID();
}

bool PermissionUtils::IsSystemApp()
{
    uint64_t tokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}
}  // namespace Media
}  // namespace OHOS
