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

#include "access_token.h"
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

bool g_hasDelayTask;
std::mutex AddPhotoPermissionRecordLock_;
std::thread DelayTask_;
std::vector<Security::AccessToken::AddPermParamInfo> infos;

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

void PermissionUtils::GetClientBundle(const int uid, string &bundleName)
{
    bundleMgr_ = GetSysBundleManager();
    if (bundleMgr_ == nullptr) {
        bundleName = "";
        return;
    }
    auto result = bundleMgr_->GetBundleNameForUid(uid, bundleName);
    if (!result) {
        bundleName = "";
    }
}

bool inline ShouldAddPermissionRecord(const AccessTokenID &token)
{
    return (AccessTokenKit::GetTokenTypeFlag(token) == TOKEN_HAP);
}

void AddPermissionRecord(const AccessTokenID &token, const string &perm, const bool permGranted)
{
    if (!ShouldAddPermissionRecord(token)) {
        return;
    }

    int res = PrivacyKit::AddPermissionUsedRecord(token, perm, !!permGranted, !permGranted, true);
    if (res != 0) {
        /* Failed to add permission used record, not fatal */
        MEDIA_WARN_LOG("Failed to add permission used record: %{public}s, permGranted: %{public}d, err: %{public}d",
            perm.c_str(), permGranted, res);
    }
}

vector<AddPermParamInfo> GetPermissionRecord()
{
    lock_guard<mutex> lock(AddPhotoPermissionRecordLock_);
    vector<AddPermParamInfo> result = infos;
    infos.clear();
    return result;
}

void AddPermissionRecord()
{
    vector<AddPermParamInfo> infos = GetPermissionRecord();
    for (const auto &info : infos) {
        int32_t ret = PrivacyKit::AddPermissionUsedRecord(info, true);
        if (ret != 0) {
            /* Failed to add permission used record, not fatal */
            MEDIA_WARN_LOG("Failed to add permission used record: %{public}s, permGranted: %{public}d, err: %{public}d",
                info.permissionName.c_str(), info.successCount, ret);
        }
    }
    infos.clear();
}

void DelayAddPermissionRecord()
{
    string name("DelayAddPermissionRecord");
    pthread_setname_np(pthread_self(), name.c_str());
    MEDIA_DEBUG_LOG("DelayTask start");
    std::this_thread::sleep_for(std::chrono::minutes(1));
    AddPermissionRecord();
    g_hasDelayTask = false;
    MEDIA_DEBUG_LOG("DelayTask end");
}

void DelayTaskInit()
{
    if (!g_hasDelayTask) {
        MEDIA_DEBUG_LOG("DelayTaskInit");
        DelayTask_ = thread(DelayAddPermissionRecord);
        DelayTask_.detach();
        g_hasDelayTask = true;
    }
}

void CollectPermissionRecord(const AccessTokenID &token, const string &perm,
    const bool permGranted, const PermissionUsedType type)
{
    lock_guard<mutex> lock(AddPhotoPermissionRecordLock_);
    DelayTaskInit();

    if (!ShouldAddPermissionRecord(token)) {
        return;
    }

    AddPermParamInfo info = {token, perm, permGranted, !permGranted, type};
    infos.push_back(info);
}

void PermissionUtils::CollectPermissionInfo(const string &permission,
    const bool permGranted, const PermissionUsedType type)
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    CollectPermissionRecord(tokenCaller, permission, permGranted, type);
}

bool PermissionUtils::CheckPhotoCallerPermission(const string &permission)
{
    PermissionUsedType type = PermissionUsedTypeValue::NORMAL_TYPE;
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int res = AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    if (res != PermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("Have no media permission: %{public}s", permission.c_str());
        CollectPermissionRecord(tokenCaller, permission, false, type);
        return false;
    }
    CollectPermissionRecord(tokenCaller, permission, true, type);
    return true;
}

bool PermissionUtils::CheckPhotoCallerPermission(const vector<string> &perms)
{
    if (perms.empty()) {
        return false;
    }

    for (const auto &perm : perms) {
        if (!CheckPhotoCallerPermission(perm)) {
            return false;
        }
    }
    return true;
}

bool PermissionUtils::CheckCallerPermission(const string &permission)
{
    MediaLibraryTracer tracer;
    tracer.Start("CheckCallerPermission");

    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int res = AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    if (res != PermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("Have no media permission: %{public}s", permission.c_str());
        AddPermissionRecord(tokenCaller, permission, false);
        return false;
    }
    AddPermissionRecord(tokenCaller, permission, true);

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

bool PermissionUtils::CheckIsSystemAppByUid()
{
    int uid = IPCSkeleton::GetCallingUid();
    bundleMgr_ = GetSysBundleManager();
    if (bundleMgr_ == nullptr) {
        MEDIA_ERR_LOG("Can not get bundleMgr");
        return false;
    }
    return bundleMgr_->CheckIsSystemAppByUid(uid);
}

bool PermissionUtils::IsNativeSAApp()
{
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    MEDIA_DEBUG_LOG("check if native sa token, tokenId:%{public}d, tokenType:%{public}d",
        tokenId, tokenType);
    if (tokenType == ATokenTypeEnum::TOKEN_NATIVE) {
        return true;
    }
    return false;
}

bool PermissionUtils::IsRootShell()
{
    return IPCSkeleton::GetCallingUid() == 0;
}

string PermissionUtils::GetPackageNameByBundleName(const string &bundleName)
{
    const static int32_t INVALID_UID = -1;
    const static int32_t BASE_USER_RANGE = 200000;
    
    int uid = IPCSkeleton::GetCallingUid();
    if (uid <= INVALID_UID) {
        MEDIA_ERR_LOG("Get INVALID_UID UID %{public}d", uid);
        return "";
    }
    int32_t userId = uid / BASE_USER_RANGE;
    MEDIA_DEBUG_LOG("uid:%{private}d, userId:%{private}d", uid, userId);

    AAFwk::Want want;
    auto bundleMgr_ = GetSysBundleManager();
    if (bundleMgr_ == nullptr) {
        MEDIA_ERR_LOG("Get BundleManager failed");
        return "";
    }
    int ret = bundleMgr_->GetLaunchWantForBundle(bundleName, want, userId);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("Can not get bundleName by want, err=%{public}d, userId=%{private}d",
            ret, userId);
        return "";
    }
    string abilityName = want.GetOperation().GetAbilityName();
    return bundleMgr_->GetAbilityLabel(bundleName, abilityName);
}

string PermissionUtils::GetAppIdByBundleName(const string &bundleName)
{
    int uid = IPCSkeleton::GetCallingUid();
    if (uid <= INVALID_UID) {
        MEDIA_ERR_LOG("Get INVALID_UID UID %{public}d", uid);
        return "";
    }
    int32_t userId = uid / BASE_USER_RANGE;
    MEDIA_DEBUG_LOG("uid:%{private}d, userId:%{private}d", uid, userId);

    auto bundleMgr_ = GetSysBundleManager();
    if (bundleMgr_ == nullptr) {
        MEDIA_ERR_LOG("Get BundleManager failed");
        return "";
    }
    return bundleMgr_->GetAppIdByBundleName(bundleName, userId);
}
}  // namespace Media
}  // namespace OHOS
