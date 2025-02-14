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
#define MLOG_TAG "Distributed"

#include "device_permission_verification.h"
#include "device_auth.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_device.h"
#include "medialibrary_errno.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace Media {
using namespace std;
const std::string SAME_ACCOUNT_MARK = "const.distributed_file_only_for_same_account_test";

bool DevicePermissionVerification::CheckPermission(const std::string &udid)
{
    if (!CheckIsSameAccount()) {
        return false;
    }
    QueryTrustedRelationship(udid);
    return ReqDestDevSecLevel(udid);
}

bool DevicePermissionVerification::QueryTrustedRelationship(const std::string &udid)
{
    int ret = InitDeviceAuthService();
    if (ret != 0) {
        MEDIA_ERR_LOG("InitDeviceAuthService failed, ret %{public}d", ret);
        return false;
    }

    auto hichainDevGroupMgr_ = GetGmInstance();
    if (hichainDevGroupMgr_ == nullptr) {
        MEDIA_ERR_LOG("failed to get hichain device group manager");
        return false;
    }

    char *returnGroupVec = nullptr;
    uint32_t groupNum = 0;
    ret = hichainDevGroupMgr_->getRelatedGroups(ANY_OS_ACCOUNT, BUNDLE_NAME.c_str(), udid.c_str(),
        &returnGroupVec, &groupNum);
    if (ret != 0 || returnGroupVec == nullptr) {
        MEDIA_ERR_LOG("failed to get related groups, ret %{public}d", ret);
        return false;
    }

    if (groupNum == 0) {
        MEDIA_ERR_LOG("failed to get related groups, groupNum is %{public}u", groupNum);
        return false;
    }

    std::string groups = std::string(returnGroupVec);
    nlohmann::json jsonObject = nlohmann::json::parse(groups); // transform from cjson to cppjson
    if (jsonObject.is_discarded()) {
        MEDIA_INFO_LOG("returnGroupVec parse failed");
        return false;
    }

    std::vector<TrustedRelationshipGroupInfo> groupList;
    groupList = jsonObject.get<std::vector<TrustedRelationshipGroupInfo>>();
    for (auto &a : groupList) {
        MEDIA_INFO_LOG("group info:[groupName] %{private}s, [groupId] %{private}s, [groupType] %{private}d,",
                       a.groupName.c_str(), a.groupId.c_str(), a.groupType);
        if (a.groupType == PEER_TO_PEER_GROUP || a.groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
            return true;
        }
    }

    return false;
}

bool DevicePermissionVerification::CheckIsSameAccount()
{
    // because of there no same_account, only for test, del later
    bool ret = system::GetBoolParameter(SAME_ACCOUNT_MARK, false);
    MEDIA_INFO_LOG("SAME_ACCOUNT_MARK val is %{public}d", ret);
    return ret;
}

void DevicePermissionVerification::MLDevSecInfoCb(const DeviceIdentify *identify, struct DeviceSecurityInfo *info)
{
    int32_t level = 0;
    int32_t ret = GetDeviceSecurityLevelValue(info, &level);
    FreeDeviceSecurityInfo(info);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("get device sec level failed %{public}d", ret);
        return;
    }
    std::string udid(reinterpret_cast<char *>(const_cast<uint8_t *>(identify->identity)), identify->length);
    MediaLibraryDevice::GetInstance()->OnGetDevSecLevel(udid, level);
}

bool DevicePermissionVerification::ReqDestDevSecLevel(const std::string &udid)
{
    DeviceIdentify devIdentify;
    devIdentify.length = DEVICE_ID_MAX_LEN;
    int ret = memcpy_s(devIdentify.identity, DEVICE_ID_MAX_LEN, udid.c_str(), DEVICE_ID_MAX_LEN);
    if (ret != 0) {
        MEDIA_ERR_LOG("str copy failed %{public}d", ret);
    }
    ret = RequestDeviceSecurityInfoAsync(&devIdentify, nullptr, DevicePermissionVerification::MLDevSecInfoCb);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("request device sec info failed %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace Media
} // namespace OHOS
