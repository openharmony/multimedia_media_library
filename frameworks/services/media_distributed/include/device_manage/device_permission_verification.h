/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_DEVICE_PERMISSION_VERIFICATION_H
#define OHOS_MEDIALIBRARY_DEVICE_PERMISSION_VERIFICATION_H

#include <string>
#include <string>
#include "device_security_defines.h"
#include "device_security_info.h"

namespace OHOS {
namespace Media {
struct TrustedRelationshipGroupInfo {
    std::string groupName;
    std::string groupId;
    std::string groupOwner;
    int32_t groupType;
    TrustedRelationshipGroupInfo() : groupType(0) {}
    TrustedRelationshipGroupInfo(std::string name, std::string id, std::string owner, int32_t type)
        : groupName(name), groupId(id), groupOwner(owner), groupType(type)
    {
    }
};

class DevicePermissionVerification final {
public:
    DevicePermissionVerification() = delete;
    ~DevicePermissionVerification() = delete;
    DevicePermissionVerification(const DevicePermissionVerification&) = delete;
    DevicePermissionVerification(DevicePermissionVerification&&) = delete;
    DevicePermissionVerification& operator=(const DevicePermissionVerification&) = delete;
    DevicePermissionVerification& operator=(DevicePermissionVerification&&) = delete;

    static bool CheckPermission(const std::string &udid);
    static void MLDevSecInfoCb(const DeviceIdentify *identify, struct DeviceSecurityInfo *info);
    static bool ReqDestDevSecLevel(const std::string &udid);
private:
    static bool QueryTrustedRelationship(const std::string &udid);
    static bool CheckIsSameAccount();
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DEVICE_PERMISSION_VERIFICATION_H
