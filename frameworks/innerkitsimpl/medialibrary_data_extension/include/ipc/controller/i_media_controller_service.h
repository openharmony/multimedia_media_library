/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_IPC_I_MEDIA_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_IPC_I_MEDIA_CONTROLLER_SERVICE_H

#include "message_parcel.h"
#include "datashare_stub.h"
#include "ipc_context.h"
#include "media_permission_policy_type.h"

namespace OHOS::Media::IPC {
class IMediaControllerService {
public:
    virtual bool Accept(uint32_t code) = 0;
    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, IPCContext &context) = 0;
    // If policy returns a value other than E_SUCCESS, access is denied.
    virtual int32_t GetPermissionPolicy(
        uint32_t code, std::vector<std::vector<PermissionType>> &permissionPolicy, bool &isBypass) = 0;
};
}  // namespace OHOS::Media::IPC
#endif  // OHOS_MEDIA_IPC_I_MEDIA_CONTROLLER_SERVICE_H