/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Media_IPC"

#include "user_define_ipc_client.h"

#include "iservice_registry.h"
#include "userfile_client.h"

namespace OHOS::Media::IPC {
static const int STORAGE_MANAGER_MANAGER_ID = 5003;

UserDefineIPCClient::UserDefineIPCClient()
{
    SetUserId(UserFileClient::GetUserId());
}

int32_t UserDefineIPCClient::UserDefineFunc(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    bool errConn = UserFileClient::IsValid(GetUserId());
    if (!errConn) {
        MEDIA_ERR_LOG("Call IPC UserFileClient::IsInValid");
        auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        errConn = saManager == nullptr;
        CHECK_AND_RETURN_RET_LOG(!errConn, E_ERR, "Get system ability mgr failed.");
        auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
        errConn = remoteObj == nullptr;
        CHECK_AND_RETURN_RET_LOG(!errConn, E_ERR, "GetSystemAbility Service Failed.");
        UserFileClient::Init(remoteObj, true, GetUserId());
    }
    return UserFileClient::UserDefineFunc(GetUserId(), data, reply, option);
}
}  // namespace OHOS::Media::IPC