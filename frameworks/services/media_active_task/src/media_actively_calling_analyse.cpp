/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_actively_calling_analyse.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace Media {
MediaActivelyCallingAnalyse::MediaActivelyCallingAnalyse(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IMediaAnalyseService>(object)
{
    MEDIA_INFO_LOG("creat MediaActivelyCallingAnalyse instance");
}

MediaActivelyCallingAnalyse::~MediaActivelyCallingAnalyse()
{
    MEDIA_INFO_LOG("destroy MediaActivelyCallingAnalyse instance");
}

bool MediaActivelyCallingAnalyse::SendTransactCmd(int32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int32_t minTimeout = 4;
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("Get samgr fail, samgr is nullptr");
        return false;
    }
    sptr<IRemoteObject> remoteObject = saMgr->CheckSystemAbility(SAID);
    if (remoteObject != nullptr) {
        MEDIA_INFO_LOG("Active task: sa already running");
        return false;
    }
    sptr<IRemoteObject> remote = saMgr->LoadSystemAbility(SAID, minTimeout);
    if (remote == nullptr) {
        MEDIA_ERR_LOG("fail to send transact %{public}d due to remote object", code);
        return false;
    }
    
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        MEDIA_ERR_LOG("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    MEDIA_INFO_LOG("send request success");
    return true;
}
} // namespace Media
} // namespace OHOS