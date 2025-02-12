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

#include "media_param_watcher_ability.h"
#include "parameter.h"
#include "parameters.h"
#include "media_log.h"

namespace OHOS {
namespace DataShare {

constexpr const char *MTP_DISABLE = "persist.edm.mtp_server_disable";

MtpParamWatcher::MtpParamWatcher() {}

MtpParamWatcher::~MtpParamWatcher() {}

void MtpParamWatcher::RegisterMtpParamListener()
{
    MEDIA_INFO_LOG("RegisterMTPParamListener");
    WatchParameter(MTP_DISABLE, OnMtpParamDisableChanged, this);
}

void MtpParamWatcher::RemoveMtpParamListener()
{
    RemoveParameterWatcher(MTP_DISABLE, OnMtpParamDisableChanged, this);
}

void MtpParamWatcher::OnMtpParamDisableChanged(const char *key, const char *value, void *context)
{
    if (key == nullptr || value == nullptr) {
        MEDIA_ERR_LOG("OnMtpParamDisableChanged return invalid value");
        return;
    }
    MEDIA_INFO_LOG("OnMTPParamDisable, key = %{public}s, value = %{public}s", key, value);
    if (strcmp(key, MTP_DISABLE) != 0) {
        MEDIA_INFO_LOG("event key mismatch");
        return;
    }
    std::string param(MTP_DISABLE);
    bool mtpDisable = system::GetBoolParameter(param, false);
    if (!mtpDisable) {
        MEDIA_INFO_LOG("MTP Manager init");
        OHOS::Media::MtpManager::GetInstance().Init();
    } else {
        MEDIA_INFO_LOG("MTP Manager not init");
    }
}
}
}