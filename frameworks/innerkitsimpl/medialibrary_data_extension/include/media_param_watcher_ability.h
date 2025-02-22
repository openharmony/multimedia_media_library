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

#ifndef MEDIA_PARAM_WATCHER_ABILITY_H
#define MEDIA_PARAM_WATCHER_ABILITY_H

#include "singleton.h"
#include "mtp_manager.h"

namespace OHOS {
namespace DataShare {
class MtpParamWatcher : public DelayedSingleton<MtpParamWatcher> {
    DECLARE_DELAYED_SINGLETON(MtpParamWatcher);
public:
    void RegisterMtpParamListener();
    void RemoveMtpParamListener();
    static void OnMtpParamDisableChanged(const char *key, const char *value, void *context);
};
}
}

#endif