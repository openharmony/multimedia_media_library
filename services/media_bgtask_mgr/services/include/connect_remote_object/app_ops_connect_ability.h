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

#ifndef APP_OPS_CONNECT_ABILITY_H
#define APP_OPS_CONNECT_ABILITY_H

#include "ability_connect_callback_stub.h"
#include "app_ops_connection.h"
#include "singleton.h"

#include <condition_variable>
#include <mutex>

namespace OHOS {
namespace MediaBgtaskSchedule {
enum AppConnectionStatus : int32_t {
    ALREADY_EXISTS = 1,
    TO_BE_ADDED,
    REMOTE_DIED,
    FAILED_TO_CONNECT = 10,
};

class AppOpsConnectAbility {
DECLARE_DELAYED_SINGLETON(AppOpsConnectAbility)
public:
    int32_t ConnectAbility(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
        const std::string &taskName, const std::string &extra);
    int32_t DisconnectAbility(int32_t userId);
    int32_t TaskOpsSync(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
        const std::string& taskName, const std::string &extra);

private:
    int32_t DoConnect(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
        const std::string &taskName, const std::string &extra);
    void OnConnectedCallback();

    std::mutex abilityMapMutex_;
    std::unordered_map<std::int32_t, sptr<AppOpsConnection>> appConnections_;

    std::mutex connectMutex_;
    std::condition_variable conditionVal_;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // APP_OPS_CONNECT_ABILITY_H
