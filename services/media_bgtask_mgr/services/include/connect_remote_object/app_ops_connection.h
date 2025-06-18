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

#ifndef APP_OPS_CONNECTION_H
#define APP_OPS_CONNECTION_H

#include "ability_manager_client.h"
#include "ability_connect_callback_stub.h"
#include "app_task_ops_proxy.h"
#include "task_runner_types.h"

#include <memory>
#include <mutex>

namespace OHOS {
namespace MediaBgtaskSchedule {
class AppOpsConnection : public AAFwk::AbilityConnectionStub {
public:
    AppOpsConnection(const AppSvcInfo &svcName, int32_t userId);
    ~AppOpsConnection();

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
        int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    int32_t TaskOpsSync(const std::string &ops, const std::string &taskName, const std::string &extra);
    void AddConnectedCallback(std::function<void()> callback);

private:
    std::mutex mutex_;
    sptr<IRemoteObject> remoteObject_;
    sptr<AppTaskOpsProxy> proxy_;
    AppSvcInfo svcName_;
    int32_t userId_;

    std::function<void()> connectedCallback_;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // APP_OPS_CONNECTION_H
