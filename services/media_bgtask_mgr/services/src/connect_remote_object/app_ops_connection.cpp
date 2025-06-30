/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaBgTask_AppOpsConnection"

#include "app_ops_connection.h"
#include "media_bgtask_schedule_service.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t E_ERR = -1;
static const int32_t CONNECT_ABILITY_SUCCESS = 0;

AppOpsConnection::AppOpsConnection(const AppSvcInfo &svcName, int32_t userId) : svcName_(svcName), userId_(userId) {}

AppOpsConnection::~AppOpsConnection() {}

void AppOpsConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (resultCode != CONNECT_ABILITY_SUCCESS) {
        MEDIA_ERR_LOG("failed to OnAbilityConnectDone result code: %{public}d.", resultCode);
        return;
    }
    MEDIA_INFO_LOG("OnAbilityConnectDone, userId: %{public}d, bundleName: %{public}s, ability: %{public}s.",
        userId_, svcName_.bundleName.c_str(), svcName_.abilityName.c_str());

    remoteObject_ = remoteObject;
    proxy_ = new AppTaskOpsProxy(remoteObject_);
    if (proxy_ == nullptr) {
        MEDIA_ERR_LOG("taskOpsProxy is nullptr.");
        return;
    }

    std::string bundle = svcName_.bundleName;
    int32_t userId = userId_;
    deathRecipient_ = new AAFwk::AbilityConnectCallbackRecipient([bundle, userId](const wptr<IRemoteObject> &remote) {
        MEDIA_INFO_LOG("app death recipient, userId: %{public}d", userId);
        MediaBgtaskScheduleService::GetInstance().NotifyAppTaskProcessDie(bundle, userId);
    });
    if (!remoteObject_->AddDeathRecipient(deathRecipient_)) {
        MEDIA_INFO_LOG("add death recipient failed.");
    }
    if (!connectedCallback_) {
        MEDIA_ERR_LOG("connectedCallback_ is nullptr.");
        return;
    }
    connectedCallback_();
}

void AppOpsConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (remoteObject_) {
        MEDIA_INFO_LOG("app disconnect, remove death recipient, userId: %{public}d", userId_);
        remoteObject_->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
    remoteObject_ = nullptr;
    deathRecipient_ = nullptr;
    if (disConnectedCallback_) {
        disConnectedCallback_(userId_);
    }
    TaskInfoMgr::GetInstance().SaveTaskState(false);
}

int32_t AppOpsConnection::TaskOpsSync(const std::string& ops, const std::string& taskName, const std::string &extra)
{
    std::lock_guard<std::mutex> lock(mutex_);

    MEDIA_INFO_LOG("AppOpsConnection::TaskOpsSync start.");
    CHECK_AND_RETURN_RET_LOG(proxy_ != nullptr, E_ERR, "IRemoteProxy is nullptr");
    int32_t funcResult = 0;
    return proxy_->DoTaskOps(ops, taskName, extra, funcResult);
}

void AppOpsConnection::AddConnectedCallback(std::function<void()> callback)
{
    if (callback) {
        connectedCallback_ = std::move(callback);
    }
}

void AppOpsConnection::AddDisConnectedCallback(std::function<void(int32_t)> callback)
{
    if (callback) {
        disConnectedCallback_ = std::move(callback);
    }
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS
