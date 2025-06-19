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

#define MLOG_TAG "MediaBgTask_AppOpsConnectAbility"

#include "app_ops_connect_ability.h"

#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t E_OK = 0;
static const int32_t E_ERR = -1;
constexpr int32_t CONNECT_TIMEOUT = 5;

AppOpsConnectAbility::AppOpsConnectAbility() {}

AppOpsConnectAbility::~AppOpsConnectAbility() {}

int32_t AppOpsConnectAbility::ConnectAbility(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
    const std::string &taskName, const std::string &extra)
{
    std::lock_guard<std::mutex> lock(abilityMapMutex_);
    if (appConnections_.find(userId) != appConnections_.end()) {
        return AppConnectionStatus::ALREADY_EXISTS;
    }
    return DoConnect(svcName, userId, ops, taskName, extra);
}

int32_t AppOpsConnectAbility::DisconnectAbility(int32_t userId)
{
    MEDIA_INFO_LOG("Disconnect app service extension.");

    std::lock_guard<std::mutex> lock(abilityMapMutex_);
    if (appConnections_.find(userId) == appConnections_.end()) {
        MEDIA_ERR_LOG("userId is not exist");
        return E_ERR;
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(appConnections_[userId]);
    if (err != ERR_OK) {
        MEDIA_ERR_LOG("Fail to disconnect callui ,err:%{public}d", err);
        return E_ERR;
    }
    appConnections_.erase(userId);
    MEDIA_INFO_LOG("Success disconnect app service extension, userId: %{public}d.", userId);
    return E_OK;
}

int32_t AppOpsConnectAbility::TaskOpsSync(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
    const std::string &taskName, const std::string &extra)
{
    if (appConnections_.find(userId) == appConnections_.end() || appConnections_[userId] == nullptr) {
        MEDIA_ERR_LOG("userId is not exist");
        return E_ERR;
    }
    int32_t ret = appConnections_[userId]->TaskOpsSync(ops, taskName, extra);
    if (ret == E_ERR) {
        MEDIA_INFO_LOG("connectCallback_ maybe died, need to connect again.");
        return DoConnect(svcName, userId, ops, taskName, extra);
    }
    return ret;
}

int32_t AppOpsConnectAbility::DoConnect(const AppSvcInfo &svcName, int32_t userId, const std::string &ops,
    const std::string &taskName, const std::string &extra)
{
    sptr<AppOpsConnection> appConnection = new AppOpsConnection(svcName, userId);
    CHECK_AND_RETURN_RET_LOG(appConnection != nullptr, E_ERR, "appConnection is nullptr.");
    appConnection->AddConnectedCallback([this]() {
        this->OnConnectedCallback();
    });

    AAFwk::Want want;
    want.SetElementName(svcName.bundleName, svcName.abilityName);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, appConnection, userId);

    std::unique_lock<std::mutex> uniqueLock(connectMutex_);
    conditionVal_.wait_for(uniqueLock, std::chrono::seconds(CONNECT_TIMEOUT));

    if (err != ERR_OK) {
        MEDIA_ERR_LOG("Fail to connect service extension, err: %{public}d, count: %{public}zu.",
            err, appConnections_.size());
        return AppConnectionStatus::FAILED_TO_CONNECT;
    }
    appConnections_[userId] = appConnection;
    MEDIA_INFO_LOG("Success connect service extension, userId: %{public}d, count: %{public}zu.",
        userId, appConnections_.size());
    return appConnections_[userId]->TaskOpsSync(ops, taskName, extra);
}

void AppOpsConnectAbility::OnConnectedCallback()
{
    MEDIA_INFO_LOG("OnConnectedCallback connected.");
    conditionVal_.notify_one();
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS
