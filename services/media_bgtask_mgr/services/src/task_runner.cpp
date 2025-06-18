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

#define MLOG_TAG "MediaBgTask_TaskRunner"

#include "task_runner.h"

#include "app_ops_connect_ability.h"
#include "sa_ops_connection_manager.h"
#include "media_bgtask_utils.h"
#include "media_bgtask_mgr_log.h"
#include "os_account_manager_wrapper.h"
#include "singleton.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t E_OK = 0;
static const int32_t E_ERR = -1;
/**
 * 实现对任务的启动、停止操作
 * return 成功返回0，错误返回错误原因值
 */
int TaskRunner::OpsSaTask(TaskOps ops, int32_t saId, std::string taskName, std::string extra)
{
    SAOpsConnectionManager& connectionManager = SAOpsConnectionManager::GetInstance();
    return connectionManager.TaskOpsSync(MediaBgTaskUtils::TaskOpsToString(ops), saId, taskName, extra);
}

int TaskRunner::OpsAppTask(TaskOps ops, AppSvcInfo svcName, std::string taskName, std::string extra)
{
    MEDIA_INFO_LOG("app TaskRunner, taskName: %{public}s.", taskName.c_str());
    std::vector<int32_t> activeIdList = { 0 };
    DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeIdList);

    int32_t ret = E_ERR;
    for (auto activeId : activeIdList) {
        MEDIA_INFO_LOG("OpsAppTask activeId: %{public}d.", activeId);
        ret = DelayedSingleton<AppOpsConnectAbility>::GetInstance()->ConnectAbility(svcName, activeId,
            MediaBgTaskUtils::TaskOpsToString(ops), taskName, extra);
        if (ret == AppConnectionStatus::ALREADY_EXISTS) {
            ret = DelayedSingleton<AppOpsConnectAbility>::GetInstance()->TaskOpsSync(svcName, activeId,
                MediaBgTaskUtils::TaskOpsToString(ops), taskName, extra);
            if (ret != E_OK) {
                MEDIA_ERR_LOG("Failed to TaskOpsSync, activeId: %{public}d, ret: %{public}d.", activeId, ret);
                continue;
            }
        } else {
            MEDIA_INFO_LOG("ConnectAbility ret: %{public}d.", ret);
        }
    }
    return ret;
}

void TaskMonitor::HandleProcessDie(/** 参数待定 */)
{}

int TaskMonitor::addProcess(pid_t pid, const sptr<IRemoteObject> &proxyStub)
{
    return 0;
}

int TaskMonitor::removeProcess(pid_t pid)
{
    return 0;
}

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
