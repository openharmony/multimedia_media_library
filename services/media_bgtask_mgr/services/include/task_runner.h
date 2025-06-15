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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_H
#include <string>

#include "ability_manager_client.h"
#include "ability_connect_callback_stub.h"
#include "app_ops_connection.h"
#include "iremote_object.h"
#include "task_runner_types.h"

namespace OHOS::MediaBgtaskSchedule {
class TaskRunner {
public:
    /**
     * 实现对任务的启动、停止操作
     * return 成功返回0，错误返回错误原因值
     */
    static int OpsSaTask(TaskOps ops, int32_t saId, std::string taskName, std::string extra);
    static int OpsAppTask(TaskOps ops, AppSvcInfo svcName, std::string taskName, std::string extra);
};

class TaskMonitor {
public:
    int addProcess(pid_t pid, const sptr<IRemoteObject> &proxyStub);
    int removeProcess(pid_t pid);
private:
    void HandleProcessDie(/** 参数待定 */);
};

}  // namespace OHOS::MediaBgtaskSchedule

#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_H
