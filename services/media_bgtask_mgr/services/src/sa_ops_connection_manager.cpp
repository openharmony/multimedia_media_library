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
 
#define MLOG_TAG "MediaBgTask_SAOpsConnectionManager"

#include "sa_ops_connection_manager.h"
#include "media_bgtask_utils.h"
#include "media_bgtask_schedule_service.h"
#include "task_info_mgr.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS::MediaBgtaskSchedule {

SAOpsConnectionManager::SAOpsConnectionManager()
{
}

int32_t SAOpsConnectionManager::TaskOpsSync(const std::string& ops, int32_t saId,
    const std::string& taskName, const std::string& extra)
{
    auto connection = GetConnection(saId);
    if (!connection) {
        MEDIA_ERR_LOG("TaskOpsSync failed: bad connection obj saId:%{public}d", saId);
        return ERR_INVALID_DATA;
    }
    return connection->TaskOpsSync(ops, taskName, extra);
}

std::shared_ptr<SAOpsConnection> SAOpsConnectionManager::GetConnection(int32_t saId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.find(saId) == connections_.end()) {
        auto connection = std::make_shared<SAOpsConnection>(saId,
            [](const int32_t saId, SAOpsConnection::ConnectionStatus status) {
                MEDIA_INFO_LOG("Connection status changed SAID:%{public}d status:%{public}d", saId, status);
                if (status == SAOpsConnection::ConnectionStatus::DISCONNECTED) {
                    MediaBgtaskScheduleService::GetInstance().NotifySaTaskProcessDie(saId);
                    TaskInfoMgr::GetInstance().SaveTaskState(false);
                }
            }
        );
        if (connection->Init() != 0) {
            MEDIA_ERR_LOG("error init SAID:%{public}d", saId);
            return nullptr;
        }
        connections_[saId] = connection;
    }
    return connections_[saId];
}

} // namespace OHOS::MediaBgtaskSchedule
