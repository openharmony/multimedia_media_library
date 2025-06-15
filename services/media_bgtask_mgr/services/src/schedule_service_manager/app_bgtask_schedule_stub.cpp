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
#define MLOG_TAG "MediaBgTask_AppBgTaskScheduleStub"

#include "app_bgtask_schedule_stub.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
int32_t AppBgTaskScheduleStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption& option)
{
    MEDIA_INFO_LOG("MmlTaskMgrStub OnRemoteRequest, code: %{public}d.", code);
    std::u16string localDescriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (localDescriptor != remoteDescriptor) {
        return ERR_TRANSACTION_FAILED;
    }
    switch (static_cast<IMmlTaskMgrIpcCode>(code)) {
        case IMmlTaskMgrIpcCode::COMMAND_REPORT_TASK_COMPLETE: {
            return CmdReportTaskComplete(data, reply);
        }
        case IMmlTaskMgrIpcCode::COMMAND_MODIFY_TASK: {
            return CmdModifyTask(data, reply);
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_TRANSACTION_FAILED;
}

int32_t AppBgTaskScheduleStub::CmdReportTaskComplete(MessageParcel& data, MessageParcel& reply)
{
    std::string taskName = data.ReadString();
    MEDIA_INFO_LOG("MmlTaskMgrStub OnRemoteRequest, task_name: %{public}s.", taskName.c_str());
    int32_t result;
    int32_t errCode = ReportTaskComplete(taskName, result);
    if (!reply.WriteInt32(errCode)) {
        return ERR_INVALID_VALUE;
    }
    if (SUCCEEDED(errCode)) {
        if (!reply.WriteInt32(result)) {
            return ERR_INVALID_DATA;
        }
    }
    return ERR_NONE;
}

int32_t AppBgTaskScheduleStub::CmdModifyTask(MessageParcel& data, MessageParcel& reply)
{
    std::string taskName = data.ReadString();
    std::string modifyInfo = data.ReadString();
    int32_t result;
    int32_t errCode = ModifyTask(taskName, modifyInfo, result);
    if (!reply.WriteInt32(errCode)) {
        return ERR_INVALID_VALUE;
    }
    if (SUCCEEDED(errCode)) {
        if (!reply.WriteInt32(result)) {
            return ERR_INVALID_DATA;
        }
    }
    return ERR_NONE;
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS
