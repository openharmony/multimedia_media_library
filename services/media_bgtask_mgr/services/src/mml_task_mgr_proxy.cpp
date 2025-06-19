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

#define MLOG_TAG "MediaBgTask_MmlTaskMgrProxy"

#include "mml_task_mgr_proxy.h"
#include <string_ex.h>
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

ErrCode MmlTaskMgrProxy::ReportTaskComplete(const std::string& task_name)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        MEDIA_ERR_LOG("Write interface token failed!");
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString(task_name)) {
        MEDIA_ERR_LOG("Write [task_name] failed!");
        return ERR_INVALID_DATA;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        MEDIA_ERR_LOG("Remote is nullptr!");
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IMmlTaskMgrIpcCode::COMMAND_REPORT_TASK_COMPLETE), data, reply, option);
    if (FAILED(result)) {
        MEDIA_ERR_LOG("Send request failed!");
        return result;
    }

    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        MEDIA_ERR_LOG("Read result failed, code is: %{public}d.",
            static_cast<uint32_t>(IMmlTaskMgrIpcCode::COMMAND_REPORT_TASK_COMPLETE));
        return errCode;
    }

    return ERR_OK;
}

ErrCode MmlTaskMgrProxy::ModifyTask(const std::string& task_name, const std::string& modifyInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        MEDIA_ERR_LOG("Write interface token failed!");
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString(task_name)) {
        MEDIA_ERR_LOG("Write [task_name] failed!");
        return ERR_INVALID_DATA;
    }
    if (!data.WriteString(modifyInfo)) {
        MEDIA_ERR_LOG("Write [modifyInfo] failed!");
        return ERR_INVALID_DATA;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        MEDIA_ERR_LOG("Remote is nullptr!");
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IMmlTaskMgrIpcCode::COMMAND_MODIFY_TASK), data, reply, option);
    if (FAILED(result)) {
        MEDIA_ERR_LOG("Send request failed!");
        return result;
    }

    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        MEDIA_ERR_LOG("Read result failed, code is: %{public}d.",
            static_cast<uint32_t>(IMmlTaskMgrIpcCode::COMMAND_MODIFY_TASK));
        return errCode;
    }

    return ERR_OK;
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS
