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

#define MLOG_TAG "MediaBgTask_AppTaskOpsProxy"

#include "app_task_ops_proxy.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
ErrCode AppTaskOpsProxy::DoTaskOps(const std::string& ops, const std::string& taskName, const std::string& taskExtra,
    int32_t& funcResult)
{
    MEDIA_INFO_LOG("AppTaskOpsProxy ops: %{public}s, taskName: %{public}s, taskExtra: %{public}s",
        ops.c_str(), taskName.c_str(), taskExtra.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString16(Str8ToStr16(ops))) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteString16(Str8ToStr16(taskName))) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteString16(Str8ToStr16(taskExtra))) {
        return ERR_INVALID_DATA;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IMmlTaskOpsIpcCode::COMMAND_DO_TASK_OPS), data, reply, option);
    if (FAILED(result)) {
        return result;
    }

    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    funcResult = reply.ReadInt32();
    return ERR_OK;
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS
