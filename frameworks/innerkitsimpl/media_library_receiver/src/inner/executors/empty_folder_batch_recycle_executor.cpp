/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "inner/executors/empty_folder_batch_recycle_executor.h"
#include "media_log.h"
#include "inner/policys/empty_folder_batch_recycle_policy.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "EmptyFolderBatchRecycleExecutor";
}
ExecStatus EmptyFolderBatchRecycleExecutor::Register(std::vector<std::string> &events)
{
    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Register enter[%{public}d]|", GetID());

    auto executePolicy = sptr<ExecutePolicy>(new EmptyFolderBatchRecyclePolicy());
    AddPolicy("EmptyFolderBatchRecyclePolicy01", executePolicy);
    AddPolicy("EmptyFolderBatchRecyclePolicy02", executePolicy);

    GetPolicys(events);

    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Register leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus EmptyFolderBatchRecycleExecutor::BeforeExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::BeforeExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::BeforeExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus EmptyFolderBatchRecycleExecutor::Execute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Execute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    auto policys = GetPolicy(executeEvent->event);
    for (auto policy : policys) {
        policy->OnEvent(executeEvent);
    }

    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Execute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus EmptyFolderBatchRecycleExecutor::AfterExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::AfterExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::AfterExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus EmptyFolderBatchRecycleExecutor::Finally(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Finally enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("EmptyFolderBatchRecycleExecutor::Finally leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

const std::string EmptyFolderBatchRecycleExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void EmptyFolderBatchRecycleExecutor::Dump() const
{
    PolicyExecutor::Dump();
}
} // namespace Media
} // namespace OHOS