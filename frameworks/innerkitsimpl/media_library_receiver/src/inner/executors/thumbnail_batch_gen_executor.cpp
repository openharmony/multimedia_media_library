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
#include "inner/executors/thumbnail_batch_gen_executor.h"
#include "media_log.h"
#include "inner/policys/thumbnail_batch_gen_policy.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "ThumbnailBatchGenExecutor";
}
ExecStatus ThumbnailBatchGenExecutor::Register(std::vector<std::string> &events)
{
    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Register enter[%{public}d]|", GetID());

    auto executePolicy = sptr<ExecutePolicy>(new ThumbnailBatchGenPolicy());
    AddPolicy("ThumbnailBatchGenPolicy01", executePolicy);
    AddPolicy("ThumbnailBatchGenPolicy02", executePolicy);

    GetPolicys(events);

    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Register leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus ThumbnailBatchGenExecutor::BeforeExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::BeforeExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::BeforeExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus ThumbnailBatchGenExecutor::Execute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Execute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    auto policys = GetPolicy(executeEvent->event);
    for (auto policy : policys) {
        policy->OnEvent(executeEvent);
    }

    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Execute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus ThumbnailBatchGenExecutor::AfterExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::AfterExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::AfterExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus ThumbnailBatchGenExecutor::Finally(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Finally enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("ThumbnailBatchGenExecutor::Finally leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

const std::string ThumbnailBatchGenExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void ThumbnailBatchGenExecutor::Dump() const
{
    PolicyExecutor::Dump();
}
} // namespace Media
} // namespace OHOS