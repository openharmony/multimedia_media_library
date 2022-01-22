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
#include "inner/executors/lcd_batch_recycle_executor.h"
#include "media_log.h"
#include "inner/policys/lcd_batch_recycle_policy.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "LCDBatchRecycleExecutor";
}
ExecStatus LCDBatchRecycleExecutor::Register(std::vector<std::string> &events)
{
    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Register enter[%{public}d]|", GetID());

    auto executePolicy = sptr<ExecutePolicy>(new LCDBatchRecyclePolicy());
    AddPolicy("LCDBatchRecyclePolicy01", executePolicy);
    AddPolicy("LCDBatchRecyclePolicy02", executePolicy);

    GetPolicys(events);

    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Register leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus LCDBatchRecycleExecutor::BeforeExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::BeforeExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::BeforeExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus LCDBatchRecycleExecutor::Execute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Execute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    auto policys = GetPolicy(executeEvent->event);
    for (auto policy : policys) {
        policy->OnEvent(executeEvent);
    }

    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Execute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus LCDBatchRecycleExecutor::AfterExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::AfterExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::AfterExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus LCDBatchRecycleExecutor::Finally(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Finally enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("LCDBatchRecycleExecutor::Finally leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

const std::string LCDBatchRecycleExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void LCDBatchRecycleExecutor::Dump() const
{
    PolicyExecutor::Dump();
}
} // namespace Media
} // namespace OHOS