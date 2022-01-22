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
#include "inner/common/function_executor.h"
#include <cstdio>
#include "media_log.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "FunctionExecutor";
}
FunctionExecutor::FunctionExecutor()
{
    MEDIA_DEBUG_LOG("FunctionExecutor created[%{public}d]|", GetID());
}

FunctionExecutor::~FunctionExecutor()
{
    MEDIA_DEBUG_LOG("FunctionExecutor released[%{public}d]|", GetID());
}

ExecStatus FunctionExecutor::Register(std::vector<std::string> &events)
{
    MEDIA_DEBUG_LOG("FunctionExecutor::Register enter[%{public}d]|size=%{public}d", GetID(), events.size());

    using namespace std::placeholders;
    entryMap_.insert(std::make_pair("DoTest01", std::bind(&FunctionExecutor::DoTest01, this, _1)));
    entryMap_.insert(std::make_pair("DoTest02", std::bind(&FunctionExecutor::DoTest02, this, _1)));

    for (auto item : entryMap_) {
        events.push_back(item.first);
    }

    MEDIA_DEBUG_LOG("FunctionExecutor::Register leave[%{public}d]|size=%{public}d", GetID(), events.size());
    return ExecStatus::EXEC_OK;
}

ExecStatus FunctionExecutor::BeforeExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("FunctionExecutor::BeforeExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    if (entryMap_.count(executeEvent->event) < 1) {
        MEDIA_DEBUG_LOG("FunctionExecutor::BeforeExecute leave[%{public}d]|UNSUPPORT\n", GetID());
        return ExecStatus::EXEC_UNSUPPORT;
    }

    auto entry = entryMap_[executeEvent->event];
    ExecStatus ret = entry(executeEvent);

    MEDIA_DEBUG_LOG("FunctionExecutor::BeforeExecute leave[%{public}d]|ret=%{public}d", GetID(), ret);
    return ret;
}

ExecStatus FunctionExecutor::Execute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("FunctionExecutor::Execute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("FunctionExecutor::Execute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_FAIL;
}

ExecStatus FunctionExecutor::AfterExecute(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("FunctionExecutor::AfterExecute enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("FunctionExecutor::AfterExecute leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_FAIL;
}

ExecStatus FunctionExecutor::Finally(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("FunctionExecutor::Finally enter[%{public}d]|", GetID());

    executeEvent->Dump();

    MEDIA_DEBUG_LOG("FunctionExecutor::Finally leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_FAIL;
}

const std::string FunctionExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void FunctionExecutor::Dump() const
{
    TaskExecutor::Dump();
}

ExecStatus FunctionExecutor::DoTest01(const sptr<ExecuteEvent> &executeEvent)
{
    printf("FunctionExecutor::DoTest01 ***************\n");
    executeEvent->Dump();
    return ExecStatus::EXEC_FAIL;
}

ExecStatus FunctionExecutor::DoTest02(const sptr<ExecuteEvent> &executeEvent)
{
    printf("FunctionExecutor::DoTest02 ***************\n");
    executeEvent->Dump();
    return ExecStatus::EXEC_FAIL;
}
} // namespace Media
} // namespace OHOS