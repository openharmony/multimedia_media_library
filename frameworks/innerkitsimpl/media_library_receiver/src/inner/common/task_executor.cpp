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
#include "inner/common/task_executor.h"
#include <algorithm>
#include "media_log.h"
#include "inner/utils/receiver_utils.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "TaskExecutor";
}
TaskExecutor::TaskExecutor(CallType callType) : TaskDispatch(callType)
{
    MEDIA_DEBUG_LOG("TaskExecutor created[%{public}d]|callType=%{public}d", GetID(), callType);
}

TaskExecutor::~TaskExecutor()
{
    MEDIA_DEBUG_LOG("TaskExecutor released[%{public}d]|", GetID());
}

const std::string TaskExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void TaskExecutor::Dump() const
{
    MEDIA_DEBUG_LOG("TaskExecutor::Dump dump[%{public}d]|", GetID());
    for (auto event : events_) {
        MEDIA_DEBUG_LOG("TaskExecutor::Dump dump[%{public}d]|event=[%{public}s]", GetID(), event.c_str());
    }
    MEDIA_DEBUG_LOG("TaskExecutor::Dump dump[%{public}d]|workings=%{public}d", GetID(), workings_.size());
}

ExecStatus TaskExecutor::OnInit(void)
{
    MEDIA_DEBUG_LOG("TaskExecutor::OnInit enter[%{public}d]|", GetID());

    DispatchInit();

    inited_ = true;

    MEDIA_DEBUG_LOG("TaskExecutor::OnInit leave[%{public}d]|", GetID());
    return ExecStatus::EXEC_OK;
}

ExecStatus TaskExecutor::OnRegister(std::vector<std::string> &events)
{
    MEDIA_DEBUG_LOG("TaskExecutor::OnRegister enter[%{public}d]|", GetID());

    ExecStatus ret = Register(events_);

    MEDIA_DEBUG_LOG("TaskExecutor::OnRegister debug[%{public}d]|ret=%{public}d", GetID(), ret);

    ReceiverUtils::RemoveEmptyString(events_);
    ReceiverUtils::RemoveDuplicateString(events_);

    MEDIA_DEBUG_LOG("TaskExecutor::OnRegister debug[%{public}d]|size=%{public}d", GetID(), events_.size());

    if (ret == ExecStatus::EXEC_OK) {
        events.insert(events.end(), events_.begin(), events_.end());
    }

    MEDIA_DEBUG_LOG("TaskExecutor::OnRegister leave[%{public}d]|ret=%{public}d", GetID(), ret);
    return ret;
}

ExecStatus TaskExecutor::OnEvent(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent enter[%{public}d]|", GetID());

    if (executeEvent == nullptr) {
        MEDIA_ERR_LOG("TaskExecutor::OnEvent error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("TaskExecutor::OnEvent leave[%{public}d]|parameter", GetID());
        return ExecStatus::EXEC_PARAM;
    }

    if (std::find(events_.begin(), events_.end(), executeEvent->event) == events_.end()) {
        MEDIA_ERR_LOG("TaskExecutor::OnEvent error[%{public}d]|unsupport", GetID());
        MEDIA_DEBUG_LOG("TaskExecutor::OnEvent leave[%{public}d]|unsupport", GetID());
        return ExecStatus::EXEC_UNSUPPORT;
    }

    DispatchEvent(executeEvent);

    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent leave[%{public}d]|ok", GetID());
    return ExecStatus::EXEC_OK;
}

void TaskExecutor::AddEventToWorking(const sptr<ExecuteEvent> &executeEvent)
{
    std::lock_guard<std::mutex> lock(mutex_);

    workings_.insert(std::make_pair(executeEvent->GetID(), executeEvent));
}

void TaskExecutor::EraseEventFromWorking(const sptr<ExecuteEvent> &executeEvent)
{
    std::lock_guard<std::mutex> lock(mutex_);

    workings_.erase(executeEvent->GetID());
}

std::vector<const sptr<ExecuteEvent>> TaskExecutor::GetEventFromWorking()
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<const sptr<ExecuteEvent>> workings;

    for (auto item : workings_) {
        workings.push_back(item.second);
    }

    return workings;
}

void TaskExecutor::DoEvent(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent enter[%{public}d]|", GetID());

    AddEventToWorking(executeEvent);

    executeEvent->Dump();

    ExecStatus res = BeforeExecute(executeEvent);
    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent debug[%{public}d]|BeforeExecute, res=%{public}d", GetID(), res);

    if (res == ExecStatus::EXEC_OK) {
        while (true) {
            res = Execute(executeEvent);
            MEDIA_DEBUG_LOG("TaskExecutor::OnEvent debug[%{public}d]|Execute, res=%{public}d", GetID(), res);
            if (res != ExecStatus::EXEC_LOOP) {
                break;
            }
        }

        res = AfterExecute(executeEvent);
        MEDIA_DEBUG_LOG("TaskExecutor::OnEventdebug[%{public}d]|AfterExecute, res=%{public}d", GetID(), res);
    }

    res = Finally(executeEvent);
    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent debug[%{public}d]|Finally, res=%{public}d", GetID(), res);

    EraseEventFromWorking(executeEvent);

    MEDIA_DEBUG_LOG("TaskExecutor::OnEvent leave[%{public}d]|", GetID());
}
} // namespace Media
} // namespace OHOS