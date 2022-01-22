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
#include "inner/common/task_dispatch.h"
#include <algorithm>
#include <functional>
#include <thread>
#include "media_log.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "TaskDispatch";
static const std::string TASK_DOEVENT = "TaskDispatch_DoEvent_";
const uint32_t ID_MAX = 1000000;
}
std::mutex TaskDispatch::staticMutex_;
uint32_t TaskDispatch::statcIndex_ = 0;
TaskDispatch::TaskDispatch(CallType callType) : callType_(callType)
{
    id_ = CreateID();
}

TaskDispatch::~TaskDispatch()
{
}

const std::string TaskDispatch::GetClassName() const
{
    return CLASS_NAME;
}

ExecStatus TaskDispatch::DispatchInit(void)
{
    MEDIA_DEBUG_LOG("TaskExecutor::DispatchInit enter[%{public}d]|callType=%{public}d",
        GetID(), callType_);

    if (inited_) {
        return ExecStatus::EXEC_OK;
    }

    if (callType_ == CallType::CALL_HANDLE) {
        if (!eventRunner_) {
            eventRunner_ = AppExecFwk::EventRunner::Create(GetClassName());
        }
        if (eventRunner_ && (!eventHandler_)) {
            eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(eventRunner_);
        }
        if (!eventHandler_) {
            callType_ = CallType::CALL_THREAD;
        }
    }
    inited_ = true;

    MEDIA_DEBUG_LOG("TaskExecutor::DispatchInit leave[%{public}d]|callType=%{public}d",
        GetID(), callType_);
    return ExecStatus::EXEC_OK;
}

ExecStatus TaskDispatch::DispatchEvent(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent enter[%{public}d]|callType=%{public}d",
        GetID(), callType_);

    if (executeEvent == nullptr) {
        MEDIA_ERR_LOG("TaskDispatch::DispatchEvent error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent leave[%{public}d]|parameter", GetID());
        return ExecStatus::EXEC_PARAM;
    }

    if (callType_ == CallType::CALL_FUNCTION) {
        MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent debug[%{public}d]|CALL_FUNCTION", GetID());
        DoEvent(executeEvent);
    } else if (callType_ == CallType::CALL_HANDLE) {
        MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent debug[%{public}d]|CALL_HANDLE", GetID());
        std::function<void()> postTask = std::bind(&TaskDispatch::DoDispatchEvent, this, executeEvent);
        eventHandler_->PostTask(postTask, GetPostTaskName(executeEvent));
    } else {
        MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent debug[%{public}d]|CALL_THREAD", GetID());
        std::make_unique<std::thread>([=] {
            DoEvent(executeEvent);
        })->detach();
    }

    MEDIA_DEBUG_LOG("TaskDispatch::DispatchEvent leave[%{public}d]|ok", GetID());
    return ExecStatus::EXEC_OK;
}

std::string TaskDispatch::GetPostTaskName(const sptr<ExecuteEvent> &executeEvent)
{
    return TASK_DOEVENT + executeEvent->event;
}

void TaskDispatch::DoDispatchEvent(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("TaskDispatch::DoDispatchEvent enter[%{public}d]|", GetID());

    DoEvent(executeEvent);

    MEDIA_DEBUG_LOG("TaskDispatch::DoDispatchEvent leave[%{public}d]|", GetID());
}

uint32_t TaskDispatch::GetID(void) const
{
    return id_;
}

uint32_t TaskDispatch::CreateID()
{
    std::lock_guard<std::mutex> lock(staticMutex_);
    return (statcIndex_ > ID_MAX) ? 0 : statcIndex_++;
}
} // namespace Media
} // namespace OHOS