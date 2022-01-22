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
#include "inner/task_event_receiver.h"
#include <vector>
#include <string_ex.h>
#include "media_log.h"
#include "inner/utils/receiver_utils.h"
#include "inner/executors/distributed_devices_batch_recycle_executor.h"
#include "inner/executors/empty_folder_batch_recycle_executor.h"
#include "inner/executors/lcd_batch_recycle_executor.h"
#include "inner/executors/thumbnail_batch_gen_executor.h"
#include "inner/executors/thumbnail_batch_recycle_executor.h"
#include "inner/executors/trash_file_batch_recycle_executor.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "TaskEventReceiver";
}
TaskEventReceiver::TaskEventReceiver() : TaskDispatch(CallType::CALL_HANDLE)
{
    MEDIA_DEBUG_LOG("TaskEventReceiver created[%{public}d]|", GetID());
}

TaskEventReceiver::~TaskEventReceiver()
{
    MEDIA_DEBUG_LOG("TaskEventReceiver released[%{public}d]|", GetID());
}

void TaskEventReceiver::Init(void)
{
    MEDIA_DEBUG_LOG("TaskEventReceiver::Init enter[%{public}d]|inited_=%{public}d", GetID(), inited_);

    if (inited_) {
        MEDIA_DEBUG_LOG("TaskEventReceiver::Init leave[%{public}d]|", GetID());
        return;
    }

    DispatchInit();
    AddAllExecutors();

    inited_ = true;

    MEDIA_DEBUG_LOG("TaskEventReceiver::Init leave[%{public}d]|inited_=%{public}d", GetID(), inited_);
}

void TaskEventReceiver::OnEvent(const std::string &event)
{
    MEDIA_DEBUG_LOG("TaskEventReceiver::OnEvent enter[%{public}d]|event=[%{public}s]", GetID(), event.c_str());

    std::string trimedEvent = TrimStr(event);
    if (trimedEvent.empty()) {
        MEDIA_ERR_LOG("TaskEventReceiver::OnEvent error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("TaskEventReceiver::OnEvent leave[%{public}d]|parameter", GetID());
        return;
    }

    auto executeEvent = sptr<ExecuteEvent>(new ExecuteEvent(trimedEvent));
    executeEvent->Dump();

    DispatchEvent(executeEvent);

    MEDIA_DEBUG_LOG("TaskEventReceiver::OnEvent leave[%{public}d]|", GetID());
}

void TaskEventReceiver::Dump() const
{
    for (auto &mapItem : eventMap_) {
        MEDIA_DEBUG_LOG("TaskEventReceiver::Dump dump[%{public}d]|event=[%{public}s]", GetID(), mapItem.first.c_str());
        for (auto &vectorItem : mapItem.second) {
            vectorItem->Dump();
        }
    }
}

void TaskEventReceiver::AddAllExecutors()
{
    MEDIA_DEBUG_LOG("TaskEventReceiver::AddAllExecutors enter[%{public}d]|", GetID());

    AddExecutor(new DistributedDevicesBatchRecycleExecutor());
    AddExecutor(new EmptyFolderBatchRecycleExecutor());
    AddExecutor(new LCDBatchRecycleExecutor());
    AddExecutor(new ThumbnailBatchGenExecutor());
    AddExecutor(new ThumbnailBatchRecycleExecutor());
    AddExecutor(new TrashFileBatchRecycleExecutor());

    MEDIA_DEBUG_LOG("TaskEventReceiver::AddAllExecutors leave[%{public}d]|", GetID());
}

void TaskEventReceiver::DoEvent(const sptr<ExecuteEvent> &executeEvent)
{
    MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent enter[%{public}d]|", GetID());

    if (executeEvent == nullptr) {
        MEDIA_ERR_LOG("TaskEventReceiver::DoEvent error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent leave[%{public}d]|", GetID());
        return;
    }

    executeEvent->Dump();

    if (eventMap_.count(executeEvent->event) < 1) {
        MEDIA_ERR_LOG("TaskEventReceiver::DoEvent error[%{public}d]|unsupport", GetID());
        MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent leave[%{public}d]|", GetID());
        return;
    }

    auto executors = eventMap_[executeEvent->event];
    MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent debug[%{public}d]|size=%{public}d",
        GetID(), executors.size());

    for (auto executor : executors) {
        std::string className = executor->GetClassName();
        MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent debug[%{public}d]|%{public}s->OnEvent",
            GetID(), className.c_str());

        executor->OnEvent(executeEvent);
    }

    MEDIA_DEBUG_LOG("TaskEventReceiver::DoEvent leave[%{public}d]|", GetID());
}

void TaskEventReceiver::AddExecutor(sptr<TaskExecutor> executor)
{
    MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor enter[%{public}d]|", GetID());

    if (executor == nullptr) {
        MEDIA_ERR_LOG("TaskEventReceiver::AddExecutor error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor leave[%{public}d]|parameter", GetID());
        return;
    }

    std::string className = executor->GetClassName();

    MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor debug[%{public}d]|%{public}s->OnInit",
        GetID(), className.c_str());

    executor->OnInit();

    MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor debug[%{public}d]|%{public}s->OnRegister",
        GetID(), className.c_str());

    std::vector<std::string> events;
    executor->OnRegister(events);

    ReceiverUtils::RemoveEmptyString(events);
    ReceiverUtils::RemoveDuplicateString(events);

    if (events.empty()) {
        MEDIA_ERR_LOG("TaskEventReceiver::AddExecutor error[%{public}d]|empty", GetID());
        MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor leave[%{public}d]|empty", GetID());
        return;
    }

    MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor debug[%{public}d]|size=%{public}d",
        GetID(), events.size());

    for (size_t i = 0; i < events.size(); i++) {
        const std::string event = events[i];
        if (eventMap_.count(event) < 1) {
            std::vector<sptr<TaskExecutor>> tempUsed;
            eventMap_.insert(std::make_pair(event, tempUsed));
        }

        auto &executors = eventMap_[event];
        executors.push_back(executor);
    }

    MEDIA_DEBUG_LOG("TaskEventReceiver::AddExecutor leave[%{public}d]|", GetID());
}
} // namespace Media
} // namespace OHOS