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
#include "inner/event/execute_event.h"
#include <algorithm>
#include <functional>
#include "datetime_ex.h"
#include "media_log.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "ExecuteEvent";
const uint32_t ID_MAX = 1000000;
}
std::mutex ExecuteEvent::staticMutex_;
uint32_t ExecuteEvent::statcIndex_ = 0;
ExecuteEvent::ExecuteEvent(const std::string &e) : event(e)
{
    MEDIA_DEBUG_LOG("ExecuteEvent debug|event=%{public}s", event.c_str());

    id_ = CreateID();
    createTick_ = GetTickCount();

    MEDIA_DEBUG_LOG("ExecuteEvent created[%{public}d]|", GetID());
}

ExecuteEvent::~ExecuteEvent()
{
    MEDIA_DEBUG_LOG("ExecuteEvent released[%{public}d]|", GetID());
}

bool ExecuteEvent::IsCanceled() const
{
    return canceled_;
}

void ExecuteEvent::Cancel()
{
    MEDIA_DEBUG_LOG("ExecuteEvent::Cancel debug[%{public}d]|event=%{public}s", id_, event.c_str());

    canceled_ = true;
}

void ExecuteEvent::Dump() const
{
    MEDIA_DEBUG_LOG("ExecuteEvent::Dump dump[%{public}d]|event=%{public}s, canceled=%{public}d",
        GetID(), event.c_str(), canceled_);
}

uint32_t ExecuteEvent::GetID(void) const
{
    return id_;
}

uint32_t ExecuteEvent::CreateID()
{
    std::lock_guard<std::mutex> lock(staticMutex_);
    return (statcIndex_ > ID_MAX) ? 0 : statcIndex_++;
}
} // namespace Media
} // namespace OHOS