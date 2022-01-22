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
#ifndef TASK_DISPATCH_H
#define TASK_DISPATCH_H
#include <string>
#include <map>
#include <vector>
#include <event_runner.h>
#include <event_handler.h>
#include <refbase.h>
#include "inner/common/execute_common.h"
#include "inner/event/execute_event.h"
namespace OHOS {
namespace Media {
class TaskDispatch : public RefBase {
public:
    virtual const std::string GetClassName() const;
    virtual uint32_t GetID(void) const final;
protected:
    explicit TaskDispatch(CallType callType = CallType::CALL_FUNCTION);
    ~TaskDispatch();
    virtual void DoEvent(const sptr<ExecuteEvent> &executeEvent) = 0;
    virtual ExecStatus DispatchInit(void) final;
    virtual ExecStatus DispatchEvent(const sptr<ExecuteEvent> &executeEvent) final;
private:
    std::string GetPostTaskName(const sptr<ExecuteEvent> &executeEvent);
    void DoDispatchEvent(const sptr<ExecuteEvent> &executeEvent);
private:
    static uint32_t CreateID();
private:
    std::mutex mutex_;
    bool inited_ {false};
    CallType callType_ {CallType::CALL_HANDLE};
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
private:
    uint32_t id_ {0};
    static std::mutex staticMutex_;
    static uint32_t statcIndex_;
};
} // namespace Media
} // namespace OHOS
#endif // TASK_DISPATCH_H
