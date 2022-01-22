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
#ifndef TASK_EXECUTOR_H
#define TASK_EXECUTOR_H
#include <string>
#include <map>
#include <vector>
#include "inner/common/execute_common.h"
#include "inner/event/execute_event.h"
#include "inner/common/task_dispatch.h"
namespace OHOS {
namespace Media {
class TaskExecutor : public TaskDispatch {
public:
    virtual ExecStatus Register(std::vector<std::string> &events) = 0;
    virtual ExecStatus BeforeExecute(const sptr<ExecuteEvent> &executeEvent) = 0;
    virtual ExecStatus Execute(const sptr<ExecuteEvent> &executeEvent) = 0;
    virtual ExecStatus AfterExecute(const sptr<ExecuteEvent> &executeEvent) = 0;
    virtual ExecStatus Finally(const sptr<ExecuteEvent> &executeEvent) = 0;
public:
    virtual const std::string GetClassName() const;
    virtual void Dump() const;
public:
    virtual ExecStatus OnInit(void) final;
    virtual ExecStatus OnRegister(std::vector<std::string> &event) final;
    virtual ExecStatus OnEvent(const sptr<ExecuteEvent> &executeEvent) final;
protected:
    explicit TaskExecutor(CallType callType = CallType::CALL_FUNCTION);
    ~TaskExecutor();
private:
    void AddEventToWorking(const sptr<ExecuteEvent> &executeEvent);
    void EraseEventFromWorking(const sptr<ExecuteEvent> &executeEvent);
    std::vector<const sptr<ExecuteEvent>> GetEventFromWorking();
    virtual void DoEvent(const sptr<ExecuteEvent> &executeEvent) final;
private:
    std::mutex mutex_;
    bool inited_ {false};
    std::vector<std::string> events_;
    std::map<uint32_t, const sptr<ExecuteEvent>> workings_;
};
} // namespace Media
} // namespace OHOS
#endif // TASK_EXECUTOR_H
