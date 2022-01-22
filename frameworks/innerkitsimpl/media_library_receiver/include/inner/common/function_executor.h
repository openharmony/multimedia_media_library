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
#ifndef FUNCTION_EXECUTOR_H
#define FUNCTION_EXECUTOR_H
#include "inner/common/task_executor.h"
namespace OHOS {
namespace Media {
using FunctionEntry = std::function<ExecStatus(const sptr<ExecuteEvent>&)>;
class FunctionExecutor : public TaskExecutor {
public:
    FunctionExecutor();
    ~FunctionExecutor();
public:
    ExecStatus Register(std::vector<std::string> &events) override;
    ExecStatus BeforeExecute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus Execute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus AfterExecute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus Finally(const sptr<ExecuteEvent> &executeEvent) override;
public:
    const std::string GetClassName() const override;
    void Dump() const override;
private:
    ExecStatus DoTest01(const sptr<ExecuteEvent> &executeEvent);
    ExecStatus DoTest02(const sptr<ExecuteEvent> &executeEvent);
private:
    std::map<const std::string, FunctionEntry> entryMap_;
};
} // namespace Media
} // namespace OHOS
#endif // FUNCTION_EXECUTOR_H
