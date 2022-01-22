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
#ifndef TASK_EVENT_RECEIVER_H
#define TASK_EVENT_RECEIVER_H
#include <map>
#include <vector>
#include <singleton.h>
#include "inner/common/execute_common.h"
#include "inner/common/task_executor.h"
#include "inner/common/task_dispatch.h"
namespace OHOS {
namespace Media {
class TaskEventReceiver : public Singleton<TaskEventReceiver>, public TaskDispatch {
public:
    TaskEventReceiver();
    ~TaskEventReceiver();
public:
    void Init(void);
    void OnEvent(const std::string &event);
public:
    virtual void Dump() const;
private:
    void AddAllExecutors();
    void DoEvent(const sptr<ExecuteEvent> &executeEvent);
    void AddExecutor(sptr<TaskExecutor> taskExecutor);
private:
    bool inited_ {false};
    std::map<const std::string, std::vector<sptr<TaskExecutor>>> eventMap_;
};
} // namespace Media
} // namespace OHOS
#endif // TASK_EVENT_RECEIVER_H
