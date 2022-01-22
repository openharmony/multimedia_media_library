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
#ifndef THUMBNAIL_BATCH_GEN_EXECUTOR_H
#define THUMBNAIL_BATCH_GEN_EXECUTOR_H
#include <map>
#include <vector>
#include "inner/common/execute_policy.h"
#include "inner/common/policy_executor.h"
namespace OHOS {
namespace Media {
class ThumbnailBatchGenExecutor : public PolicyExecutor {
public:
    ExecStatus Register(std::vector<std::string> &events) override;
    ExecStatus BeforeExecute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus Execute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus AfterExecute(const sptr<ExecuteEvent> &executeEvent) override;
    ExecStatus Finally(const sptr<ExecuteEvent> &executeEvent) override;
public:
    const std::string GetClassName() const override;
    void Dump() const override;
};
} // namespace Media
} // namespace OHOS
#endif // THUMBNAIL_BATCH_GEN_EXECUTOR_H
