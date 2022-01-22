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
#ifndef POLICY_EXECUTOR_H
#define POLICY_EXECUTOR_H
#include <map>
#include <vector>
#include "inner/common/task_executor.h"
#include "inner/common/execute_policy.h"
namespace OHOS {
namespace Media {
class PolicyExecutor : public TaskExecutor {
public:
    PolicyExecutor();
    ~PolicyExecutor();
public:
    const std::string GetClassName() const override;
    void Dump() const override;
protected:
    void AddPolicy(const std::string &policy, const sptr<ExecutePolicy> &executePolicy);
    std::vector<sptr<ExecutePolicy>> &GetPolicy(const std::string &policy);
    void GetPolicys(std::vector<std::string> &policys) const;
private:
    std::map<const std::string, std::vector<sptr<ExecutePolicy>>> policyMap_;
    std::vector<sptr<ExecutePolicy>> emptyList_;
};
} // namespace Media
} // namespace OHOS
#endif // POLICY_EXECUTOR_H
