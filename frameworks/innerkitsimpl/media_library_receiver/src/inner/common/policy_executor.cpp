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
#include "inner/common/policy_executor.h"
#include <string_ex.h>
#include "media_log.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "PolicyExecutor";
}
PolicyExecutor::PolicyExecutor()
{
    MEDIA_DEBUG_LOG("PolicyExecutor created[%{public}d]|", GetID());
}

PolicyExecutor::~PolicyExecutor()
{
    MEDIA_DEBUG_LOG("PolicyExecutor released[%{public}d]|", GetID());
}

const std::string PolicyExecutor::GetClassName() const
{
    return CLASS_NAME;
}

void PolicyExecutor::Dump() const
{
    TaskExecutor::Dump();
}

void PolicyExecutor::AddPolicy(const std::string &policy, const sptr<ExecutePolicy> &executePolicy)
{
    MEDIA_DEBUG_LOG("PolicyExecutor::AddPolicy enter[%{public}d]|policy=%{public}s", GetID(), policy.c_str());

    std::string trimedPolicy = TrimStr(policy);
    if ((executePolicy == nullptr) || trimedPolicy.empty()) {
        MEDIA_ERR_LOG("PolicyExecutor::AddPolicy error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("PolicyExecutor::AddPolicy leave[%{public}d]|parameter", GetID());
        return;
    }

    if (policyMap_.count(trimedPolicy) < 1) {
        std::vector<sptr<ExecutePolicy>> tempUsed;
        policyMap_.insert(std::make_pair(trimedPolicy, tempUsed));
    }

    auto &executePolicys = policyMap_[trimedPolicy];
    executePolicys.push_back(executePolicy);

    MEDIA_DEBUG_LOG("PolicyExecutor::AddPolicy leave[%{public}d]|", GetID());
}

std::vector<sptr<ExecutePolicy>> &PolicyExecutor::GetPolicy(const std::string &policy)
{
    MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicy enter[%{public}d]|policy=%{public}s", GetID(), policy.c_str());

    std::string trimedPolicy = TrimStr(policy);
    if (trimedPolicy.empty()) {
        MEDIA_ERR_LOG("PolicyExecutor::GetPolicy error[%{public}d]|parameter", GetID());
        MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicy leave[%{public}d]|parameter", GetID());
        return emptyList_;
    }

    if (policyMap_.count(policy) < 1) {
        MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicy leave[%{public}d]|empty", GetID());
        return emptyList_;
    }

    auto &ret = policyMap_[policy];

    MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicy leave[%{public}d]|size=%{public}d", GetID(), ret.size());
    return ret;
}

void PolicyExecutor::GetPolicys(std::vector<std::string> &policys) const
{
    MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicys enter[%{public}d]|size=%{public}d", GetID(), policys.size());

    for (auto item : policyMap_) {
        policys.push_back(item.first);
    }

    MEDIA_DEBUG_LOG("PolicyExecutor::GetPolicys leave[%{public}d]|size=%{public}d", GetID(), policys.size());
}
} // namespace Media
} // namespace OHOS