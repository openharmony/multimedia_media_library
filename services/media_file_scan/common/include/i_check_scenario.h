/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIA_I_CHECK_SCENARIO_H
#define OHOS_MEDIA_I_CHECK_SCENARIO_H

#include "check_dfx_collector.h"
#include "consistency_check_data_types.h"

namespace OHOS::Media {
class ICheckScenario {
public:
    enum RunningStatus {
        FINISHED = 0,
        NOT_STARTED,
        INTERRUPTED
    };

    struct ScenarioContext {
        std::atomic<bool> &isInterrupted;
        CheckDfxCollector &dfxCollector;
        ConsistencyCheck::ScenarioProgress &progress;

        ScenarioContext(const ScenarioContext&) = delete;
        ScenarioContext& operator=(const ScenarioContext&) = delete;
        ScenarioContext(ScenarioContext&&) = delete;
        ScenarioContext& operator=(ScenarioContext&&) = delete;
    };

    virtual ~ICheckScenario() = default;
    virtual bool IsConditionSatisfied(const ConsistencyCheck::DeviceStatus &deviceStatus);
    virtual void Execute(std::atomic<bool> &isInterrupted) = 0;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_I_CHECK_SCENARIO_H