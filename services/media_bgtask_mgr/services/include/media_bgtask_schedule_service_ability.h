/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MEDIA_BGTASK_SCHEDULE_SERVICE_ABILITY_H
#define MEDIA_BGTASK_SCHEDULE_SERVICE_ABILITY_H

#include "system_ability.h"
#include "imml_task_mgr.h"
#include "app_bgtask_schedule_stub.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class MediaBgtaskScheduleServiceAbility : public SystemAbility, public AppBgTaskScheduleStub {
public:
    DECLARE_SYSTEM_ABILITY(MediaTaskScheduleServiceAbility);

    MediaBgtaskScheduleServiceAbility(const int32_t systemAbilityId, bool runOnCreate);
    ~MediaBgtaskScheduleServiceAbility();

    ErrCode ReportTaskComplete(const std::string& task_name, int32_t& funcResult) override;
    ErrCode ModifyTask(const std::string& task_name, const std::string& modifyInfo, int32_t& funcResult) override;
protected:
    void OnStart(const SystemAbilityOnDemandReason& activeReason) override;
    void OnStop() override;
    void OnActive(const SystemAbilityOnDemandReason& activeReason) override;
    int32_t OnSvcCmd(int32_t fd, const std::vector<std::u16string>& args) override;
    int32_t OnIdle(const SystemAbilityOnDemandReason& idleReason) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;

    void Init();

    std::atomic<bool> registerToService_{false};
    std::mutex systemAbilityMutex_;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // MEDIA_BGTASK_SCHEDULE_SERVICE_ABILITY_H
