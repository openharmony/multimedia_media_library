/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mediabgtaskmgrscheduleserviceability_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "media_bgtask_schedule_service.h"
#include "media_bgtask_schedule_service_ability.h"
#undef protected
#undef private

#include <cstdlib>
#include <string>
#include <map>
#include <thread>

#include "ffrt_inner.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_utils.h"
#include "schedule_policy.h"
#include "task_info_mgr.h"
#include "task_runner.h"
#include "task_schedule_param_manager.h"
#include "system_state_mgr.h"
#include "system_ability_definition.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

constexpr int MEDIA_TASK_SCHEDULE_SERVICE_ID = 3016;

const int32_t INT32_COUNT = 2;
const int8_t BOOL_COUNT = 1;
const int8_t STRING_COUNT = 3;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT);

MediaBgtaskScheduleServiceAbility ability(MEDIA_TASK_SCHEDULE_SERVICE_ID, true);
FuzzedDataProvider *FDP = nullptr;

static inline std::u16string FuzzTaskOpsValue()
{
    int32_t value = FDP->ConsumeIntegralInRange<int32_t>(-1, 1);
    switch (static_cast<MediaBgtaskSchedule::TaskOps>(value)) {
        case MediaBgtaskSchedule::TaskOps::START:
            return u"start";
        case MediaBgtaskSchedule::TaskOps::STOP:
            return u"stop";
        default:
            return u"other";
    }
}

static void MediaBgTaskScheduleServiceAbilityFuzzerTest()
{
    ability.registerToService_ = true;
    SystemAbilityOnDemandReason activeReason;
    ability.OnStart(activeReason);
    ability.OnActive(activeReason);
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();
    ability.OnIdle(activeReason);

    std::vector<std::u16string> args;
    args.push_back(u"-test");
    args.push_back(FDP->ConsumeBool() ? u"sa" : u"app");
    args.push_back(FuzzTaskOpsValue());
    args.push_back(Str8ToStr16(FDP->ConsumeBytesAsString(1)));
    std::string taskName = FDP->ConsumeBytesAsString(1);
    args.push_back(Str8ToStr16(taskName));
    ability.Dump(1, args);

    int32_t funcResult = FDP->ConsumeIntegral<int32_t>();
    ability.ReportTaskComplete(taskName, funcResult);
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();

    std::string modifyInfo = FDP->ConsumeBytesAsString(1);
    ability.ModifyTask(taskName, modifyInfo, funcResult);
    ability.OnStop();
}

static void Init()
{
    MediaBgtaskScheduleService::GetInstance().Init();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::FDP = &fdp;
    /* Run your code on data */
    OHOS::MediaBgTaskScheduleServiceAbilityFuzzerTest();
    return 0;
}
