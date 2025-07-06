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

#include "mediabgtaskmgrscheduleservice_fuzzer.h"

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
const int8_t STRING_COUNT = 5;

const int32_t CONDITION_ZERO = 0;
const int32_t CONDITION_ONE = 1;
const int32_t CONDITION_TWO = 2;
const int32_t CONDITION_THREE = 3;
const int32_t MAX_COUNT = 4;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT);

FuzzedDataProvider *FDP = nullptr;

static TaskScheduleResult FuzzResult()
{
    std::map <std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    TaskScheduleResult result;
    for (int i = 0; i < MAX_COUNT; i++) {
        std::string id = FDP->ConsumeBytesAsString(1);
        TaskInfo taskInfo;
        if (i != CONDITION_THREE) {
            if (i == 0) {
                taskInfo.scheduleCfg.type = "sa";
            } else if (i == CONDITION_ONE) {
                taskInfo.scheduleCfg.type = "app";
            }
            allTask[id] = taskInfo;
        }
        result.taskStop_.push_back(id);
        result.taskStart_.push_back(id);
    }
    return result;
}

static std::string FuzzModifyInfo()
{
    int32_t index = FDP->ConsumeIntegralInRange<int32_t>(0, 3);
    if (index == CONDITION_ZERO) {
        return "taskRun:true";
    }
    if (index == CONDITION_ONE) {
        return "taskRun:false";
    }
    if (index == CONDITION_TWO) {
        return "taskRun:skipToday";
    }
    return "";
}

static void MediaBgTaskScheduleServiceFuzzerTest()
{
    MediaBgtaskScheduleService &instance =  MediaBgtaskScheduleService::GetInstance();
    std::string taskId = FDP->ConsumeBool() ? "" : FDP->ConsumeBytesAsString(1) + ":";
    instance.GetTaskNameFromId(taskId);

    TaskScheduleResult compResult = FuzzResult();
    instance.HandleStopTask(compResult);
    instance.HandleStartTask(compResult);

    int32_t index = FDP->ConsumeIntegralInRange<int32_t>(0, 3);
    int32_t funcResult;
    std::string modifyInfo = FuzzModifyInfo();

    instance.modifyTask(compResult.taskStop_[index], modifyInfo, funcResult);
    instance.reportTaskComplete(compResult.taskStop_[index], funcResult);
    instance.HandleReschedule();
    instance.HandleScheduleParamUpdate();
    instance.HandleSystemStateChange();
    instance.HandleTaskStateChange();
    instance.HandleTimerCome();
    instance.ClearAllSchedule();
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
    OHOS::MediaBgTaskScheduleServiceFuzzerTest();
    return 0;
}
