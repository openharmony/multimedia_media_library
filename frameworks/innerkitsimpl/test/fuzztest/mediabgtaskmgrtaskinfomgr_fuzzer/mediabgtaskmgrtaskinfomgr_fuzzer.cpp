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

#include "mediabgtaskmgrtaskinfomgr_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio>

#define private public
#include "task_info_mgr.h"
#undef private
#include "directory_ex.h"
#include "file_ex.h"
#include "string_ex.h"
#include "task_schedule_cfg.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_utils.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int8_t BOOL_COUNT = 1;
const int8_t STRING_COUNT = 1;
const int MIN_SIZE = sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT);

TaskInfoMgr &instance = TaskInfoMgr::GetInstance();
FuzzedDataProvider *FDP = nullptr;


static void TaskInfoMgrFuzzerTest()
{
    TaskScheduleCfg cfg;
    cfg.taskId = FDP->ConsumeBytesAsString(1);
    std::vector<TaskScheduleCfg> taskCfgs;
    taskCfgs.push_back(cfg);

    instance.InitTaskInfoByCfg(taskCfgs);
    instance.GetAllTask();

    bool onlyCriticalInfo = FDP->ConsumeBool();
    instance.SaveTaskState(onlyCriticalInfo);

    instance.RestoreTaskState();
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::FDP = &fdp;

    /* Run your code on data */
    OHOS::TaskInfoMgrFuzzerTest();
    return 0;
}
