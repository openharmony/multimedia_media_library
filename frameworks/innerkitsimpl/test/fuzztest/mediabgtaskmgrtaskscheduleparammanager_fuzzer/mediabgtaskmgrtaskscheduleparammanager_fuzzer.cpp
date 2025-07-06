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

#include "mediabgtaskmgrtaskscheduleparammanager_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "task_schedule_param_manager.h"
#include "media_bgtask_schedule_service.h"
#undef private
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>

#ifdef CONFIG_POLICY_PUSH_SUPPORT
#include "config_policy_param_upgrade_path.h"
#include "config_policy_utils.h"
#endif
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_utils.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int32_t INT32_COUNT = 3;
const int8_t STRING_COUNT = 8;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int8_t) * STRING_COUNT;

TaskScheduleParamManager &instance = TaskScheduleParamManager::GetInstance();

static void TaskScheduleParamManagerFuzzerTest(std::string &content)
{
    instance.InitParams();
    instance.GetAllTaskCfg();
    instance.GetScheduleCfg();
    instance.UpdateCotaParams();
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();

    cJSON *json = cJSON_Parse(content.c_str());
    cJSON *scheduleJson = cJSON_GetObjectItem(json, "taskScheduleParam");
    cJSON *systemJson = cJSON_GetObjectItem(json, "schedulePolicy");

    instance.taskScheduleCfgList_.clear();
    instance.GetTaskListFromJson(scheduleJson, instance.taskScheduleCfgList_);
    instance.UpdateUnifySchedulePolicyCfgFromJson(systemJson);
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
    std::string content(data, data + size);
    /* Run your code on data */
    OHOS::TaskScheduleParamManagerFuzzerTest(content);
    return 0;
}
