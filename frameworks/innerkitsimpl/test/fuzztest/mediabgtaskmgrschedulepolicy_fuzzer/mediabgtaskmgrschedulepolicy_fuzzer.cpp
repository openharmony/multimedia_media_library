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

#include "mediabgtaskmgrschedulepolicy_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "schedule_policy.h"
#include "task_schedule_param_manager.h"
#undef private

#include <vector>
#include <algorithm>
#include <iostream>
#include "media_bgtask_utils.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const std::string TAG_NEEDCOMPUTE = "needCompute";
const std::string TAG_UNLOCKED = "unlocked";
const std::string TAG_CHARGING = "charging";
const std::string TAG_SCREENOFF = "screenOff";
const std::string TAG_LOADLEVEL = "loadLevel";
const std::string TAG_THERMALLEVEL = "thermalLevel";
const std::string TAG_BATTERYCAP = "batteryCap";
const std::string TAG_WIFICONNECTED = "wifiConnected";
const std::string TAG_CELLULARCONNECT = "CellularConnect";
const std::string TAG_STORAGEFREE = "storageFree";
const std::string TAG_NOW = "now";

const std::string TAG_TASKID = "taskId";
const std::string TAG_LASTSTOPTIME = "lastStopTime";
const std::string TAG_ISRUNNING = "isRunning";
const std::string TAG_EXCEEDENERGY = "exceedEnergy";
const std::string TAG_ISCOMPLETE = "isComplete";

TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();

FuzzedDataProvider *FDP = nullptr;

static void ParseTaskScheduleCfg(const cJSON *const scheduleJson)
{
    if (scheduleJson == nullptr) {
        return;
    }
    manager.taskScheduleCfgList_.clear();
    if (!manager.GetTaskListFromJson(scheduleJson, manager.taskScheduleCfgList_)) {
        manager.taskScheduleCfgList_.clear();
    }
}

static void ParseUnifySchedulePolicyCfg(const cJSON *const cloudJson)
{
    if (cloudJson == nullptr) {
        return;
    }
    manager.UpdateUnifySchedulePolicyCfgFromJson(cloudJson);
}

static void ParseTaskListJson(std::vector<TaskScheduleCfg> &taskScheduleCfgList,
                              std::map<std::string, TaskInfo> &taskInfos)
{
    for (const auto &taskScheduleCfg: taskScheduleCfgList) {
        TaskInfo taskInfo;
        taskInfo.taskId = taskScheduleCfg.taskId;
        taskInfo.scheduleCfg = taskScheduleCfg;
        taskInfos[taskInfo.taskId] = taskInfo;
    }
}

void ParseSystemStatus(const cJSON *const systemJson, SystemInfo& sysInfo, std::map<std::string, TaskInfo> &taskInfos)
{
    if (systemJson == nullptr) {
        return;
    }
    // 设置systemInfo
    cJSON *systemInfoJson = nullptr;
    manager.GetObjFromJsonObj(systemJson, "systemInfo", &systemInfoJson);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_NEEDCOMPUTE, sysInfo.needCompute);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_UNLOCKED, sysInfo.unlocked);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_CHARGING, sysInfo.charging);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_SCREENOFF, sysInfo.screenOff);
    manager.GetIntFromJsonObj(systemInfoJson, TAG_LOADLEVEL, sysInfo.loadLevel);
    manager.GetIntFromJsonObj(systemInfoJson, TAG_THERMALLEVEL, sysInfo.thermalLevel);
    manager.GetIntFromJsonObj(systemInfoJson, TAG_BATTERYCAP, sysInfo.batteryCap);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_WIFICONNECTED, sysInfo.wifiConnected);
    manager.GetBoolFromJsonObj(systemInfoJson, TAG_CELLULARCONNECT, sysInfo.CellularConnect);
    manager.GetIntFromJsonObj(systemInfoJson, TAG_STORAGEFREE, sysInfo.storageFree);
    int now;
    manager.GetIntFromJsonObj(systemInfoJson, TAG_NOW, now);
    sysInfo.now = static_cast<time_t>(now);

    cJSON *taskStatusJson = cJSON_GetObjectItemCaseSensitive(systemJson, "taskStatus");
    int jsonDataSize = cJSON_GetArraySize(taskStatusJson);
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(taskStatusJson, i);
        std::string taskId;
        manager.GetStringFromJsonObj(value, TAG_TASKID, taskId);
        if (taskInfos.find(taskId) != taskInfos.end()) {
            int time;
            manager.GetIntFromJsonObj(value, TAG_LASTSTOPTIME, time);
            taskInfos[taskId].lastStopTime = static_cast<time_t>(time);
            manager.GetBoolFromJsonObj(value, TAG_ISRUNNING, taskInfos[taskId].isRunning);
            manager.GetBoolFromJsonObj(value, TAG_EXCEEDENERGY, taskInfos[taskId].exceedEnergy);
            manager.GetBoolFromJsonObj(value, TAG_ISCOMPLETE, taskInfos[taskId].isComplete);
        }
    }
}

void SetTask(const std::map<std::string, TaskInfo> &taskInfos)
{
    // 获取所有任务
    schedulePolicy.allTasksList_.clear();
    for (std::map<std::string, TaskInfo>::const_iterator it = taskInfos.begin(); it != taskInfos.end(); it++) {
        TaskInfo task = it->second;
        schedulePolicy.allTasksList_.insert(std::make_pair(it->first, task));
    }
}

static void UnifyReadConfig(const std::string &data, SystemInfo &sysInfo, std::map<std::string, TaskInfo> &taskInfos)
{
    cJSON *json = cJSON_Parse(data.c_str());
    cJSON *scheduleJson = cJSON_GetObjectItem(json, "taskScheduleParam");
    cJSON *cloudJson = cJSON_GetObjectItem(json, "cloudParams");
    cJSON *systemJson = cJSON_GetObjectItem(json, "systemStatus");
    ParseTaskScheduleCfg(scheduleJson);
    ParseUnifySchedulePolicyCfg(cloudJson);
    ParseTaskListJson(manager.taskScheduleCfgList_, taskInfos);

    ParseSystemStatus(systemJson, sysInfo, taskInfos);

    schedulePolicy.SetSchedulePolicy(manager.unifySchedulePolicyCfg_);
    SetTask(taskInfos);
    schedulePolicy.sysInfo_ = sysInfo;
    cJSON_Delete(json);
}

static void SchedulePolicyFuzzerTest(std::string &content)
{
    SchedulePolicy &policy = SchedulePolicy::GetInstance();
    std::map<std::string, TaskInfo> testTaskInfos;
    SystemInfo testSysInfo;
    UnifyReadConfig(content, testSysInfo, testTaskInfos);
    schedulePolicy.ScheduleTasks(testTaskInfos, testSysInfo);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string content(data, data + size);
    /* Run your code on data */
    OHOS::SchedulePolicyFuzzerTest(content);
    return 0;
}
