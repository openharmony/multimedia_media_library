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
#ifndef TASK_SCH_PARAM_MANAGER_H
#define TASK_SCH_PARAM_MANAGER_H

#include <map>
#include <mutex>
#include <set>
#include <string>

#include "cJSON.h"
#include "common_event_manager.h"
#include "task_schedule_cfg.h"

#define CFG_CHECK_AND_RETURN(value, rangeLow, rangeHigh, logString)                                 \
    do {                                                                                         \
        if (((value) != -1) && ((value) < (rangeLow) || (value) > (rangeHigh))) {                \
            MEDIA_ERR_LOG("[%{public}s: %{public}d] value invalid", (logString).c_str(), value); \
            return false;                                                                        \
        }                                                                                        \
    } while (0)

#define CFG_CHECK_AND_SET_DEFAULT(value, rangeLow, rangeHigh, defaultVal, logString) \
    do {                                                                             \
        if ((value) < (rangeLow) || (value) > (rangeHigh)) {                         \
            MEDIA_ERR_LOG("[%{public}s] value invalid", (logString).c_str());        \
            value = defaultVal;                                                      \
        }                                                                            \
    } while (0)

#define CFG_PURE_CHECK_AND_RETURN(value, rangeLow, rangeHigh, logString)                                 \
    do {                                                                                         \
        if ((value) < (rangeLow) || (value) > (rangeHigh)) {                \
            MEDIA_ERR_LOG("[%{public}s: %{public}d] value invalid", (logString).c_str(), value); \
            return false;                                                                        \
        }                                                                                        \
    } while (0)

namespace OHOS {
namespace MediaBgtaskSchedule {

class TaskScheduleParamManager {
public:
    static TaskScheduleParamManager &GetInstance()
    {
        static TaskScheduleParamManager instance;
        return instance;
    }

    // SA启动的时候，初始化配置
    void InitParams();

    //  获取所有的任务配置
    std::vector<TaskScheduleCfg> &GetAllTaskCfg();

    // 获取调度策略配置，如果有云推的，要返回最新的
    UnifySchedulePolicyCfg &GetScheduleCfg();

    // 内部使用，云推参数更新事件触发CotaUpdateReceiver调用
    void UpdateCotaParams();

private:
    TaskScheduleParamManager();
    ~TaskScheduleParamManager();

    void SubscribeCotaUpdatedEvent();
    void UnsubscribeCotaUpdatedEvent();

    void ReadIntMap(const cJSON *const jsonData, int &first, int &second);
    void ReadFloatMap(const cJSON *const jsonData, float &first, float &second);
    bool GetStringFromJsonObj(const cJSON *const jsonObj, const std::string &key, std::string &value);
    bool GetIntFromJsonObj(const cJSON *const jsonObj, const std::string &key, int &value);
    bool GetFloatFromJsonObj(const cJSON *const jsonObj, const std::string &key, float &value);
    bool GetBoolFromJsonObj(const cJSON *const jsonObj, const std::string &key, bool &value);
    bool GetObjFromJsonObj(const cJSON *const jsonObj, const std::string &key, cJSON **value);
    void GetConflictedTaskFromJson(const cJSON *paramData, std::vector<std::string> &conflictedTask);
    bool VerifyTaskPolicy(const TaskScheduleCfg &taskScheduleCfg);
    bool GetTaskPolicyFromJson(const cJSON *value, TaskScheduleCfg &taskScheduleCfg);
    bool GetStartConditionFromJson(const cJSON *paramData, TaskStartCondition &startCondition);
    bool GetTaskListFromJson(const cJSON *paramData, std::vector<TaskScheduleCfg> &taskScheduleCfgList);
    void GetAgingFactorMapFromJson(const cJSON *json);
    void GetUnifySchedulePolicyCfgFromJson(const cJSON *json);
    void ParseTaskScheduleCfg(const std::string &filepath);
    void ParseUnifySchedulePolicyCfg(const std::string &filepath);

    std::string GetParamPath();
    void UpdateUnifySchedulePolicyCfg();
    class CotaUpdateReceiver;

private:
    std::shared_ptr<EventFwk::CommonEventSubscriber> cotaUpdateSubscriber_{};
    std::mutex mutex_{};
    std::vector<TaskScheduleCfg> taskScheduleCfgList_{};
    UnifySchedulePolicyCfg unifySchedulePolicyCfg_{};
};
}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
#endif  // TASK_SCH_PARAM_MANAGER_H
