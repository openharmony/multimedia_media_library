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

#define MLOG_TAG "MediaBgTask_TaskScheduleParamManager"

#include "task_schedule_param_manager.h"

#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>

#ifdef CONFIG_POLICY_PUSH_SUPPORT
#include "config_policy_param_upgrade_path.h"
#include "config_policy_utils.h"
#endif
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service.h"
#include "media_bgtask_utils.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
// param used for cota common event
constexpr const char *COTA_UPDATE_EVENT = "usual.event.DUE_SA_CFG_UPDATED";
constexpr const char *COTA_SCH_POLICY_UPDATE = "medialibary_unify_schedule";
constexpr const char *COTA_EVENT_INFO_TYPE = "type";
constexpr const char *COTA_EVENT_INFO_SUBTYPE = "subtype";
const int COTA_EVENT_SUBSCRIBE_DELAY_TIME = 300;  // 单位ms，公共事件订阅CES服务还没拉起，需要延时再订阅

// params used for json file parsing
const std::string LOCAL_TASK_SCH_PARAM_FILE_PATH = "/system/etc/medialibary_schedule_task_cfg/task_schedule_param.json";
const std::string TASK_SCH_POLICY_COTA_CFG_DIR = "etc/medialibary_unify_schedule/";
const std::string TASK_SCH_POLICY_COTA_CFG_FILE = "schedule_policy.json";
const std::string TASK_SCH_POLICY_LOCAL_DIR = "/system/etc/medialibary_schedule_task_cfg/";

const std::string TAG_TASKLIST = "taskList";
const std::string TAG_TASKID = "taskId";
const std::string TAG_TYPE = "type";
const std::string TAG_SAID = "saId";
const std::string TAG_BUNDLENAME = "bundleName";
const std::string TAG_ABILITYNAME = "abilityName";
const std::string TAG_TASKPOLICY = "taskPolicy";
const std::string TAG_PRIORITY_LVL = "priorityLevel";
const std::string TAG_PRIORITY_FACTOR = "priorityFactor";
const std::string TAG_MAX_TOLERANCE_TIME = "maxToleranceTime";
const std::string TAG_MAX_RUNNING_TIME = "maxRunningTime";
const std::string TAG_LOAD_LVL = "loadLevel";
const std::string TAG_LOADSCALE = "loadscale";
const std::string TAG_CRITICALRES = "criticalRes";
const std::string TAG_CONFLICTEDTASK = "conflictedTask";
const std::string TAG_DEFAULTRUN = "defaultRun";
const std::string TAG_STARTCONDITION = "startCondition";
const std::string TAG_TIMERINTERVAL = "timerInterval";
const std::string TAG_RESCHEDULEINTERVAL = "reScheduleInterval";
const std::string TAG_CONDITIONARRAY = "conditionArray";
const std::string TAG_ISCHARGING = "isCharging";
const std::string TAG_NETWORKTYPE = "networkType";
const std::string TAG_BATTERYCAPACITY = "batteryCapacity";
const std::string TAG_STORAGEFREE = "storageFree";
const std::string TAG_CHECKPARAMBEFORERUN = "checkParamBeforeRun";
const std::string TAG_SCREENOFF = "screenOff";

const std::string TAG_SCHEDULE_ENABLE = "scheduleEnable";
const std::string TAG_AGING_FACTOR_MAP = "agingFactorMap";
const std::string TAG_TEMPERATURE_LEVEL_THRED_NOCHARING = "temperatureLevelThredNoCharing";
const std::string TAG_TEMPERATURE_LEVEL_THRED_CHARING = "temperatureLevelThredCharing";
const std::string TAG_LOAD_THRED_HIGH = "loadThredHigh";
const std::string TAG_LOAD_THRED_MEDIUM = "loadThredMedium";
const std::string TAG_LOAD_THRED_LOW = "loadThredLow";
const std::string TAG_WAITING_PRESSURE_THRED = "waitingPressureThred";
const std::string TAG_SYS_LOAD_L_LVL = "sysLoadLowLevel";
const std::string TAG_SYS_LOAD_M_LVL = "sysLoadMediumLevel";
const std::string TAG_MIN_NEXT_INTERVAL = "minNextInterval";

class TaskScheduleParamManager::CotaUpdateReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit CotaUpdateReceiver(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    ~CotaUpdateReceiver() {}
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

TaskScheduleParamManager::CotaUpdateReceiver::CotaUpdateReceiver(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
}

void TaskScheduleParamManager::CotaUpdateReceiver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    std::string type = data.GetWant().GetStringParam(COTA_EVENT_INFO_TYPE);
    std::string subtype = data.GetWant().GetStringParam(COTA_EVENT_INFO_SUBTYPE);
    MEDIA_INFO_LOG("CotaUpdateReceiver: action[%{public}s], type[%{public}s], subType[%{public}s]", action.c_str(),
                   type.c_str(), subtype.c_str());

    if (action != COTA_UPDATE_EVENT || type != COTA_SCH_POLICY_UPDATE) {
        MEDIA_ERR_LOG("other action, ignore.");
        return;
    }

    TaskScheduleParamManager::GetInstance().UpdateCotaParams();
}

TaskScheduleParamManager::TaskScheduleParamManager()
{
    MEDIA_INFO_LOG("TaskScheduleParamManager constructor start.");
}

TaskScheduleParamManager::~TaskScheduleParamManager()
{
    MEDIA_WARN_LOG("TaskScheduleParamManager destructing");
    UnsubscribeCotaUpdatedEvent();
}

void TaskScheduleParamManager::SubscribeCotaUpdatedEvent()
{
    // private function, only called in constructor, no need to lock.
    if (cotaUpdateSubscriber_ != nullptr) {
        MEDIA_WARN_LOG("cota update event already subscribed.");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(COTA_UPDATE_EVENT);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission("ohos.permission.RECEIVE_UPDATE_MESSAGE");
    cotaUpdateSubscriber_ = std::make_shared<CotaUpdateReceiver>(subscribeInfo);
    if (cotaUpdateSubscriber_ == nullptr) {
        MEDIA_ERR_LOG("cota update subscriber nullptr.");
        return;
    }

    if (EventFwk::CommonEventManager::SubscribeCommonEvent(cotaUpdateSubscriber_)) {
        MEDIA_WARN_LOG("Subscribe cota update event successed");
        return;
    }
    MEDIA_ERR_LOG("Subscribe cota update event fail");
    // 公共事件订阅CES服务还没拉起导致订阅失败，需要延时再订阅
    std::this_thread::sleep_for(std::chrono::milliseconds(COTA_EVENT_SUBSCRIBE_DELAY_TIME));
    if (EventFwk::CommonEventManager::SubscribeCommonEvent(cotaUpdateSubscriber_)) {
        MEDIA_INFO_LOG("Sleep for subscribe cota update event successed");
    } else {
        MEDIA_ERR_LOG("Sleep for subscribe cota update event fail");
    }
}

void TaskScheduleParamManager::UnsubscribeCotaUpdatedEvent()
{
    // private function, only called in destructor, no need to lock.
    if (cotaUpdateSubscriber_ == nullptr) {
        MEDIA_WARN_LOG("cota updat event not subscribed.");
        return;
    }
    bool subscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(cotaUpdateSubscriber_);
    MEDIA_INFO_LOG("subscribeResult = %{public}d", subscribeResult);
    cotaUpdateSubscriber_ = nullptr;
}

void TaskScheduleParamManager::ReadIntMap(const cJSON *const jsonData, int &first, int &second)
{
    if (jsonData == nullptr) {
        MEDIA_DEBUG_LOG("jsonData is not exist");
        return;
    }
    if (!cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("no json array");
        return;
    }

    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize != MAX_RANGE_NUM_CNT) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsNumber(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return;
        }
        if (i == 0) {
            first = static_cast<int>(cJSON_GetNumberValue(value));
        } else {
            second = static_cast<int>(cJSON_GetNumberValue(value));
            return;
        }
    }
}

void TaskScheduleParamManager::ReadFloatMap(const cJSON *const jsonData, float &first, float &second)
{
    if (jsonData == nullptr) {
        MEDIA_DEBUG_LOG("jsonData is not exist");
        return;
    }
    if (!cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("no json array");
        return;
    }

    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize != MAX_RANGE_NUM_CNT) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsNumber(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return;
        }
        if (i == 0) {
            first = static_cast<float>(cJSON_GetNumberValue(value));
        } else {
            second = static_cast<float>(cJSON_GetNumberValue(value));
            return;
        }
    }
}

bool TaskScheduleParamManager::GetStringFromJsonObj(const cJSON *const jsonObj, const std::string &key,
                                                    std::string &value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }
    cJSON *jsonObjItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if ((jsonObjItem == nullptr) || !cJSON_IsString(jsonObjItem)) {
        return false;
    }
    value = cJSON_GetStringValue(jsonObjItem);
    return true;
}

bool TaskScheduleParamManager::GetIntFromJsonObj(const cJSON *const jsonObj, const std::string &key, int &value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }
    cJSON *jsonObjItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if ((jsonObjItem == nullptr) || !cJSON_IsNumber(jsonObjItem)) {
        return false;
    }
    value = static_cast<int>(cJSON_GetNumberValue(jsonObjItem));
    return true;
}

bool TaskScheduleParamManager::GetFloatFromJsonObj(const cJSON *const jsonObj, const std::string &key, float &value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }
    cJSON *jsonObjItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if ((jsonObjItem == nullptr) || !cJSON_IsNumber(jsonObjItem)) {
        return false;
    }
    value = static_cast<float>(cJSON_GetNumberValue(jsonObjItem));
    return true;
}

bool TaskScheduleParamManager::GetBoolFromJsonObj(const cJSON *const jsonObj, const std::string &key, bool &value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }
    cJSON *jsonObjItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if ((jsonObjItem == nullptr) || !cJSON_IsBool(jsonObjItem)) {
        return false;
    }
    value = cJSON_IsTrue(jsonObjItem);
    return true;
}

bool TaskScheduleParamManager::GetObjFromJsonObj(const cJSON *const jsonObj, const std::string &key, cJSON **value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }
    cJSON *jsonObjItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if ((jsonObjItem == nullptr) || !cJSON_IsObject(jsonObjItem)) {
        return false;
    }
    *value = cJSON_Duplicate(jsonObjItem, true);
    return true;
}

void TaskScheduleParamManager::GetConflictedTaskFromJson(const cJSON *paramData,
                                                         std::vector<std::string> &conflictedTask)
{
    MEDIA_DEBUG_LOG("parsing field [%{public}s]", TAG_CONFLICTEDTASK.c_str());
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(paramData, TAG_CONFLICTEDTASK.c_str());
    if (jsonData == nullptr || !cJSON_IsArray(jsonData)) {
        MEDIA_DEBUG_LOG("no field [%{public}s]", TAG_CONFLICTEDTASK.c_str());
        return;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_TASK_LIST_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsString(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return;
        }
        conflictedTask.push_back(cJSON_GetStringValue(value));
        MEDIA_DEBUG_LOG("%{public}s = %{public}s", TAG_CONFLICTEDTASK.c_str(), value->valuestring);
    }
}

bool TaskScheduleParamManager::GetStartConditionFromJson(const cJSON *paramData, TaskStartCondition &startCondition)
{
    MEDIA_DEBUG_LOG("parsing [%{public}s]", TAG_STARTCONDITION.c_str());
    cJSON *startConditionJson = nullptr;
    if (!GetObjFromJsonObj(paramData, TAG_STARTCONDITION, &startConditionJson)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_STARTCONDITION.c_str());
        return false;
    }

    if (!GetIntFromJsonObj(startConditionJson, TAG_TIMERINTERVAL, startCondition.timerInterval)) {
        MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_TIMERINTERVAL.c_str());
    }
    if (!GetIntFromJsonObj(startConditionJson, TAG_RESCHEDULEINTERVAL, startCondition.reScheduleInterval)) {
        MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_RESCHEDULEINTERVAL.c_str());
    }

    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(startConditionJson, TAG_CONDITIONARRAY.c_str());
    if (jsonData == nullptr || !cJSON_IsArray(jsonData)) {
        MEDIA_DEBUG_LOG("no field [%{public}s]", TAG_CONDITIONARRAY.c_str());
        return false;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_CONDITION_ARRAY_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsObject(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not object, index[%{public}d]", i);
            return false;
        }
        MEDIA_DEBUG_LOG("parse %{public}s,i = %{public}d", TAG_CONDITIONARRAY.c_str(), i);
        TaskStartSubCondition taskStartSubCondition;
        (void)GetIntFromJsonObj(value, TAG_ISCHARGING, taskStartSubCondition.isCharging);
        CFG_CHECK_AND_RETURN(taskStartSubCondition.isCharging, 0, MAX_ISCHARGING_VALUE, TAG_ISCHARGING);
        (void)GetIntFromJsonObj(value, TAG_BATTERYCAPACITY, taskStartSubCondition.batteryCapacity);
        CFG_CHECK_AND_RETURN(taskStartSubCondition.batteryCapacity, 0, MAX_BATTERYCAPACITY, TAG_BATTERYCAPACITY);
        (void)GetIntFromJsonObj(value, TAG_SCREENOFF, taskStartSubCondition.screenOff);
        CFG_CHECK_AND_RETURN(taskStartSubCondition.screenOff, 0, MAX_SCREENOFF_VALUE, TAG_SCREENOFF);
        (void)GetStringFromJsonObj(value, TAG_NETWORKTYPE, taskStartSubCondition.networkType);
        (void)GetStringFromJsonObj(value, TAG_CHECKPARAMBEFORERUN, taskStartSubCondition.checkParamBeforeRun);
        ReadIntMap(cJSON_GetObjectItemCaseSensitive(value, TAG_STORAGEFREE.c_str()),
                   taskStartSubCondition.storageFreeRangeLow, taskStartSubCondition.storageFreeRangeHig);
        CFG_CHECK_AND_RETURN(taskStartSubCondition.storageFreeRangeLow, 0, MAX_STORAGEFREE, TAG_STORAGEFREE);
        CFG_CHECK_AND_RETURN(taskStartSubCondition.storageFreeRangeHig, 0, MAX_STORAGEFREE, TAG_STORAGEFREE);
        CHECK_AND_RETURN_RET_LOG(taskStartSubCondition.storageFreeRangeLow <= taskStartSubCondition.storageFreeRangeHig,
                                 false, "storageFreeRange err");
        startCondition.conditionArray.push_back(taskStartSubCondition);
        MEDIA_DEBUG_LOG("batteryCapacity = %{public}d", taskStartSubCondition.batteryCapacity);
    }
    return true;
}

bool TaskScheduleParamManager::VerifyTaskPolicy(const TaskScheduleCfg &taskScheduleCfg)
{
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.priorityLevel, 0, MAX_PRIORITY_LEVEL, TAG_PRIORITY_LVL);
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.priorityFactor, 1, MAX_PRIORITY_FACTOR, TAG_PRIORITY_FACTOR);
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.maxToleranceTime, 1, MAX_TOLERANCE_TIME, TAG_MAX_TOLERANCE_TIME);
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.maxRunningTime, 1, MAX_RUNNING_TIME, TAG_MAX_RUNNING_TIME);
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.loadLevel, 0, MAX_LOAD_LEVEL, TAG_LOAD_LVL);
    CFG_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.loadScale, 1, MAX_LOADSCALE, TAG_LOADSCALE);
    return true;
}

bool TaskScheduleParamManager::GetTaskPolicyFromJson(const cJSON *value, TaskScheduleCfg &taskScheduleCfg)
{
    cJSON *taskPolicy = nullptr;
    if (!GetObjFromJsonObj(value, TAG_TASKPOLICY, &taskPolicy)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_TASKPOLICY.c_str());
        return false;
    }
    if (!GetIntFromJsonObj(taskPolicy, TAG_PRIORITY_LVL, taskScheduleCfg.taskPolicy.priorityLevel)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_PRIORITY_LVL.c_str());
        return false;
    }
    if (!GetIntFromJsonObj(taskPolicy, TAG_PRIORITY_FACTOR, taskScheduleCfg.taskPolicy.priorityFactor)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_PRIORITY_FACTOR.c_str());
        return false;
    }
    if (!GetIntFromJsonObj(taskPolicy, TAG_MAX_TOLERANCE_TIME, taskScheduleCfg.taskPolicy.maxToleranceTime)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_MAX_TOLERANCE_TIME.c_str());
        return false;
    }

    (void)GetIntFromJsonObj(taskPolicy, TAG_MAX_RUNNING_TIME, taskScheduleCfg.taskPolicy.maxRunningTime);

    if (!GetIntFromJsonObj(taskPolicy, TAG_LOAD_LVL, taskScheduleCfg.taskPolicy.loadLevel)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_LOAD_LVL.c_str());
        return false;
    }
    if (!GetIntFromJsonObj(taskPolicy, TAG_LOADSCALE, taskScheduleCfg.taskPolicy.loadScale)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_LOADSCALE.c_str());
        return false;
    }
    if (!GetStringFromJsonObj(taskPolicy, TAG_CRITICALRES, taskScheduleCfg.taskPolicy.criticalRes)) {
        MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_CRITICALRES.c_str());
    }
    if (!GetBoolFromJsonObj(taskPolicy, TAG_DEFAULTRUN, taskScheduleCfg.taskPolicy.defaultRun)) {
        MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_DEFAULTRUN.c_str());
    }
    GetConflictedTaskFromJson(taskPolicy, taskScheduleCfg.taskPolicy.conflictedTask);
    if (!VerifyTaskPolicy(taskScheduleCfg)) {
        MEDIA_ERR_LOG("TaskPolicy invalid!");
        return false;
    }
    if (!GetStartConditionFromJson(taskPolicy, taskScheduleCfg.taskPolicy.startCondition)) {
        taskScheduleCfg.taskPolicy.startCondition.conditionArray.clear();
        MEDIA_ERR_LOG("StartCondition invalid!");
        return false;
    }
    MEDIA_INFO_LOG("priorityLevel: %{public}d loadLevel: %{public}d maxRunningTime: %{public}d",
                   taskScheduleCfg.taskPolicy.priorityLevel, taskScheduleCfg.taskPolicy.loadLevel,
                   taskScheduleCfg.taskPolicy.maxRunningTime);
    return true;
}

bool TaskScheduleParamManager::GetTaskListFromJson(const cJSON *paramData,
                                                   std::vector<TaskScheduleCfg> &taskScheduleCfgList)
{
    MEDIA_DEBUG_LOG("parsing [%{public}s]", TAG_TASKLIST.c_str());
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(paramData, TAG_TASKLIST.c_str());
    if (jsonData == nullptr || !cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("fail to parse field [%{public}s]", TAG_TASKLIST.c_str());
        return false;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_TASK_LIST_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr) {
            MEDIA_ERR_LOG("json value nullptr, index[%{public}d]", i);
            return false;
        }
        TaskScheduleCfg taskScheduleCfg;
        if (!GetStringFromJsonObj(value, TAG_TASKID, taskScheduleCfg.taskId)) {
            MEDIA_ERR_LOG("Did't define %s in json.", TAG_TASKID.c_str());
            return false;
        }
        if (!GetStringFromJsonObj(value, TAG_TYPE, taskScheduleCfg.type)) {
            MEDIA_ERR_LOG("Did't define %s in json.", TAG_TYPE.c_str());
            return false;
        }
        if (!GetIntFromJsonObj(value, TAG_SAID, taskScheduleCfg.saId)) {
            MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_SAID.c_str());
        }
        if (!GetStringFromJsonObj(value, TAG_BUNDLENAME, taskScheduleCfg.bundleName)) {
            MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_BUNDLENAME.c_str());
        }
        if (!GetStringFromJsonObj(value, TAG_ABILITYNAME, taskScheduleCfg.abilityName)) {
            MEDIA_DEBUG_LOG("Did't define %s in json.", TAG_ABILITYNAME.c_str());
        }
        if (!GetTaskPolicyFromJson(value, taskScheduleCfg)) {
            MEDIA_ERR_LOG("Get task policy from json fail.");
            return false;
        }
        MEDIA_INFO_LOG("parse %{public}s,idx[%{public}d] taskName: %{public}s", TAG_TASKLIST.c_str(), i,
                       taskScheduleCfg.taskId.c_str());
        taskScheduleCfgList.push_back(taskScheduleCfg);
    }
    return true;
}

void TaskScheduleParamManager::GetAgingFactorMapFromJson(const cJSON *json)
{
    MEDIA_INFO_LOG("parsing [%{public}s]", TAG_AGING_FACTOR_MAP.c_str());
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(json, TAG_AGING_FACTOR_MAP.c_str());
    if (jsonData == nullptr || !cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("fail to parse field [%{public}s]", TAG_AGING_FACTOR_MAP.c_str());
        return;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_AGING_FACTOR_MAP_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return;
    }
    unifySchedulePolicyCfg_.agingFactorMap.clear();
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        MEDIA_DEBUG_LOG("parse %{public}s, index[%{public}d]", TAG_AGING_FACTOR_MAP.c_str(), i);
        AgingFactorMapElement agingFactorMapElement;
        ReadFloatMap(value, agingFactorMapElement.waitingPressure, agingFactorMapElement.agingFactor);
        MEDIA_INFO_LOG("waitingPressure: %{public}f, agingFactor: %{public}f", agingFactorMapElement.waitingPressure,
                       agingFactorMapElement.agingFactor);
        CFG_CHECK_AND_SET_DEFAULT(agingFactorMapElement.waitingPressure, 0, MAX_WAITING_PRESSURE,
                                  DEFAULT_WAITING_PRESSURE, TAG_AGING_FACTOR_MAP);
        CFG_CHECK_AND_SET_DEFAULT(agingFactorMapElement.agingFactor, 0, MAX_WAITING_PRESSURE, DEFAULT_AGING_FACTOR,
                                  TAG_AGING_FACTOR_MAP);
        unifySchedulePolicyCfg_.agingFactorMap.push_back(agingFactorMapElement);
    }
    MEDIA_INFO_LOG("agingFactorMap.size [%{public}zu]", unifySchedulePolicyCfg_.agingFactorMap.size());
}

void TaskScheduleParamManager::GetUnifySchedulePolicyCfgFromJson(const cJSON *json)
{
    UnifySchedulePolicyCfg cfg = {};
    if (!GetBoolFromJsonObj(json, TAG_SCHEDULE_ENABLE, cfg.scheduleEnable)) {
        MEDIA_ERR_LOG("Did't define %{public}s in json.", TAG_SCHEDULE_ENABLE.c_str());
        return;
    }
    if (!GetIntFromJsonObj(json, TAG_TEMPERATURE_LEVEL_THRED_NOCHARING, cfg.temperatureLevelThredNoCharing)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_TEMPERATURE_LEVEL_THRED_NOCHARING.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.temperatureLevelThredNoCharing, 0, MAX_TEMPERATURE_LEVEL,
                              DEFAULT_TEMP_LEVEL_THRED_NOCHARING, TAG_TEMPERATURE_LEVEL_THRED_NOCHARING);

    if (!GetIntFromJsonObj(json, TAG_TEMPERATURE_LEVEL_THRED_CHARING, cfg.temperatureLevelThredCharing)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_TEMPERATURE_LEVEL_THRED_CHARING.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.temperatureLevelThredCharing, 0, MAX_TEMPERATURE_LEVEL,
                              DEFAULT_TEMP_LEVEL_THRED_CHARING, TAG_TEMPERATURE_LEVEL_THRED_CHARING);

    if (!GetIntFromJsonObj(json, TAG_LOAD_THRED_HIGH, cfg.loadThredHigh)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_LOAD_THRED_HIGH.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.loadThredHigh, 0, MAX_LOAD_THRED, DEFAULT_LOAD_THRED_HIGH, TAG_LOAD_THRED_HIGH);

    if (!GetIntFromJsonObj(json, TAG_LOAD_THRED_MEDIUM, cfg.loadThredMedium)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_LOAD_THRED_MEDIUM.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.loadThredMedium, 0, MAX_LOAD_THRED, DEFAULT_LOAD_THRED_MEDIUM, TAG_LOAD_THRED_MEDIUM);

    if (!GetIntFromJsonObj(json, TAG_LOAD_THRED_LOW, cfg.loadThredLow)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_LOAD_THRED_LOW.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.loadThredLow, 0, MAX_LOAD_THRED, DEFAULT_LOAD_THRED_LOW, TAG_LOAD_THRED_LOW);

    if (!GetFloatFromJsonObj(json, TAG_WAITING_PRESSURE_THRED, cfg.waitingPressureThred)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_WAITING_PRESSURE_THRED.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.waitingPressureThred, 0, MAX_WAITING_PRESSURE, DEFAULT_WAITING_PRESSURE_THRED,
                              TAG_WAITING_PRESSURE_THRED);

    if (!GetIntFromJsonObj(json, TAG_SYS_LOAD_L_LVL, cfg.sysLoadLowLevel)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_SYS_LOAD_L_LVL.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.sysLoadLowLevel, 0, MAX_SYS_LOAD_LEVEL, DEFAULT_SYSLOAD_L_LVL, TAG_SYS_LOAD_L_LVL);

    if (!GetIntFromJsonObj(json, TAG_SYS_LOAD_M_LVL, cfg.sysLoadMediumLevel)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_SYS_LOAD_M_LVL.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.sysLoadMediumLevel, 0, MAX_SYS_LOAD_LEVEL, DEFAULT_SYSLOAD_M_LVL, TAG_SYS_LOAD_M_LVL);

    if (!GetIntFromJsonObj(json, TAG_MIN_NEXT_INTERVAL, cfg.minNextInterval)) {
        MEDIA_DEBUG_LOG("Did't define %{public}s in json.", TAG_MIN_NEXT_INTERVAL.c_str());
    }
    CFG_CHECK_AND_SET_DEFAULT(cfg.minNextInterval, 1, MAX_NEXT_INTERVAL, DEFAULT_NEXT_INTERVAL, TAG_MIN_NEXT_INTERVAL);
    unifySchedulePolicyCfg_ = cfg;
    GetAgingFactorMapFromJson(json);
    MEDIA_INFO_LOG("SchedulePolicy enable: %{public}d, thermalLevelThred:NoCharing[%{public}d] Charing[%{public}d]",
                   cfg.scheduleEnable, cfg.temperatureLevelThredNoCharing, cfg.temperatureLevelThredCharing);
}

void TaskScheduleParamManager::ParseTaskScheduleCfg(const std::string &filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open()) {
        MEDIA_ERR_LOG("fail to open file %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
        return;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    MEDIA_DEBUG_LOG("%{public}s.%{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str(), content.c_str());
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        MEDIA_ERR_LOG("json content nullptr.");
        return;
    }

    taskScheduleCfgList_.clear();
    if (!GetTaskListFromJson(json, taskScheduleCfgList_)) {
        MEDIA_ERR_LOG("get task list from Json fail.");
        taskScheduleCfgList_.clear();
    } else {
        MEDIA_INFO_LOG("Parse local task cfg succeed, task list size [%{public}zu]", taskScheduleCfgList_.size());
    }
    cJSON_Delete(json);
}

void TaskScheduleParamManager::ParseUnifySchedulePolicyCfg(const std::string &filepath)
{
    std::ifstream file(filepath);
    MEDIA_INFO_LOG("filepath: %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
    if (!file.is_open()) {
        MEDIA_ERR_LOG("fail to open file %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
        return;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    MEDIA_DEBUG_LOG("%{public}s.%{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str(), content.c_str());

    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        MEDIA_ERR_LOG("json content nullptr.");
        return;
    }
    GetUnifySchedulePolicyCfgFromJson(json);
    cJSON_Delete(json);
    MEDIA_INFO_LOG("Parse unify schedule policy succeed.");
}

std::string TaskScheduleParamManager::GetParamPath()
{
#ifdef CONFIG_POLICY_PUSH_SUPPORT
    // 获取云推参数高版本路径
    HwCustSetDataSourceType(HW_CUST_TYPE_SYSTEM);

    ParamVersionFileInfo *paramVersionFileInfo =
        GetDownloadCfgFile(TASK_SCH_POLICY_COTA_CFG_DIR.c_str(), TASK_SCH_POLICY_COTA_CFG_DIR.c_str());
    if (paramVersionFileInfo == NULL) {
        MEDIA_ERR_LOG("paramVersionFileInfo is null in path :  %{public}s", TASK_SCH_POLICY_COTA_CFG_DIR.c_str());
        return "";
    }

    if (!paramVersionFileInfo->found) {
        MEDIA_ERR_LOG("can not found version txt in path :  %{public}s", TASK_SCH_POLICY_COTA_CFG_DIR.c_str());
        free(paramVersionFileInfo);
        return "";
    }
    std::string path = std::string(paramVersionFileInfo->path);
    free(paramVersionFileInfo);
    return path;
#else
    return TASK_SCH_POLICY_LOCAL_DIR;
#endif
}

void TaskScheduleParamManager::InitParams()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("InitParams start.");
    SubscribeCotaUpdatedEvent();
    ParseTaskScheduleCfg(LOCAL_TASK_SCH_PARAM_FILE_PATH);
    ParseUnifySchedulePolicyCfg(GetParamPath() + TASK_SCH_POLICY_COTA_CFG_FILE);
}

std::vector<TaskScheduleCfg> &TaskScheduleParamManager::GetAllTaskCfg()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return taskScheduleCfgList_;
}

UnifySchedulePolicyCfg &TaskScheduleParamManager::GetScheduleCfg()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return unifySchedulePolicyCfg_;
}

void TaskScheduleParamManager::UpdateUnifySchedulePolicyCfg()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("Update unify schedule policy cfg.");
    ParseUnifySchedulePolicyCfg(GetParamPath() + TASK_SCH_POLICY_COTA_CFG_FILE);
}

void TaskScheduleParamManager::UpdateCotaParams()
{
    UpdateUnifySchedulePolicyCfg();
    MediaBgtaskScheduleService::GetInstance().HandleScheduleParamUpdate();
}
}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
