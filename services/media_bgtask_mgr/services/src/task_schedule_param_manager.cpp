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
const std::string TAG_RESCHEDULEINTERVAL = "reScheduleInterval";
const std::string TAG_CONDITIONARRAY = "conditionArray";
const std::string TAG_ISCHARGING = "isCharging";
const std::string TAG_NETWORKTYPE = "networkType";
const std::string TAG_BATTERYCAPACITY = "batteryCapacity";
const std::string TAG_STORAGEFREE = "storageFree";
const std::string TAG_CHECKPARAMBEFORERUN = "checkParamBeforeRun";
const std::string TAG_SCREENOFF = "screenOff";
const std::string TAG_STARTTHERMALLEVELDAY = "startThermalLevelDay";
const std::string TAG_STARTTHERMALLEVELNIGHT = "startThermalLevelNight";

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

bool TaskScheduleParamManager::SubscribeCotaUpdatedEvent()
{
    // private function, only called in constructor, no need to lock.
    if (cotaUpdateSubscriber_ != nullptr) {
        MEDIA_WARN_LOG("cota update event already subscribed.");
        return true;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(COTA_UPDATE_EVENT);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission("ohos.permission.RECEIVE_UPDATE_MESSAGE");
    cotaUpdateSubscriber_ = std::make_shared<CotaUpdateReceiver>(subscribeInfo);
    if (cotaUpdateSubscriber_ == nullptr) {
        MEDIA_ERR_LOG("cota update subscriber nullptr.");
        return false;
    }

    if (EventFwk::CommonEventManager::SubscribeCommonEvent(cotaUpdateSubscriber_)) {
        MEDIA_WARN_LOG("Subscribe cota update event successed");
        return true;
    }
    MEDIA_ERR_LOG("Subscribe cota update event fail");
    // 公共事件订阅CES服务还没拉起导致订阅失败，需要延时再订阅
    std::this_thread::sleep_for(std::chrono::milliseconds(COTA_EVENT_SUBSCRIBE_DELAY_TIME));
    if (EventFwk::CommonEventManager::SubscribeCommonEvent(cotaUpdateSubscriber_)) {
        MEDIA_INFO_LOG("Sleep for subscribe cota update event successed");
        return true;
    } else {
        MEDIA_ERR_LOG("Sleep for subscribe cota update event fail");
        return false;
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

bool TaskScheduleParamManager::ReadIntMap(const cJSON *const jsonData, int &first, int &second)
{
    if (jsonData == nullptr) {
        MEDIA_DEBUG_LOG("jsonData is not exist");
        return false;
    }
    if (!cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("no json array");
        return false;
    }

    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize != MAX_RANGE_NUM_CNT) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsNumber(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return false;
        }
        if (i == 0) {
            first = static_cast<int>(cJSON_GetNumberValue(value));
        } else {
            second = static_cast<int>(cJSON_GetNumberValue(value));
            return true;
        }
    }
    return true;
}

bool TaskScheduleParamManager::ReadFloatMap(const cJSON *const jsonData, float &first, float &second)
{
    if (jsonData == nullptr) {
        MEDIA_ERR_LOG("jsonData is not exist");
        return false;
    }
    if (!cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("no json array");
        return false;
    }

    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize != MAX_RANGE_NUM_CNT) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsNumber(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return false;
        }
        if (i == 0) {
            first = static_cast<float>(cJSON_GetNumberValue(value));
        } else {
            second = static_cast<float>(cJSON_GetNumberValue(value));
            return true;
        }
    }
    return true;
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

bool TaskScheduleParamManager::GetConflictedTaskFromJson(const cJSON *paramData,
                                                         std::vector<std::string> &conflictedTask)
{
    MEDIA_DEBUG_LOG("parsing field [%{public}s]", TAG_CONFLICTEDTASK.c_str());
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(paramData, TAG_CONFLICTEDTASK.c_str());
    if (jsonData == nullptr) {
        MEDIA_WARN_LOG("no field [%{public}s]", TAG_CONFLICTEDTASK.c_str());
        return true;
    }
    if (!cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("field [%{public}s] is not array", TAG_CONFLICTEDTASK.c_str());
        return false;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_TASK_LIST_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr || !cJSON_IsString(value)) {
            MEDIA_ERR_LOG("json value nullptr or param is not string, index[%{public}d]", i);
            return false;
        }
        conflictedTask.push_back(cJSON_GetStringValue(value));
        MEDIA_DEBUG_LOG("%{public}s = %{public}s", TAG_CONFLICTEDTASK.c_str(), value->valuestring);
    }
    return true;
}

bool TaskScheduleParamManager::ParseSubCondition(const cJSON *value, TaskStartSubCondition &subCondition)
{
    if (value == nullptr || !cJSON_IsObject(value)) {
        MEDIA_ERR_LOG("Sub-condition JSON value is null or not an object.");
        return false;
    }

    (void)GetIntFromJsonObj(value, TAG_ISCHARGING, subCondition.isCharging);
    CFG_CHECK_AND_RETURN(subCondition.isCharging, 0, MAX_ISCHARGING_VALUE, TAG_ISCHARGING);

    (void)GetIntFromJsonObj(value, TAG_BATTERYCAPACITY, subCondition.batteryCapacity);
    CFG_CHECK_AND_RETURN(subCondition.batteryCapacity, 0, MAX_BATTERYCAPACITY, TAG_BATTERYCAPACITY);

    (void)GetIntFromJsonObj(value, TAG_SCREENOFF, subCondition.screenOff);
    CFG_CHECK_AND_RETURN(subCondition.screenOff, 0, MAX_SCREENOFF_VALUE, TAG_SCREENOFF);

    (void)GetIntFromJsonObj(value, TAG_STARTTHERMALLEVELDAY, subCondition.startThermalLevelDay);
    CFG_CHECK_AND_RETURN(subCondition.startThermalLevelDay, 0, MAX_TEMPERATURE_LEVEL, TAG_STARTTHERMALLEVELDAY);

    (void)GetIntFromJsonObj(value, TAG_STARTTHERMALLEVELNIGHT, subCondition.startThermalLevelNight);
    CFG_CHECK_AND_RETURN(subCondition.startThermalLevelNight, 0, MAX_TEMPERATURE_LEVEL, TAG_STARTTHERMALLEVELNIGHT);

    (void)GetStringFromJsonObj(value, TAG_NETWORKTYPE, subCondition.networkType);
    (void)GetStringFromJsonObj(value, TAG_CHECKPARAMBEFORERUN, subCondition.checkParamBeforeRun);

    ReadIntMap(cJSON_GetObjectItemCaseSensitive(value, TAG_STORAGEFREE.c_str()),
               subCondition.storageFreeRangeLow, subCondition.storageFreeRangeHig);
    CFG_CHECK_AND_RETURN(subCondition.storageFreeRangeLow, 0, MAX_STORAGEFREE, TAG_STORAGEFREE);
    CFG_CHECK_AND_RETURN(subCondition.storageFreeRangeHig, 0, MAX_STORAGEFREE, TAG_STORAGEFREE);
    CHECK_AND_RETURN_RET_LOG(subCondition.storageFreeRangeLow <= subCondition.storageFreeRangeHig,
                             false, "storageFreeRange err");

    MEDIA_DEBUG_LOG("Parsed sub-condition: batteryCapacity = %{public}d", subCondition.batteryCapacity);
    return true;
}

bool TaskScheduleParamManager::GetStartConditionFromJson(const cJSON *paramData, TaskStartCondition &startCondition)
{
    MEDIA_DEBUG_LOG("Parsing [%{public}s]", TAG_STARTCONDITION.c_str());
    cJSON *startConditionJson = nullptr;
    if (!GetObjFromJsonObj(paramData, TAG_STARTCONDITION, &startConditionJson)) {
        MEDIA_ERR_LOG("Did not define %s in json.", TAG_STARTCONDITION.c_str());
        return false;
    }

    if (!GetIntFromJsonObj(startConditionJson, TAG_RESCHEDULEINTERVAL, startCondition.reScheduleInterval)) {
        MEDIA_DEBUG_LOG("Did not define %s in json.", TAG_RESCHEDULEINTERVAL.c_str());
    }

    cJSON *conditionArrayJson = cJSON_GetObjectItemCaseSensitive(startConditionJson, TAG_CONDITIONARRAY.c_str());
    if (conditionArrayJson == nullptr || !cJSON_IsArray(conditionArrayJson)) {
        MEDIA_DEBUG_LOG("No field [%{public}s] or it is not an array.", TAG_CONDITIONARRAY.c_str());
        return false;
    }

    int arraySize = cJSON_GetArraySize(conditionArrayJson);
    if (arraySize == 0 || arraySize > MAX_CONDITION_ARRAY_LEN) {
        MEDIA_ERR_LOG("Illegal array size for conditions: [%{public}d]", arraySize);
        return false;
    }

    for (int i = 0; i < arraySize; i++) {
        cJSON *item = cJSON_GetArrayItem(conditionArrayJson, i);
        TaskStartSubCondition subCondition;
        MEDIA_DEBUG_LOG("Parsing %{public}s, index = %{public}d", TAG_CONDITIONARRAY.c_str(), i);
        if (!ParseSubCondition(item, subCondition)) {
            MEDIA_ERR_LOG("Failed to parse sub-condition at index [%{public}d]", i);
            return false;
        }
        startCondition.conditionArray.push_back(subCondition);
    }

    return true;
}

bool TaskScheduleParamManager::VerifyTaskPolicy(const TaskScheduleCfg &taskScheduleCfg)
{
    CFG_PURE_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.priorityLevel, 0, MAX_PRIORITY_LEVEL, TAG_PRIORITY_LVL);
    CFG_PURE_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.priorityFactor, 1, MAX_PRIORITY_FACTOR, TAG_PRIORITY_FACTOR);
    CFG_PURE_CHECK_AND_RETURN(
        taskScheduleCfg.taskPolicy.maxToleranceTime, 1, MAX_TOLERANCE_TIME, TAG_MAX_TOLERANCE_TIME);
    CFG_PURE_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.maxRunningTime, 1, MAX_RUNNING_TIME, TAG_MAX_RUNNING_TIME);
    CFG_PURE_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.loadLevel, 0, MAX_LOAD_LEVEL, TAG_LOAD_LVL);
    CFG_PURE_CHECK_AND_RETURN(taskScheduleCfg.taskPolicy.loadScale, 1, MAX_LOADSCALE, TAG_LOADSCALE);
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
    if (!GetConflictedTaskFromJson(taskPolicy, taskScheduleCfg.taskPolicy.conflictedTask)) {
        MEDIA_ERR_LOG("fail to get conflicted task from json");
        return false;
    }
    if (!VerifyTaskPolicy(taskScheduleCfg)) {
        MEDIA_ERR_LOG("TaskPolicy invalid!");
        return false;
    }
    if (!GetStartConditionFromJson(taskPolicy, taskScheduleCfg.taskPolicy.startCondition)) {
        taskScheduleCfg.taskPolicy.startCondition.conditionArray.clear();
        MEDIA_ERR_LOG("StartCondition invalid!");
        return false;
    }
    MEDIA_INFO_LOG("priorityLevel: %{public}d, loadLevel: %{public}d",
                   taskScheduleCfg.taskPolicy.priorityLevel, taskScheduleCfg.taskPolicy.loadLevel);
    return true;
}

bool TaskScheduleParamManager::GetTaskIdFromJson(const cJSON *const value, TaskScheduleCfg &scheduleCfg,
                                                 std::unordered_set<std::string> &idSet)
{
    if (!GetStringFromJsonObj(value, TAG_TASKID, scheduleCfg.taskId)) {
        MEDIA_ERR_LOG("Did't define %s in json.", TAG_TASKID.c_str());
        return false;
    }
    if (idSet.find(scheduleCfg.taskId) != idSet.end()) {
        MEDIA_ERR_LOG("Did't redefine taskId %{public}s.", scheduleCfg.taskId.c_str());
        return false;
    }
    idSet.insert(scheduleCfg.taskId);
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
    std::unordered_set<std::string> curExistTaskId;
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        if (value == nullptr) {
            MEDIA_ERR_LOG("json value nullptr, index[%{public}d]", i);
            return false;
        }
        TaskScheduleCfg taskScheduleCfg;
        if (!GetTaskIdFromJson(value, taskScheduleCfg, curExistTaskId)) {
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

bool TaskScheduleParamManager::GetAgingFactorMapFromJson(const cJSON *json, UnifySchedulePolicyCfg& cfg)
{
    MEDIA_INFO_LOG("parsing [%{public}s]", TAG_AGING_FACTOR_MAP.c_str());
    cJSON *jsonData = cJSON_GetObjectItemCaseSensitive(json, TAG_AGING_FACTOR_MAP.c_str());
    if (jsonData == nullptr || !cJSON_IsArray(jsonData)) {
        MEDIA_ERR_LOG("fail to parse field [%{public}s]", TAG_AGING_FACTOR_MAP.c_str());
        return false;
    }
    int jsonDataSize = cJSON_GetArraySize(jsonData);
    if (jsonDataSize == 0 || jsonDataSize > MAX_AGING_FACTOR_MAP_LEN) {
        MEDIA_ERR_LOG("illegal array size [%{public}d]", jsonDataSize);
        return false;
    }
    cfg.agingFactorMap.clear();
    for (int i = 0; i < jsonDataSize; i++) {
        cJSON *value = cJSON_GetArrayItem(jsonData, i);
        MEDIA_DEBUG_LOG("parse %{public}s, index[%{public}d]", TAG_AGING_FACTOR_MAP.c_str(), i);
        AgingFactorMapElement agingFactorMapElement;
        if (!ReadFloatMap(value, agingFactorMapElement.waitingPressure, agingFactorMapElement.agingFactor)) {
            MEDIA_ERR_LOG("fail to read float map");
            return false;
        }
        MEDIA_INFO_LOG("waitingPressure: %{public}f, agingFactor: %{public}f", agingFactorMapElement.waitingPressure,
                       agingFactorMapElement.agingFactor);
        CFG_PURE_CHECK_AND_RETURN(agingFactorMapElement.waitingPressure, 0, MAX_WAITING_PRESSURE,
                                  TAG_AGING_FACTOR_MAP);
        CFG_PURE_CHECK_AND_RETURN(agingFactorMapElement.agingFactor, 0, MAX_WAITING_PRESSURE,
                                  TAG_AGING_FACTOR_MAP);
        cfg.agingFactorMap.push_back(agingFactorMapElement);
    }
    MEDIA_INFO_LOG("agingFactorMap.size [%{public}zu]", cfg.agingFactorMap.size());
    return true;
}

bool TaskScheduleParamManager::UpdateUnifySchedulePolicyCfgFromJson(const cJSON *json)
{
    UnifySchedulePolicyCfg cfg = {};
    CHECK_AND_RETURN_RET_LOG(GetBoolFromJsonObj(json, TAG_SCHEDULE_ENABLE, cfg.scheduleEnable),
        false, "Did't define %{public}s in json.", TAG_SCHEDULE_ENABLE.c_str());

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_TEMPERATURE_LEVEL_THRED_NOCHARING,
        cfg.temperatureLevelThredNoCharing), false, "Did't define %{public}s in json.",
        TAG_TEMPERATURE_LEVEL_THRED_NOCHARING.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.temperatureLevelThredNoCharing, 0, MAX_TEMPERATURE_LEVEL,
                              TAG_TEMPERATURE_LEVEL_THRED_NOCHARING);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_TEMPERATURE_LEVEL_THRED_CHARING,
        cfg.temperatureLevelThredCharing), false, "Did't define %{public}s in json.",
        TAG_TEMPERATURE_LEVEL_THRED_CHARING.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.temperatureLevelThredCharing, 0, MAX_TEMPERATURE_LEVEL,
                              TAG_TEMPERATURE_LEVEL_THRED_CHARING);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_LOAD_THRED_HIGH, cfg.loadThredHigh),
        false, "Did't define %{public}s in json.", TAG_LOAD_THRED_HIGH.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.loadThredHigh, 0, MAX_LOAD_THRED, TAG_LOAD_THRED_HIGH);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_LOAD_THRED_MEDIUM, cfg.loadThredMedium),
        false, "Did't define %{public}s in json.", TAG_LOAD_THRED_MEDIUM.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.loadThredMedium, 0, MAX_LOAD_THRED, TAG_LOAD_THRED_MEDIUM);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_LOAD_THRED_LOW, cfg.loadThredLow),
        false, "Did't define %{public}s in json.", TAG_LOAD_THRED_LOW.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.loadThredLow, 0, MAX_LOAD_THRED, TAG_LOAD_THRED_LOW);

    CHECK_AND_RETURN_RET_LOG(GetFloatFromJsonObj(json, TAG_WAITING_PRESSURE_THRED, cfg.waitingPressureThred),
        false, "Did't define %{public}s in json.", TAG_WAITING_PRESSURE_THRED.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.waitingPressureThred, 0, MAX_WAITING_PRESSURE,
                              TAG_WAITING_PRESSURE_THRED);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_SYS_LOAD_L_LVL, cfg.sysLoadLowLevel),
        false, "Did't define %{public}s in json.", TAG_SYS_LOAD_L_LVL.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.sysLoadLowLevel, 0, MAX_SYS_LOAD_LEVEL, TAG_SYS_LOAD_L_LVL);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_SYS_LOAD_M_LVL, cfg.sysLoadMediumLevel),
        false, "Did't define %{public}s in json.", TAG_SYS_LOAD_M_LVL.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.sysLoadMediumLevel, 0, MAX_SYS_LOAD_LEVEL, TAG_SYS_LOAD_M_LVL);

    CHECK_AND_RETURN_RET_LOG(GetIntFromJsonObj(json, TAG_MIN_NEXT_INTERVAL, cfg.minNextInterval),
        false, "Did't define %{public}s in json.", TAG_MIN_NEXT_INTERVAL.c_str());
    CFG_PURE_CHECK_AND_RETURN(cfg.minNextInterval, 1, MAX_NEXT_INTERVAL, TAG_MIN_NEXT_INTERVAL);

    if (!GetAgingFactorMapFromJson(json, cfg)) {
        MEDIA_ERR_LOG("fail to get aging factor map from json");
        return false;
    }
    unifySchedulePolicyCfg_ = cfg;
    MEDIA_INFO_LOG("SchedulePolicy enable: %{public}d, thermalLevelThred:NoCharing[%{public}d] Charing[%{public}d]",
                   cfg.scheduleEnable, cfg.temperatureLevelThredNoCharing, cfg.temperatureLevelThredCharing);
    return true;
}

bool TaskScheduleParamManager::ParseTaskScheduleCfg(const std::string &filepath)
{
    if (!MediaBgTaskUtils::IsFileExists(filepath)) {
        MEDIA_ERR_LOG("file not exist, path=%{private}s", filepath.c_str());
        return false;
    }
    std::ifstream file(filepath);
    if (!file.is_open()) {
        MEDIA_ERR_LOG("fail to open file %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    MEDIA_DEBUG_LOG("%{public}s.%{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str(), content.c_str());
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        MEDIA_ERR_LOG("json content nullptr.");
        return false;
    }

    taskScheduleCfgList_.clear();
    if (!GetTaskListFromJson(json, taskScheduleCfgList_)) {
        MEDIA_ERR_LOG("get task list from Json fail.");
        taskScheduleCfgList_.clear();
        return false;
    }
    MEDIA_INFO_LOG("Parse local task cfg succeed, task list size [%{public}zu]", taskScheduleCfgList_.size());
    cJSON_Delete(json);
    InitMaxRescheduleIntervalLocked();
    return true;
}

void TaskScheduleParamManager::InitMaxRescheduleIntervalLocked()
{
    maxRescheduleInerval_ = -1;
    for (auto &taskCfg : taskScheduleCfgList_) {
        auto taskRescheduleInterval = taskCfg.taskPolicy.startCondition.reScheduleInterval;
        maxRescheduleInerval_ = std::max(taskRescheduleInterval, maxRescheduleInerval_);
    }
    MEDIA_DEBUG_LOG("max reschedule interval:%{public}d", maxRescheduleInerval_);
}

int TaskScheduleParamManager::GetMaxRescheduleInerval()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return maxRescheduleInerval_;
}

bool TaskScheduleParamManager::ParseUnifySchedulePolicyCfg(const std::string &filepath)
{
    if (!MediaBgTaskUtils::IsFileExists(filepath)) {
        MEDIA_ERR_LOG("file not exist, path=%{private}s", filepath.c_str());
        return false;
    }
    std::ifstream file(filepath);
    MEDIA_INFO_LOG("filepath: %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
    if (!file.is_open()) {
        MEDIA_ERR_LOG("fail to open file %{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str());
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    MEDIA_DEBUG_LOG("%{public}s.%{public}s", MediaBgTaskUtils::DesensitizeUri(filepath).c_str(), content.c_str());

    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        MEDIA_ERR_LOG("json content nullptr.");
        return false;
    }
    if (!UpdateUnifySchedulePolicyCfgFromJson(json)) {
        MEDIA_ERR_LOG("get unify schedule policy config from Json fail.");
        return false;
    }
    cJSON_Delete(json);
    MEDIA_INFO_LOG("Parse unify schedule policy succeed.");
    return true;
}

std::string TaskScheduleParamManager::GetParamPathLocked()
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

bool TaskScheduleParamManager::InitParams()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("InitParams start.");
    if (!SubscribeCotaUpdatedEvent()) {
        MEDIA_ERR_LOG("fail to Subscribe CotaUpdated Event");
        return false;
    }
    if (!ParseTaskScheduleCfg(LOCAL_TASK_SCH_PARAM_FILE_PATH)) {
        MEDIA_ERR_LOG("fail to Parse Task Schedule config");
        return false;
    }
    if (!ParseUnifySchedulePolicyCfg(GetParamPathLocked() + TASK_SCH_POLICY_COTA_CFG_FILE)) {
        MEDIA_ERR_LOG("fail to Parse UnifySchedule Policy config");
        return false;
    }
    return true;
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

bool TaskScheduleParamManager::UpdateUnifySchedulePolicyCfg()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_INFO_LOG("Update unify schedule policy cfg.");
    if (!ParseUnifySchedulePolicyCfg(GetParamPathLocked() + TASK_SCH_POLICY_COTA_CFG_FILE)) {
        MEDIA_ERR_LOG("fail to update unify schedule policy cfg, retain old config.");
        return false;
    }
    return true;
}

void TaskScheduleParamManager::UpdateCotaParams()
{
    if (!UpdateUnifySchedulePolicyCfg()) {
        MEDIA_ERR_LOG("fail to update unify schedule policy config");
        return;
    }
    MediaBgtaskScheduleService::GetInstance().HandleScheduleParamUpdate();
}
}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
