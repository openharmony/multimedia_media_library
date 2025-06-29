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

#define MLOG_TAG "MediaBgTask_TaskScheduleParamManagerTest"

#include "mediabgtaskmgr_task_schedule_param_manager.h"

#define private public
#include "task_schedule_param_manager.h"
#undef private

#include <sstream>
#include <fstream>
#include "config_policy_utils.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service.h"


using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

const std::string LOCAL_TASK_SCH_PARAM_FILE_PATH = "/system/etc/medialibary_schedule_task_cfg/task_schedule_param.json";
const std::string TAG_TASKLIST = "taskList";
const std::string TAG_TASKID = "taskId"; // string
const std::string TAG_TYPE = "type";
const std::string TAG_SAID = "saId";    // int
const std::string TAG_WAITING_PRESSURE_THRED = "waitingPressureThred"; // float
const std::string TAG_DEFAULTRUN = "defaultRun"; // boolean
const std::string TAG_STARTCONDITION = "startCondition"; // obj
const std::string TAG_TASKPOLICY = "taskPolicy";
const std::string TAG_PRIORITY_LVL = "priorityLevel";
const std::string TAG_PRIORITY_FACTOR = "priorityFactor";
const std::string TAG_MAXTOLERANCETIME = "maxToleranceTime";
const std::string TAG_LOAD_LVL = "loadLevel";
const std::string TAG_LOADSCALE = "loadscale";
const std::string TAG_CRITICALRES = "criticalRes";
const std::string TAG_CONFLICTEDTASK = "conflictedTask";
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
const std::string TAG_SYS_LOAD_L_LVL = "sysLoadLowLevel";
const std::string TAG_SYS_LOAD_M_LVL = "sysLoadMediumLevel";
const std::string TAG_MIN_NEXT_INTERVAL = "minNextInterval";

void MediaBgtaskMgrTaskScheduleParamManagerTest::SetUpTestCase() {}

void MediaBgtaskMgrTaskScheduleParamManagerTest::TearDownTestCase() {}

void MediaBgtaskMgrTaskScheduleParamManagerTest::SetUp()
{
    // 每次测试前重置单例状态
    TaskScheduleParamManager::GetInstance().taskScheduleCfgList_.clear();
    TaskScheduleParamManager::GetInstance().unifySchedulePolicyCfg_ = {};
}

void MediaBgtaskMgrTaskScheduleParamManagerTest::TearDown() {}

/**
 * InitParams
 */
// InitParams 读取默认配置文件测试，读取配置后，taskScheduleCfgList_ 不为空, agingFactorMap非空？
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_InitParams_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();

    // 确保初始状态为空
    EXPECT_TRUE(manager.taskScheduleCfgList_.empty());
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());

    manager.InitParams();

    // 默认设备中文件格式合法，初始化之后，taskScheduleCfgList_, agingFactorMap非空
    EXPECT_FALSE(manager.taskScheduleCfgList_.empty());
    EXPECT_LE(manager.taskScheduleCfgList_.size(), MAX_TASK_LIST_LEN);

    EXPECT_FALSE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());
    EXPECT_LE(manager.unifySchedulePolicyCfg_.agingFactorMap.size(), MAX_AGING_FACTOR_MAP_LEN);

    EXPECT_EQ(manager.unifySchedulePolicyCfg_.agingFactorMap.size(), manager.GetScheduleCfg().agingFactorMap.size());
}

// ParseTaskScheduleCfg 非法路径&非法数据, 提前返回，taskScheduleCfgList_数据为空
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_ParseTaskScheduleCfg_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    // 1. 非法路径
    manager.ParseTaskScheduleCfg("");
    EXPECT_TRUE(manager.taskScheduleCfgList_.empty());

    // 2. 合法路径，非法Json数据
    std::string tempFilePath = "/data/local/tmp/test_task_schedule.json";
    std::ofstream tempFile = std::ofstream(tempFilePath);
    tempFile << "invalid json content";
    tempFile.close();
    manager.ParseTaskScheduleCfg(tempFilePath);
    EXPECT_TRUE(manager.taskScheduleCfgList_.empty());
    if (tempFile.is_open()) {
        tempFile.close();
    }
    remove(tempFilePath.c_str());

    // 合法路径，合法Json结构，但无有效数据，为null
    tempFile = std::ofstream(tempFilePath);
    tempFile << "{}";
    tempFile.close();
    TaskScheduleCfg cfg;
    manager.taskScheduleCfgList_.push_back(cfg);
    manager.ParseTaskScheduleCfg(tempFilePath);
    EXPECT_TRUE(manager.taskScheduleCfgList_.empty());
    if (tempFile.is_open()) {
        tempFile.close();
    }
    remove(tempFilePath.c_str());
}

/**
 * ParseUnifySchedulePolicyCfg
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_ParseUnifySchedulePolicyCfg_test_001,
         TestSize.Level1)
{
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    // 1. 非法路径
    manager.ParseUnifySchedulePolicyCfg("");
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());

    // 2. 合法路径，非法Json数据
    std::string tempFilePath = "/data/local/tmp/test_task_schedule.json";
    std::ofstream tempFile = std::ofstream(tempFilePath);
    tempFile << "invalid json content";
    tempFile.close();
    manager.ParseUnifySchedulePolicyCfg(tempFilePath);
    EXPECT_TRUE(manager.taskScheduleCfgList_.empty());
    if (tempFile.is_open()) {
        tempFile.close();
    }
    remove(tempFilePath.c_str());
}

/**
 * GetUnifySchedulePolicyCfgFromJson
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetUnifySchedulePolicyCfgFromJson_test_001,
         TestSize.Level1)
{
    // 1. 测试当JSON只包含部分字段时，缺失TAG_SCHEDULE_ENABLE
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    cJSON* json = cJSON_CreateObject();
    manager.GetUnifySchedulePolicyCfgFromJson(json);
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.scheduleEnable);

    // 2. 添加TAG_SCHEDULE_ENABLE，缺少其他配置
    cJSON_AddFalseToObject(json, TAG_SCHEDULE_ENABLE.c_str());
    manager.GetUnifySchedulePolicyCfgFromJson(json);
    EXPECT_FALSE(manager.unifySchedulePolicyCfg_.scheduleEnable);
    EXPECT_EQ(DEFAULT_TEMP_LEVEL_THRED_NOCHARING, manager.unifySchedulePolicyCfg_.temperatureLevelThredNoCharing);
    EXPECT_EQ(DEFAULT_TEMP_LEVEL_THRED_CHARING, manager.unifySchedulePolicyCfg_.temperatureLevelThredCharing);
    EXPECT_EQ(DEFAULT_LOAD_THRED_HIGH, manager.unifySchedulePolicyCfg_.loadThredHigh);
    EXPECT_EQ(DEFAULT_LOAD_THRED_MEDIUM, manager.unifySchedulePolicyCfg_.loadThredMedium);
    EXPECT_EQ(DEFAULT_LOAD_THRED_LOW, manager.unifySchedulePolicyCfg_.loadThredLow);
    EXPECT_FLOAT_EQ(DEFAULT_WAITING_PRESSURE_THRED, manager.unifySchedulePolicyCfg_.waitingPressureThred);

    // 3. 添加TAG_SCHEDULE_ENABLE及其他配置
    cJSON_AddNumberToObject(json, TAG_TEMPERATURE_LEVEL_THRED_NOCHARING.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_TEMPERATURE_LEVEL_THRED_CHARING.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_LOAD_THRED_HIGH.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_LOAD_THRED_MEDIUM.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_LOAD_THRED_LOW.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_WAITING_PRESSURE_THRED.c_str(), 0.5);
    cJSON_AddNumberToObject(json, TAG_SYS_LOAD_L_LVL.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_SYS_LOAD_M_LVL.c_str(), 2);
    cJSON_AddNumberToObject(json, TAG_MIN_NEXT_INTERVAL.c_str(), 2);
    manager.GetUnifySchedulePolicyCfgFromJson(json);
    EXPECT_EQ(2, manager.unifySchedulePolicyCfg_.temperatureLevelThredNoCharing);
    EXPECT_EQ(2, manager.unifySchedulePolicyCfg_.temperatureLevelThredCharing);
    EXPECT_EQ(2, manager.unifySchedulePolicyCfg_.loadThredHigh);
    EXPECT_EQ(2, manager.unifySchedulePolicyCfg_.loadThredMedium);
    EXPECT_EQ(2, manager.unifySchedulePolicyCfg_.loadThredLow);
    EXPECT_FLOAT_EQ(0.5, manager.unifySchedulePolicyCfg_.waitingPressureThred);
    cJSON_Delete(json);
}

/**
 * GetAgingFactorMapFromJson
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetAgingFactorMapFromJson_test_001,
         TestSize.Level1)
{
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    // 1. 测试当传入的JSON对象不是数组时，agingFactorMap应被清空
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, TAG_AGING_FACTOR_MAP.c_str(), TAG_AGING_FACTOR_MAP.c_str());
    manager.GetAgingFactorMapFromJson(json);
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());
    cJSON_Delete(json);


    // 2. 测试当传入的JSON数组大小为0，或超过最大限制时，agingFactorMap应被清空
    json = cJSON_CreateObject();
    cJSON* array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, TAG_AGING_FACTOR_MAP.c_str(), array);
    manager.GetAgingFactorMapFromJson(json);
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());

    // 添加超过MAX_TASK_LIST_LEN个元素
    for (int i = 0; i <= MAX_AGING_FACTOR_MAP_LEN; ++i) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddItemToArray(array, item);
    }
    manager.GetAgingFactorMapFromJson(json);
    EXPECT_TRUE(manager.unifySchedulePolicyCfg_.agingFactorMap.empty());
    cJSON_Delete(json);
}

/**
 * GetTaskListFromJson非法校验，
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_001, TestSize.Level1)
{
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJson = cJSON_CreateObject();
    std::vector<TaskScheduleCfg> taskList;
    // 1. 测试当taskList字段不是数组时返回false
    cJSON_AddStringToObject(testJson, TAG_TASKLIST.c_str(), "");
    bool result = manager.GetTaskListFromJson(testJson, taskList);
    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_002, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testTaskList = cJSON_CreateArray();
    cJSON* testJson = cJSON_CreateObject();
    std::vector<TaskScheduleCfg> taskList;
    // 2. cJSON_GetArraySize 数据为0 或者 大于上限
    cJSON_AddItemToObject(testJson, TAG_TASKLIST.c_str(), testTaskList);
    bool result = manager.GetTaskListFromJson(testJson, taskList);
    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

void AddTestTask(cJSON *paramData, const std::string& taskId, const std::string& type)
{
    cJSON* task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, TAG_TASKID.c_str(), taskId.c_str());
    cJSON_AddStringToObject(task, TAG_TYPE.c_str(), type.c_str());
    cJSON_AddItemToArray(paramData, task);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_003, TestSize.Level1)
{
    cJSON* testTaskList = cJSON_CreateArray();
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddItemToObject(testJson, TAG_TASKLIST.c_str(), testTaskList);
    std::vector<TaskScheduleCfg> taskList;
    // 2. cJSON_GetArraySize 数据为0 或者 大于上限
    for (int i = 0; i < MAX_TASK_LIST_LEN + 1; ++i) {
        AddTestTask(testTaskList, "task" + std::to_string(i), "type" + std::to_string(i));
    }

    bool result = TaskScheduleParamManager::GetInstance().GetTaskListFromJson(testJson, taskList);

    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_004, TestSize.Level1)
{
    cJSON* testTaskList = cJSON_CreateArray();
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddItemToObject(testJson, TAG_TASKLIST.c_str(), testTaskList);
    std::vector<TaskScheduleCfg> taskList;
    // 3. 测试当任务缺少taskId字段时返回false
    cJSON* task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, TAG_TYPE.c_str(), TAG_TYPE.c_str());
    cJSON_AddItemToArray(testTaskList, task);
    bool result = TaskScheduleParamManager::GetInstance().GetTaskListFromJson(testJson, taskList);
    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_005, TestSize.Level1)
{
    cJSON* testTaskList = cJSON_CreateArray();
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddItemToObject(testJson, TAG_TASKLIST.c_str(), testTaskList);
    std::vector<TaskScheduleCfg> taskList;
    // 4. 测试当任务缺少type字段时返回false
    cJSON* task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, TAG_TASKID.c_str(), TAG_TASKID.c_str());
    cJSON_AddItemToArray(testTaskList, task);
    bool result = TaskScheduleParamManager::GetInstance().GetTaskListFromJson(testJson, taskList);
    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskListFromJson_test_006, TestSize.Level1)
{
    cJSON* testTaskList = cJSON_CreateArray();
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddItemToObject(testJson, TAG_TASKLIST.c_str(), testTaskList);
    std::vector<TaskScheduleCfg> taskList;
    // 5. 测试当任务包含所有必要字段时返回true
    cJSON* task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, TAG_TYPE.c_str(), TAG_TYPE.c_str());
    cJSON_AddStringToObject(task, TAG_TASKID.c_str(), TAG_TASKID.c_str());
    cJSON_AddItemToArray(testTaskList, task);
    bool result = TaskScheduleParamManager::GetInstance().GetTaskListFromJson(testJson, taskList);
    EXPECT_FALSE(result);
    EXPECT_TRUE(taskList.empty());
    cJSON_Delete(testJson);
}

/**
 * GetTaskPolicyFromJson
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_001, TestSize.Level1)
{
    // 1. 测试当taskPolicy中缺少priorityLevel字段时，函数应返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());

    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));

    cJSON_Delete(validJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_002, TestSize.Level1)
{
    // 2. 测试当taskPolicy中缺少priorityFactor字段时，函数应返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());
    cJSON *taskPolicy = cJSON_GetObjectItem(validJson, TAG_TASKPOLICY.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 1);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_Delete(validJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_003, TestSize.Level1)
{
    // 3. 测试当taskPolicy中缺少maxToleranceTime字段时，函数应返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());
    cJSON *taskPolicy = cJSON_GetObjectItem(validJson, TAG_TASKPOLICY.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 1);
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_FACTOR.c_str(), 2);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_Delete(validJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_004, TestSize.Level1)
{
    // 4. 测试当taskPolicy中缺少loadLevel字段时，函数应返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());
    cJSON *taskPolicy = cJSON_GetObjectItem(validJson, TAG_TASKPOLICY.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 1);
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_FACTOR.c_str(), 2);
    cJSON_AddNumberToObject(taskPolicy, TAG_MAXTOLERANCETIME.c_str(), 3);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_Delete(validJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_005, TestSize.Level1)
{
    // 5. 测试当taskPolicy中缺少loadScale字段时，函数应返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());
    cJSON *taskPolicy = cJSON_GetObjectItem(validJson, TAG_TASKPOLICY.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 1);
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_FACTOR.c_str(), 2);
    cJSON_AddNumberToObject(taskPolicy, TAG_MAXTOLERANCETIME.c_str(), 3);
    cJSON_AddNumberToObject(taskPolicy, TAG_LOAD_LVL.c_str(), 2);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_Delete(validJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetTaskPolicyFromJson_test_006, TestSize.Level1)
{
    // 6. 非法taskScheduleCfg.taskPolicy.priorityLevel 和 taskScheduleCfg.taskPolicy.loadLevel，返回false
    TaskScheduleCfg taskScheduleCfg;
    cJSON *validJson = cJSON_CreateObject();
    cJSON_AddItemToObject(validJson, TAG_TASKPOLICY.c_str(), cJSON_CreateObject());
    cJSON *taskPolicy = cJSON_GetObjectItem(validJson, TAG_TASKPOLICY.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 3);
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_FACTOR.c_str(), 2);
    cJSON_AddNumberToObject(taskPolicy, TAG_MAXTOLERANCETIME.c_str(), 3);
    cJSON_AddNumberToObject(taskPolicy, TAG_LOAD_LVL.c_str(), 2);
    cJSON_AddNumberToObject(taskPolicy, TAG_LOADSCALE.c_str(), 5);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_DeleteItemFromObject(taskPolicy, TAG_PRIORITY_LVL.c_str());
    cJSON_DeleteItemFromObject(taskPolicy, TAG_LOAD_LVL.c_str());
    cJSON_AddNumberToObject(taskPolicy, TAG_PRIORITY_LVL.c_str(), 1);
    cJSON_AddNumberToObject(taskPolicy, TAG_LOAD_LVL.c_str(), 3);
    EXPECT_FALSE(TaskScheduleParamManager::GetInstance().GetTaskPolicyFromJson(validJson, taskScheduleCfg));
    cJSON_Delete(validJson);
}

/**
 * GetConflictedTaskFromJson
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetConflictedTaskFromJson_test_001,
         TestSize.Level1)
{
    // 1. 测试当conflictedTask字段不是数组类型时，函数应返回空向量
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, TAG_CONFLICTEDTASK.c_str(), "not an array");
    std::vector<std::string> result;
    TaskScheduleParamManager::GetInstance().GetConflictedTaskFromJson(json, result);
    EXPECT_TRUE(result.empty());
    cJSON_Delete(json);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetConflictedTaskFromJson_test_002,
         TestSize.Level1)
{
    // 2. 测试当conflictedTask数组为空时，函数应返回空向量
    cJSON* json = cJSON_CreateObject();
    cJSON* array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, TAG_CONFLICTEDTASK.c_str(), array);
    std::vector<std::string> result;
    TaskScheduleParamManager::GetInstance().GetConflictedTaskFromJson(json, result);
    EXPECT_TRUE(result.empty());

    // 3. 测试当conflictedTask数组大小超过MAX_TASK_LIST_LEN时，函数应返回空向量
    // 添加超过MAX_TASK_LIST_LEN个元素
    for (int i = 0; i <= MAX_TASK_LIST_LEN; ++i) {
        cJSON_AddItemToArray(array, cJSON_CreateString("id"));
    }
    TaskScheduleParamManager::GetInstance().GetConflictedTaskFromJson(json, result);
    EXPECT_TRUE(result.empty());
    cJSON_Delete(json);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetConflictedTaskFromJson_test_003,
         TestSize.Level1)
{
    // 3. 测试当conflictedTask数组包含非字符串元素时，函数应返回空向量
    cJSON* json = cJSON_CreateObject();
    cJSON* array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, TAG_CONFLICTEDTASK.c_str(), array);

    // 添加一个字符串和一个非字符串元素
    cJSON_AddItemToArray(array, cJSON_CreateString("id1"));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(array, cJSON_CreateString("id2"));

    std::vector<std::string> result;
    TaskScheduleParamManager::GetInstance().GetConflictedTaskFromJson(json, result);

    EXPECT_EQ(result.size(), 1);
    cJSON_Delete(json);
}

/**
 * GetStartConditionFromJson
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetStartConditionFromJson_test_001,
         TestSize.Level1)
{
    cJSON* testJson = cJSON_CreateObject();
    // 1. 测试当JSON中未包含reScheduleInterval, conditionArray字段时，函数应正确解析该字段
    cJSON_AddObjectToObject(testJson, TAG_STARTCONDITION.c_str());
    TaskStartCondition startCondition;
    TaskScheduleParamManager::GetInstance().GetStartConditionFromJson(testJson, startCondition);
    EXPECT_EQ(startCondition.reScheduleInterval, -1);
    EXPECT_EQ(startCondition.conditionArray.size(), 0);

    cJSON *startJson = cJSON_GetObjectItem(testJson, TAG_STARTCONDITION.c_str());
    cJSON_AddNumberToObject(startJson, TAG_RESCHEDULEINTERVAL.c_str(), 2);
    cJSON_AddNumberToObject(startJson, TAG_CONDITIONARRAY.c_str(), 2);
    TaskScheduleParamManager::GetInstance().GetStartConditionFromJson(testJson, startCondition);
    EXPECT_EQ(startCondition.reScheduleInterval, 2);
    EXPECT_EQ(startCondition.conditionArray.size(), 0);
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetStartConditionFromJson_test_002,
         TestSize.Level1)
{
    // 2. 测试当conditionArray字段元素为空，过多时，函数应返回空的startCondition
    TaskStartCondition startCondition;
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddObjectToObject(testJson, TAG_STARTCONDITION.c_str());
    cJSON *startJson = cJSON_GetObjectItem(testJson, TAG_STARTCONDITION.c_str());
    cJSON *conditionArray = cJSON_CreateArray();
    cJSON_AddItemToObject(startJson, TAG_CONDITIONARRAY.c_str(), conditionArray);
    TaskScheduleParamManager::GetInstance().GetStartConditionFromJson(testJson, startCondition);
    EXPECT_EQ(startCondition.conditionArray.size(), 0);

    for (int i = 0; i < MAX_CONDITION_ARRAY_LEN + 1; i++) {
        cJSON_AddItemToArray(conditionArray, cJSON_CreateObject());
    }
    TaskScheduleParamManager::GetInstance().GetStartConditionFromJson(testJson, startCondition);
    EXPECT_EQ(startCondition.conditionArray.size(), 0);
    cJSON_Delete(testJson);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetStartConditionFromJson_test_003,
         TestSize.Level1)
{
    // 3. 测试当conditionArray字段元素为空，过多时，函数应返回空的startCondition
    TaskStartCondition startCondition;
    cJSON* testJson = cJSON_CreateObject();
    cJSON_AddObjectToObject(testJson, TAG_STARTCONDITION.c_str());
    cJSON *startJson = cJSON_GetObjectItem(testJson, TAG_STARTCONDITION.c_str());
    cJSON *conditionArray = cJSON_CreateArray();
    cJSON_AddItemToObject(startJson, TAG_CONDITIONARRAY.c_str(), conditionArray);
    cJSON_AddItemToArray(conditionArray, cJSON_CreateObject());
    cJSON_AddItemToArray(conditionArray, cJSON_CreateString(""));
    TaskScheduleParamManager::GetInstance().GetStartConditionFromJson(testJson, startCondition);
    EXPECT_EQ(startCondition.conditionArray.size(), 1);
    cJSON_Delete(testJson);
}

/**
 * JSON 相关非法数据测试
 */
HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_ReadIntMap_test_001, TestSize.Level1)
{
    cJSON* testJson = cJSON_CreateArray();
    cJSON* testJsonInvalid = cJSON_CreateObject();
    int preFirst = 10;
    int preSecond = 20;
    int first = 10;
    int second = 20;
    // 1. 测试当jsonData为null时，函数不修改输出参数
    TaskScheduleParamManager::GetInstance().ReadIntMap(nullptr, first, second);
    EXPECT_EQ(preFirst, first);
    EXPECT_EQ(preSecond, second);
    // 2. 测试当jsonData不是数组时，函数不修改输出参数
    TaskScheduleParamManager::GetInstance().ReadIntMap(testJsonInvalid, first, second);
    EXPECT_EQ(preFirst, first);
    EXPECT_EQ(preSecond, second);
    // 3. 测试当数组大小不为MAX_RANGE_NUM_CNT时，函数不修改输出参数
    cJSON_AddNumberToObject(testJson, "0", 0);
    TaskScheduleParamManager::GetInstance().ReadIntMap(testJson, first, second);
    EXPECT_EQ(preFirst, first);
    EXPECT_EQ(preSecond, second);
    // 4. 再添加一个字符串元素, 循环两次，第一次修改first成功，第二个数据异常second保持不变
    cJSON_AddStringToObject(testJson, TAG_TASKID.c_str(), TAG_TASKID.c_str());
    TaskScheduleParamManager::GetInstance().ReadIntMap(testJson, first, second);
    EXPECT_EQ(first, 0);
    EXPECT_EQ(second, preSecond);
    cJSON_Delete(testJson);
    testJson = cJSON_CreateArray();
    // 5. 测试当输入有效时，函数正确读取两个整数值
    cJSON_AddNumberToObject(testJson, "0", 0);
    cJSON_AddNumberToObject(testJson, "1", 1);
    TaskScheduleParamManager::GetInstance().ReadIntMap(testJson, first, second);
    EXPECT_EQ(first, 0);
    EXPECT_EQ(second, 1);

    cJSON_Delete(testJson);
    cJSON_Delete(testJsonInvalid);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_ReadFloatMap_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    float first = 1.0f;
    float second = 2.0f;
    float preFirst = 1.0f;
    float preSecond = 2.0f;
    // 测试当输入JSON数据为空指针时，函数不修改输出参数
    manager.ReadFloatMap(nullptr, first, second);
    EXPECT_FLOAT_EQ(first, preFirst);
    EXPECT_FLOAT_EQ(second, preSecond);
    // 测试当输入JSON数据不是数组时，函数不修改输出参数
    cJSON* jsonData = cJSON_CreateObject();
    manager.ReadFloatMap(jsonData, first, second);
    EXPECT_FLOAT_EQ(first, preFirst);
    EXPECT_FLOAT_EQ(second, preSecond);
    // 测试当数组大小不为MAX_RANGE_NUM_CNT时，函数不修改输出参数
    cJSON* jsonArrData = cJSON_CreateArray();
    cJSON_AddItemToArray(jsonArrData, cJSON_CreateNumber(1.5f));
    manager.ReadFloatMap(jsonArrData, first, second);
    EXPECT_FLOAT_EQ(first, preFirst);
    EXPECT_FLOAT_EQ(second, preSecond);
    // 再添加一个字符串元素, 循环两次，第一次修改first成功，第二个数据异常second保持不变
    cJSON_AddItemToArray(jsonArrData, cJSON_CreateString("invalid"));
    manager.ReadFloatMap(jsonArrData, first, second);
    EXPECT_FLOAT_EQ(first, 1.5f);
    EXPECT_FLOAT_EQ(second, preSecond);
    cJSON_Delete(jsonArrData);
    // 测试当输入JSON数据有效时，函数正确读取两个浮点数
    jsonArrData = cJSON_CreateArray();
    cJSON_AddItemToArray(jsonArrData, cJSON_CreateNumber(1.23f));
    cJSON_AddItemToArray(jsonArrData, cJSON_CreateNumber(4.56f));
    manager.ReadFloatMap(jsonArrData, first, second);
    EXPECT_FLOAT_EQ(first, 1.23f);
    EXPECT_FLOAT_EQ(second, 4.56f);
    cJSON_Delete(jsonArrData);
    cJSON_Delete(jsonData);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetStringFromJsonObj_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJsonObj = cJSON_CreateObject();
    std::string value;

    // jsonData为null
    EXPECT_FALSE(manager.GetStringFromJsonObj(nullptr, TAG_TASKID, value));
    // key为空
    EXPECT_FALSE(manager.GetStringFromJsonObj(testJsonObj, "", value));
    // 测试当JSON对象中不存在指定键时，函数应返回false
    EXPECT_FALSE(manager.GetStringFromJsonObj(testJsonObj, TAG_TASKID, value));
    // 测试当JSON对象中存在指定键但该项不是字符串类型时，函数应返回false
    cJSON_AddNumberToObject(testJsonObj, TAG_TASKID.c_str(), 1);
    EXPECT_FALSE(manager.GetStringFromJsonObj(testJsonObj, TAG_TASKID, value));

    cJSON_Delete(testJsonObj);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetIntFromJsonObj_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJsonObj = cJSON_CreateObject();
    int value = 0;

    // jsonData为null
    EXPECT_FALSE(manager.GetIntFromJsonObj(nullptr, TAG_SAID, value));
    // key为空
    EXPECT_FALSE(manager.GetIntFromJsonObj(testJsonObj, "", value));
    // 测试当JSON对象中不存在指定键时，函数应返回false
    EXPECT_FALSE(manager.GetIntFromJsonObj(testJsonObj, TAG_SAID, value));
    // 测试当JSON对象中存在指定键但该项不是字符串类型时，函数应返回false
    cJSON_AddStringToObject(testJsonObj, TAG_SAID.c_str(), TAG_SAID.c_str());
    EXPECT_FALSE(manager.GetIntFromJsonObj(testJsonObj, TAG_SAID, value));

    cJSON_Delete(testJsonObj);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetFloatFromJsonObj_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJsonObj = cJSON_CreateObject();
    float value = 0.0f;
    EXPECT_FALSE(manager.GetFloatFromJsonObj(nullptr, TAG_WAITING_PRESSURE_THRED, value));
    EXPECT_FALSE(manager.GetFloatFromJsonObj(testJsonObj, "", value));
    EXPECT_FALSE(manager.GetFloatFromJsonObj(testJsonObj, TAG_WAITING_PRESSURE_THRED, value));
    cJSON_AddStringToObject(testJsonObj, TAG_WAITING_PRESSURE_THRED.c_str(), TAG_WAITING_PRESSURE_THRED.c_str());
    EXPECT_FALSE(manager.GetFloatFromJsonObj(testJsonObj, TAG_WAITING_PRESSURE_THRED, value));
    cJSON_Delete(testJsonObj);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetBoolFromJsonObj_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJsonObj = cJSON_CreateObject();
    bool value = false;
    EXPECT_FALSE(manager.GetBoolFromJsonObj(nullptr, TAG_DEFAULTRUN, value));
    EXPECT_FALSE(manager.GetBoolFromJsonObj(testJsonObj, "", value));
    EXPECT_FALSE(manager.GetBoolFromJsonObj(testJsonObj, TAG_DEFAULTRUN, value));
    cJSON_AddStringToObject(testJsonObj, TAG_DEFAULTRUN.c_str(), TAG_DEFAULTRUN.c_str());
    EXPECT_FALSE(manager.GetBoolFromJsonObj(testJsonObj, TAG_DEFAULTRUN, value));
    cJSON_Delete(testJsonObj);
}

HWTEST_F(MediaBgtaskMgrTaskScheduleParamManagerTest, media_bgtask_mgr_GetObjFromJsonObj_test_001, TestSize.Level1)
{
    TaskScheduleParamManager& manager = TaskScheduleParamManager::GetInstance();
    cJSON* testJsonObj = cJSON_CreateObject();
    cJSON* result = nullptr;
    EXPECT_FALSE(manager.GetObjFromJsonObj(nullptr, TAG_STARTCONDITION, &result));
    EXPECT_EQ(result, nullptr);

    EXPECT_FALSE(manager.GetObjFromJsonObj(testJsonObj, "", &result));
    EXPECT_EQ(result, nullptr);

    EXPECT_FALSE(manager.GetObjFromJsonObj(testJsonObj, TAG_STARTCONDITION, &result));
    EXPECT_EQ(result, nullptr);

    cJSON_AddStringToObject(testJsonObj, TAG_STARTCONDITION.c_str(), TAG_STARTCONDITION.c_str());
    EXPECT_FALSE(manager.GetObjFromJsonObj(testJsonObj, TAG_STARTCONDITION, &result));
    EXPECT_EQ(result, nullptr);
    cJSON_Delete(testJsonObj);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS
