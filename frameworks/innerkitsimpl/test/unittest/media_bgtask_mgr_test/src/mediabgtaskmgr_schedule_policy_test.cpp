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

#define MLOG_TAG "MediaBgTask_SchedulePolicyTest"

#include "mediabgtaskmgr_schedule_policy_test.h"

#include <vector>
#include <algorithm>
#include <fstream>
#include "media_bgtask_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

const std::string CLOUD_PARAM_FILE_PATH = "/data/test/res/cloud_params.json";
const std::string TASK_SCHEDULE_FILE_PATH = "/data/test/res/task_schedule_param.json";
const std::string SYSTEM_STATUS_FILE_PATH = "/data/test/res/system_status.json";

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
const int64_t ONE_DAY_SECOND = 24 * 60 * 60;

void ClearQueueTest(std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> &taskQueue)
{
    while (!taskQueue.empty()) {
        taskQueue.pop();
    }
}

// 配置taskInfos
void ParseTaskListJson(std::vector<TaskScheduleCfg> &taskScheduleCfgList, std::map<std::string, TaskInfo> &taskInfos)
{
    for (const auto &taskScheduleCfg: taskScheduleCfgList) {
        TaskInfo taskInfo;
        taskInfo.taskId = taskScheduleCfg.taskId;
        taskInfo.scheduleCfg = taskScheduleCfg;
        taskInfos[taskInfo.taskId] = taskInfo;
    }
}

// system_status 配置
void ParseSystemStatus(const std::string &filepath, SystemInfo& sysInfo, std::map<std::string, TaskInfo> &taskInfos)
{
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    cJSON *jsonObj = cJSON_Parse(content.c_str());
    if (jsonObj == nullptr) {
        return;
    }
    // 设置systemInfo
    cJSON *systemInfoJson = nullptr;
    manager.GetObjFromJsonObj(jsonObj, "systemInfo", &systemInfoJson);
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

    cJSON *taskStatusJson = cJSON_GetObjectItemCaseSensitive(jsonObj, "taskStatus");
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
    cJSON_Delete(jsonObj);
}

void SetTask(const std::map<std::string, TaskInfo> &taskInfos)
{
    // 获取所有任务
    SchedulePolicy::GetInstance().allTasksList_.clear();
    for (std::map<std::string, TaskInfo>::const_iterator it = taskInfos.begin(); it != taskInfos.end(); it++) {
        TaskInfo task = it->second;
        SchedulePolicy::GetInstance().allTasksList_.insert(std::make_pair(it->first, task));
    }
}

// 读取task_schedule配置 & system_status & cloud_param json文件
void UnifyReadConfig(SystemInfo &sysInfo, std::map<std::string, TaskInfo> &taskInfos)
{
    TaskScheduleParamManager &manager = TaskScheduleParamManager::GetInstance();
    manager.ParseTaskScheduleCfg(TASK_SCHEDULE_FILE_PATH);
    manager.ParseUnifySchedulePolicyCfg(CLOUD_PARAM_FILE_PATH);
    ParseTaskListJson(manager.taskScheduleCfgList_, taskInfos);
    ParseSystemStatus(SYSTEM_STATUS_FILE_PATH, sysInfo, taskInfos);

    SchedulePolicy::GetInstance().SetSchedulePolicy(manager.unifySchedulePolicyCfg_);
    SetTask(taskInfos);
    SchedulePolicy::GetInstance().sysInfo_ = sysInfo;
}

void MediaBgtaskMgrSchedulePolicyTest::SetUpTestCase() {}

void MediaBgtaskMgrSchedulePolicyTest::TearDownTestCase() {}

void MediaBgtaskMgrSchedulePolicyTest::SetUp()
{
    UnifyReadConfig(testSysInfo_, testTaskInfos_);
}

void MediaBgtaskMgrSchedulePolicyTest::TearDown()
{
    // 每次测试前清空allTasksList_
    SchedulePolicy::GetInstance().allTasksList_.clear();
    SchedulePolicy::GetInstance().policyCfg_ = {};
    SchedulePolicy::GetInstance().sysInfo_ = {};
    ClearQueueTest(SchedulePolicy::GetInstance().hTaskQueue_);
    ClearQueueTest(SchedulePolicy::GetInstance().mTaskQueue_);
    ClearQueueTest(SchedulePolicy::GetInstance().lTaskQueue_);
    SchedulePolicy::GetInstance().validTasks_.clear();
    SchedulePolicy::GetInstance().validTasksId_.clear();
    SchedulePolicy::GetInstance().validTasksMustStart_.clear();
    SchedulePolicy::GetInstance().validTasksNotMustStart_.clear();
    SchedulePolicy::GetInstance().selectedTasks_.clear();
    SchedulePolicy::GetInstance().selectedTasksId_.clear();

    TaskScheduleParamManager::GetInstance().taskScheduleCfgList_.clear();
    TaskScheduleParamManager::GetInstance().unifySchedulePolicyCfg_ = {};

    testTaskInfos_.clear();
    testSysInfo_ = {};
}

/**
 * SetSchedulePolicy
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_SetSchedulePolicy_test_001, TestSize.Level1)
{
    SchedulePolicy schedulePolicy = SchedulePolicy();
    TaskScheduleParamManager manager = TaskScheduleParamManager();

    // 读取系统配置，进行排序
    manager.ParseUnifySchedulePolicyCfg(CLOUD_PARAM_FILE_PATH);
    schedulePolicy.SetSchedulePolicy(manager.unifySchedulePolicyCfg_);

    // 验证策略被正确设置
    EXPECT_EQ(schedulePolicy.policyCfg_.agingFactorMap.size(), 6);

    // 验证排序结果（默认排序是升序）
    EXPECT_FLOAT_EQ(schedulePolicy.policyCfg_.agingFactorMap[0].waitingPressure, 0.3);
    EXPECT_FLOAT_EQ(schedulePolicy.policyCfg_.agingFactorMap[1].waitingPressure, 0.6);
    EXPECT_FLOAT_EQ(schedulePolicy.policyCfg_.agingFactorMap[2].waitingPressure, 0.8);
}

/**
 * ScheduleTasks & GetTasksState & UpdateTasksState & GetValidTasks & UpdateValidTasksVRunTime
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_ScheduleTasks_test_001, TestSize.Level1)
{
    // 1. 测试当充电且温度超过充电温度阈值时，返回最大下次调度时间和所有任务停止
    SchedulePolicy schedulePolicy = SchedulePolicy();
    schedulePolicy.policyCfg_.scheduleEnable = false;
    SystemInfo sysInfo;
    std::map<std::string, TaskInfo> taskInfos;
    schedulePolicy.allTasksList_["task1"] = TaskInfo();
    TaskScheduleResult result = schedulePolicy.ScheduleTasks(taskInfos, sysInfo);
    EXPECT_EQ(result.nextComputeTime_, INT_MAX);
    EXPECT_EQ(result.taskStart_.size(), 0);
    EXPECT_TRUE(result.taskStop_.empty());
}

// 默认配置文件测试
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_ScheduleTasks_test_002, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();

    // 读取配置文件, 当前系统状态是充电中 & screenOff: false亮屏
    // 模拟修改taskEnable
    std::string taskId = "10120:BackupAllAnalysis";
    std::string taskIdAlbum = "com.ohos.medialibrary.medialibrarydata:AllAlbumRefresh";
    testTaskInfos_[taskId].taskEnable_ = MODIFY_DISABLE;
    schedulePolicy.allTasksList_[taskIdAlbum].scheduleCfg.taskPolicy.maxRunningTime = 1;

    TaskScheduleResult result = schedulePolicy.ScheduleTasks(testTaskInfos_, testSysInfo_);
    EXPECT_NE(result.nextComputeTime_, 0);
    EXPECT_FALSE(result.taskStart_.empty());
    EXPECT_FALSE(result.taskStop_.empty());
}

HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_ScheduleTasks_test_003, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();

    // 读取配置文件, 当前系统状态是未充电 & screenOff: false亮屏
    testSysInfo_.screenOff = true;
    TaskScheduleResult result = schedulePolicy.ScheduleTasks(testTaskInfos_, testSysInfo_);
    EXPECT_NE(result.nextComputeTime_, 0);
    EXPECT_FALSE(result.taskStart_.empty());
    EXPECT_FALSE(result.taskStop_.empty());
}

/**
 * TaskCanStart
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_TaskCanStart_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    // 读取配置文件, 当前系统状态是充电中 & screenOff: false亮屏
    std::string taskId = "com.ohos.medialibrary.medialibrarydata:AnalyzePhotosTable";
    TaskInfo &task = schedulePolicy.allTasksList_[taskId];
    // 1. 默认配置中返回true
    // 配置文件中charging 为true
    schedulePolicy.sysInfo_.charging = true;
    EXPECT_TRUE(schedulePolicy.TaskCanStart(task));

    task.scheduleCfg.taskPolicy.maxRunningTime = 0;
    EXPECT_TRUE(schedulePolicy.TaskCanStart(task));

    // 2. 测试当不满足任何启动条件时，TaskCanStart应返回false
    task.scheduleCfg.taskPolicy.startCondition.conditionArray.clear();
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    TaskStartSubCondition condition;
    condition.isCharging = 0; // 违背充电条件判断
    task.scheduleCfg.taskPolicy.startCondition.conditionArray.push_back(condition);
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 3. 测试当任务已运行超过最大运行时间时，TaskCanStart应返回false
    task.scheduleCfg.taskPolicy.startCondition.reScheduleInterval = -1;
    task.scheduleCfg.taskPolicy.maxRunningTime = 1;
    task.isRunning = true;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 4. 测试当任务上次停止后未达到重新调度间隔时，TaskCanStart应返回false
    task.lastStopTime = testSysInfo_.now;
    task.scheduleCfg.taskPolicy.startCondition.reScheduleInterval = 1440;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 5. 测试当任务已完成时，TaskCanStart应返回false
    task.isComplete = true;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));
}

HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_TaskCanStart_test_002, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    // 读取配置文件, 当前系统状态是充电中 & screenOff: false亮屏
    std::string taskId = "com.ohos.medialibrary.medialibrarydata:AnalyzePhotosTable";
    TaskInfo &task = schedulePolicy.allTasksList_[taskId];

    // 6. 测试当屏幕开启且系统中负载高时，高负载任务应返回false
    task.scheduleCfg.taskPolicy.loadLevel = 2;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    task.scheduleCfg.taskPolicy.loadLevel = 0; // 重置该条件
    schedulePolicy.sysInfo_.loadLevel = 3;      // 配置息屏、高负载
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 7. 测试当任务需要更多能量且设备未充电时，TaskCanStart应返回false
    task.exceedEnergy = true;
    schedulePolicy.sysInfo_.charging = false;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 8. 测试当任务默认不运行 & 未修改时，TaskCanStart应返回false
    task.taskEnable_ = MODIFY_ENABLE;
    task.scheduleCfg.taskPolicy.defaultRun = false;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));

    // 9. 测试当任务被禁用时，TaskCanStart应返回false
    task.taskEnable_ = MODIFY_DISABLE;
    EXPECT_FALSE(schedulePolicy.TaskCanStart(task));
}

/**
 * StartCondition
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_StartCondition_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    // 读取配置文件, 当前系统状态是充电中 & screenOff: false亮屏
    std::string taskId = "com.ohos.medialibrary.medialibrarydata:CleanInvalidCloudAlbumAndData";
    TaskInfo &task = schedulePolicy.allTasksList_[taskId];
    std::vector<TaskStartSubCondition> &conditionArray = task.scheduleCfg.taskPolicy.startCondition.conditionArray;
    ASSERT_EQ(conditionArray.size(), 6); // 配置文件中当前条件配置有6个

    // 1. 测试充电状态不匹配时返回false
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[0]));

    schedulePolicy.sysInfo_.charging = false;
    conditionArray[0].isCharging = 1;
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[0]));

    // 2. 测试屏幕状态不匹配时返回false
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[1]));

    schedulePolicy.sysInfo_.charging = true;
    conditionArray[0].screenOff = 0;
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[1]));

    // 3. 测试电量条件不匹配时返回false
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[2]));

    // 4. 测试存储空间条件不匹配时返回false
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[3]));
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[4]));

    // 5. 测试网络条件不匹配时返回false
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[5]));

    conditionArray[5].networkType = "any";
    schedulePolicy.sysInfo_.wifiConnected = false;
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[5]));

    conditionArray[5].networkType = "wifi";
    EXPECT_FALSE(schedulePolicy.StartCondition(conditionArray[5]));

    // 测试所有条件都匹配时返回true
    schedulePolicy.sysInfo_.wifiConnected = true;
    EXPECT_TRUE(schedulePolicy.StartCondition(conditionArray[5]));
}

/**
 * AddValidTaskToQueues
 */
void SetTasks(std::map<std::string, TaskInfo> &taskInfos, std::vector<TaskInfo> &tasks)
{
    for (std::map<std::string, TaskInfo>::const_iterator it = taskInfos.begin(); it != taskInfos.end(); it++) {
        tasks.push_back(it->second);
    }
}

HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_AddValidTaskToQueues_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();

    // 1. validTasks_为空
    schedulePolicy.AddValidTaskToQueues(SchedulePolicy::GetInstance().validTasks_);
    EXPECT_TRUE(schedulePolicy.hTaskQueue_.empty());
    EXPECT_TRUE(schedulePolicy.mTaskQueue_.empty());
    EXPECT_TRUE(schedulePolicy.lTaskQueue_.empty());

    // 2.测试时将all taskInfos 都赋值给validTasks_
    SetTasks(testTaskInfos_, SchedulePolicy::GetInstance().validTasks_);
    schedulePolicy.AddValidTaskToQueues(SchedulePolicy::GetInstance().validTasks_);
    EXPECT_FALSE(schedulePolicy.hTaskQueue_.empty());
    EXPECT_FALSE(schedulePolicy.mTaskQueue_.empty());
    EXPECT_FALSE(schedulePolicy.lTaskQueue_.empty());
}

/**
 * CanConcurrency
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_CanConcurrency_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    std::string taskId = "com.ohos.medialibrary.medialibrarydata:StorageAgingTask";
    TaskInfo &task = schedulePolicy.allTasksList_[taskId];

    // 1. selectedTasks_为空
    EXPECT_TRUE(schedulePolicy.CanConcurrency(task));

    // 2.测试时将all taskInfos 都赋值给selectedTasks_, 且当前task冲突列表中有有效的冲突id
    std::string taskIdDelete = "com.ohos.medialibrary.medialibrarydata:DeleteTemporaryPhotos";
    schedulePolicy.selectedTasksId_.insert(taskIdDelete);
    EXPECT_FALSE(schedulePolicy.CanConcurrency(task));

    // 3. 添加无效taskId 模拟冲突列表
    task.scheduleCfg.taskPolicy.conflictedTask.clear();
    task.scheduleCfg.taskPolicy.conflictedTask.push_back("testID");
    EXPECT_TRUE(schedulePolicy.CanConcurrency(task));
}

/**
 * CalculateVRunTime & GetAgingFactor
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_CalculateVRunTime_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    std::string taskId = "com.ohos.medialibrary.medialibrarydata:AnalyzePhotosTable";
    TaskInfo &task = schedulePolicy.allTasksList_[taskId];

    // 1. 测试当任务未运行 & waitPressure全部大于云推配置，正确计算vrunTime和mustStart
    schedulePolicy.CalculateVRunTime(task);
    EXPECT_FLOAT_EQ(task.vrunTime, 1e-2 * task.scheduleCfg.taskPolicy.priorityFactor);
    EXPECT_TRUE(task.mustStart);

    // 2. 测试当任务未运行 & waitPressure部分大于云推配置，正确计算vrunTime和mustStart
    task.mustStart = false; // 重置
    schedulePolicy.policyCfg_.agingFactorMap.push_back({2, 1});
    schedulePolicy.CalculateVRunTime(task);
    EXPECT_FLOAT_EQ(task.vrunTime, 1 * task.scheduleCfg.taskPolicy.priorityFactor);
    EXPECT_TRUE(task.mustStart);

    // 3. 测试当任务运行时waitPressure为0，则返回ageingFactor映射表第一个值计算vrunTime，mustStart为初始值
    task.isRunning = true;
    task.mustStart = false; // 重置
    schedulePolicy.CalculateVRunTime(task);
    EXPECT_FLOAT_EQ(task.vrunTime, schedulePolicy.policyCfg_.agingFactorMap[0].agingFactor
                                                * task.scheduleCfg.taskPolicy.priorityFactor);
    EXPECT_FALSE(task.mustStart);
}

/**
 * Schedule & CommonSchedule & SelectTaskFromQueue & CanAddTask & TotalLoad
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_Schedule_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    schedulePolicy.sysInfo_.screenOff = true;

    // 1. 优先队列为空
    schedulePolicy.Schedule();
    EXPECT_TRUE(schedulePolicy.selectedTasks_.empty());

    // 2. 设置 hTaskQueue_ & mTaskQueue_ & lTaskQueue_列表
    SetTasks(testTaskInfos_, schedulePolicy.validTasks_);
    schedulePolicy.AddValidTaskToQueues(schedulePolicy.validTasks_);
    EXPECT_FALSE(schedulePolicy.hTaskQueue_.empty());
    EXPECT_FALSE(schedulePolicy.mTaskQueue_.empty());
    EXPECT_FALSE(schedulePolicy.lTaskQueue_.empty());
    schedulePolicy.selectedTasks_.clear();

    schedulePolicy.Schedule();
    EXPECT_TRUE(schedulePolicy.hTaskQueue_.empty());
    EXPECT_TRUE(schedulePolicy.mTaskQueue_.empty());
    EXPECT_TRUE(schedulePolicy.lTaskQueue_.empty());
    EXPECT_FALSE(schedulePolicy.selectedTasks_.empty());
}

HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_Scheduletest_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    schedulePolicy.sysInfo_.screenOff = false;
    // 测试当系统负载为低、中、高 三种场景
    schedulePolicy.sysInfo_.loadLevel = 0;
    schedulePolicy.Schedule();
    EXPECT_TRUE(schedulePolicy.selectedTasks_.empty());

    schedulePolicy.sysInfo_.loadLevel = 1;
    schedulePolicy.Schedule();
    EXPECT_TRUE(schedulePolicy.selectedTasks_.empty());

    schedulePolicy.sysInfo_.loadLevel = 3;
    schedulePolicy.Schedule();
    EXPECT_TRUE(schedulePolicy.selectedTasks_.empty());
}

/**
 * GetSchedulResult & MinNextScheduleInterval
 */
HWTEST_F(MediaBgtaskMgrSchedulePolicyTest, media_bgtask_mgr_GetSchedulResult_test_001, TestSize.Level1)
{
    SchedulePolicy &schedulePolicy = SchedulePolicy::GetInstance();
    TaskScheduleResult result;

    // 1. 无有效selectedTasksId_任务列表
    schedulePolicy.GetSchedulResult(result);
    EXPECT_TRUE(result.taskStart_.empty());
    EXPECT_FALSE(result.taskStop_.empty());
    EXPECT_NE(result.taskStop_.size(), 0);
    EXPECT_EQ(result.nextComputeTime_, ONE_DAY_SECOND);

    // 2. 设置 hTaskQueue_ || mTaskQueue_ || lTaskQueue_列表
    result.taskStop_.clear();
    // 影响compute time设置
    SetTasks(testTaskInfos_, schedulePolicy.validTasks_);
    schedulePolicy.AddValidTaskToQueues(schedulePolicy.validTasks_);
    schedulePolicy.SelectTaskFromQueue(schedulePolicy.hTaskQueue_, schedulePolicy.policyCfg_.loadThredHigh);

    schedulePolicy.GetSchedulResult(result);
    EXPECT_FALSE(result.taskStart_.empty());
    EXPECT_FALSE(result.taskStop_.empty());
    EXPECT_NE(result.nextComputeTime_, ONE_DAY_SECOND);
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS