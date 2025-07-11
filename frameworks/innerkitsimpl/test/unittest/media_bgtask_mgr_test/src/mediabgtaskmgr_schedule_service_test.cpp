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

#define MLOG_TAG "MediaBgtaskScheduleServiceTest"

#include "mediabgtaskmgr_schedule_service_test.h"
#define private public
#include "media_bgtask_schedule_service.h"
#undef private
#include <cstdlib>
#include <ctime>
#include <string>
#include <map>
#include "ffrt_inner.h"
#include "media_bgtask_mgr_log.h"
#include "schedule_policy.h"
#include "task_info_mgr.h"
#include "task_runner.h"
#include "task_schedule_param_manager.h"
#include "sa_ops_connection_manager.h"
#include "system_state_mgr.h"
#include "os_account_manager_wrapper.h"
#include "task_runner.h"
#include "app_ops_connect_ability.h"
#include "sa_ops_connection.h"
#include "media_bgtask_utils.h"
#include "stub.h"

#define SCHEDULE_DELAY_SEC 20

static const int32_t E_OK = 0;
static const int32_t E_ERR = -1;

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

static void InitParamsStub(TaskScheduleParamManager *obj) {}

static TaskScheduleResult ScheduleTasksStub(SchedulePolicy *obj, std::map <std::string, TaskInfo> &taskInfos,
                                            SystemInfo &sysInfo)
{
    TaskScheduleResult result;
    result.nextComputeTime_ = SCHEDULE_DELAY_SEC;
    for (auto &taskInfo: taskInfos) {
        // 模拟结果，如果运行态加入stop，否则加入start;
        if (taskInfo.second.isRunning) {
            result.taskStop_.push_back(taskInfo.first);
            result.taskStart_.push_back(taskInfo.first + "non_exist"); // 随意添加扰动值
        } else {
            result.taskStart_.push_back(taskInfo.first);
            result.taskStop_.push_back(taskInfo.first + "non_exist"); // 随意添加扰动值
        }
    }
    return result;
}

static void InitTaskInfoByCfgStub(TaskInfoMgr *obj, std::vector <TaskScheduleCfg> taskCfgs) {}

static void InitStub(SystemStateMgr *obj) {}

static int OpsAppTaskStub(TaskOps ops, AppSvcInfo svcName, std::string taskName, std::string extra)
{
    return 0;
}

static int OpsSaTaskStub(TaskOps ops, int32_t saId, std::string taskName, std::string extra)
{
    return 0;
}

static int32_t TaskOpsSyncStub(SAOpsConnection *obj, const std::string &ops, const std::string &taskName,
                               const std::string extra)
{
    return 0;
}

static ErrCode QueryActiveOsAccountIdsStub(AppExecFwk::OsAccountManagerWrapper *obj, std::vector <int32_t> &ids)
{
    return ERR_OK;
}

static int32_t ConnectAbilityStub(AppOpsConnectAbility *obj, const AppSvcInfo &svcName, int32_t userId,
    std::string ops, std::string taskName, std::string extra)
{
    return 0;
}

void MediaBgtaskMgrScheduleServiceTest::SetUpTestCase() {}

void MediaBgtaskMgrScheduleServiceTest::TearDownTestCase() {}

void MediaBgtaskMgrScheduleServiceTest::SetUp() {}

void MediaBgtaskMgrScheduleServiceTest::TearDown()
{
    TaskInfoMgr::GetInstance().GetAllTask().clear();
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();
}

/**
 * GetTaskNameFromId
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_GetTaskNameFromId_test_001, TestSize.Level1)
{
    auto &inst = MediaBgtaskScheduleService::GetInstance();
    // 1.  测试当任务ID格式正确时，能正确提取任务名称
    std::string taskId = "task:id";
    std::string expected = "id";
    std::string result = inst.GetTaskNameFromId(taskId);
    EXPECT_EQ(expected, result);
}

HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_GetTaskNameFromId_test_002, TestSize.Level1)
{
    auto &inst = MediaBgtaskScheduleService::GetInstance();
    // 2.  测试当任务ID为空字符串时，返回nullptr并记录错误日志
    std::string taskId = "";
    std::string result = inst.GetTaskNameFromId(taskId);
    EXPECT_TRUE(result == "");
}

/**
 * Init
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_Init_test_001, TestSize.Level1)
{
    auto &inst = MediaBgtaskScheduleService::GetInstance();
    Stub stub;
    stub.set(ADDR(TaskScheduleParamManager, InitParams), InitParamsStub);
    stub.set(ADDR(TaskInfoMgr, InitTaskInfoByCfg), InitTaskInfoByCfgStub);
    stub.set(ADDR(SystemStateMgr, Init), InitStub);
    inst.Init();
    EXPECT_EQ(0, TaskScheduleParamManager::GetInstance().GetAllTaskCfg().size());
}

/**
 * HandleReschedule
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_HandleReschedule_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(SchedulePolicy, ScheduleTasks), ScheduleTasksStub);
    stub.set(ADDR(AppExecFwk::OsAccountManagerWrapper, QueryActiveOsAccountIds), QueryActiveOsAccountIdsStub);
    stub.set(ADDR(AppOpsConnectAbility, ConnectAbility), ConnectAbilityStub);
    stub.set(ADDR(SAOpsConnection, TaskOpsSync), TaskOpsSyncStub);

    TaskInfo testTask;
    testTask.scheduleCfg.type = "app";
    testTask.isRunning = true; // stop
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    // 1. type为app, stop成功 期望false
    MediaBgtaskScheduleService::GetInstance().HandleReschedule();
    EXPECT_FALSE(task.isRunning);
}

static int32_t TaskOpsSyncManagerStub(SAOpsConnectionManager *obj, const std::string& ops,
    const std::string& taskName, const std::string& extra)
{
    return 0;
}

HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_HandleReschedule_test_004, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(SchedulePolicy, ScheduleTasks), ScheduleTasksStub);
    stub.set(ADDR(AppExecFwk::OsAccountManagerWrapper, QueryActiveOsAccountIds), QueryActiveOsAccountIdsStub);
    stub.set(ADDR(AppOpsConnectAbility, ConnectAbility), ConnectAbilityStub);
    stub.set(ADDR(SAOpsConnection, TaskOpsSync), TaskOpsSyncStub);

    TaskInfo testTask;
    testTask.scheduleCfg.type = "app";
    testTask.isRunning = false; // start
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    // 1. type为app, stop成功 期望true
    MediaBgtaskScheduleService::GetInstance().HandleReschedule();
    EXPECT_TRUE(task.isRunning);
}

HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_HandleReschedule_test_005, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(SchedulePolicy, ScheduleTasks), ScheduleTasksStub);
    stub.set(ADDR(SAOpsConnectionManager, TaskOpsSync), TaskOpsSyncManagerStub);

    TaskInfo testTask;
    testTask.scheduleCfg.type = "sa";
    testTask.isRunning = false; // start
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    // 2. type为sa, stop成功 期望true
    MediaBgtaskScheduleService::GetInstance().HandleReschedule();
    EXPECT_TRUE(task.isRunning);
}

HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_HandleReschedule_test_006, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(SchedulePolicy, ScheduleTasks), ScheduleTasksStub);
    stub.set(ADDR(AppExecFwk::OsAccountManagerWrapper, QueryActiveOsAccountIds), QueryActiveOsAccountIdsStub);
    stub.set(ADDR(AppOpsConnectAbility, ConnectAbility), ConnectAbilityStub);
    stub.set(ADDR(SAOpsConnection, TaskOpsSync), TaskOpsSyncStub);

    TaskInfo testTask;
    testTask.scheduleCfg.type = "";
    testTask.isRunning = false; // start
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    // 3. type非法, stop成功 期望false
    MediaBgtaskScheduleService::GetInstance().HandleReschedule();
    EXPECT_FALSE(task.isRunning);
}

/**
 * reportTaskComplete
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_reportTaskComplete_test_002, TestSize.Level1)
{
    // 1.  测试当任务不存在时，函数应返回true并设置funcResult为1
    int32_t funcResult = 0;
    bool result = MediaBgtaskScheduleService::GetInstance().reportTaskComplete("", funcResult);
    EXPECT_FALSE(result);
    EXPECT_EQ(funcResult, 1);

    // 2. 测试当任务未完成时，函数应返回true并设置funcResult为0
    TaskInfo testTask;
    testTask.isRunning = true;
    testTask.isComplete = false;
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    result = MediaBgtaskScheduleService::GetInstance().reportTaskComplete("id", funcResult);
    EXPECT_FALSE(task.isRunning);
    EXPECT_TRUE(result);

    // 3. 测试当任务未完成时，函数应返回true并设置funcResult为0
    task.isComplete = true;
    result = MediaBgtaskScheduleService::GetInstance().reportTaskComplete("id", funcResult);
    EXPECT_FALSE(task.isRunning);
    EXPECT_TRUE(result);
}

/**
 * modifyTask
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceTest, media_bgtask_mgr_modifyTask_test_001, TestSize.Level1)
{
    TaskInfo testTask;
    testTask.isRunning = true;
    testTask.isComplete = false;
    TaskInfoMgr::GetInstance().allTaskInfos_["id"] = testTask;
    TaskInfo &task = TaskInfoMgr::GetInstance().allTaskInfos_["id"];

    // 1. taskId不存在
    int32_t funcResult = 0;
    bool result = MediaBgtaskScheduleService::GetInstance().modifyTask("", "", funcResult);
    EXPECT_TRUE(result);
    EXPECT_TRUE(funcResult == 1);

    // 2. taskId存在, modifyInfo非法
    result = MediaBgtaskScheduleService::GetInstance().modifyTask("id", "", funcResult);
    EXPECT_TRUE(funcResult == 1);

    // 3. taskId存在, modifyInfo合法
    result = MediaBgtaskScheduleService::GetInstance().modifyTask("id", "taskRun:true", funcResult);
    EXPECT_TRUE(task.taskEnable_ == TaskEnable::MODIFY_ENABLE);

    result = MediaBgtaskScheduleService::GetInstance().modifyTask("id", "taskRun:false", funcResult);
    EXPECT_TRUE(task.taskEnable_ == TaskEnable::MODIFY_DISABLE);

    result = MediaBgtaskScheduleService::GetInstance().modifyTask("id", "taskRun:skipToday", funcResult);
    EXPECT_TRUE(task.exceedEnergy);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

