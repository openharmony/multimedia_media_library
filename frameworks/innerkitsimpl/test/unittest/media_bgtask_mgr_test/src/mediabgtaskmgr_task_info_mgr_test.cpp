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

#define MLOG_TAG "MediaBgTask_TaskInfoMgrTest"

#include "mediabgtaskmgr_task_info_mgr_test.h"

#define private public
#include "task_info_mgr.h"
#undef private

#include <cstdio>
#include "directory_ex.h"
#include "file_ex.h"
#include "string_ex.h"
#include "task_schedule_cfg.h"
#include "media_bgtask_mgr_log.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

const std::string KEY_START_TIME = "startTime";
const std::string KEY_STOP_TIME = "lastStopTime";
const std::string KEY_IS_RUNNING = "isRunning";
const std::string KEY_EXCEED_ENERGY = "exceedEnergy";
const std::string KEY_EXCEED_ENERGY_TIME = "exceedEnergySetTime";
const std::string KEY_IS_COMPLETE = "isComplete";
const std::string KEY_TASK_ENABLE = "taskEnable";

void MediaBgtaskMgrTaskInfoMgrTest::SetUpTestCase() {}

void MediaBgtaskMgrTaskInfoMgrTest::TearDownTestCase() {}

void MediaBgtaskMgrTaskInfoMgrTest::SetUp()
{
    TaskInfoMgr::GetInstance().GetAllTask().clear();
}

void MediaBgtaskMgrTaskInfoMgrTest::TearDown() {}

/**
 * InitTaskInfoByCfg
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_InitTaskInfoByCfg_test_001, TestSize.Level1)
{
    std::vector<TaskScheduleCfg> taskCfgs;
    // 1. 数组为空
    TaskInfoMgr::GetInstance().InitTaskInfoByCfg(taskCfgs);
    EXPECT_TRUE(TaskInfoMgr::GetInstance().GetAllTask().empty());

    // 2. 测试当输入多个任务配置时，函数正确添加多个任务信息
    TaskScheduleCfg cfg;
    cfg.taskId = "task";
    taskCfgs.push_back(cfg);
    TaskInfoMgr::GetInstance().InitTaskInfoByCfg(taskCfgs);
    EXPECT_EQ(1, TaskInfoMgr::GetInstance().GetAllTask().size());
}

/**
 * GetPersistTaskInfoFilePathRead
 */
static int FileExistsFileSuccStub(const std::string& path) {return 0;}
static int FileExistsFileBakSuccStub(const std::string& path)
{
    if (path == TaskInfoMgr::GetInstance().TASK_INFO_PERSIST_FILE) {
        return 1;
    }
    return 0;
}
static int FileExistsFileFailStub(const std::string& path) {return 1;}
static int FileExistsFileBakFailStub(const std::string& path) {return 1;}
static int SaveStringToFileSuccStub(const std::string& path, const std::string& con, bool truncated = true) {return 0;}
static int SaveStringToFileFailStub(const std::string& path, const std::string& con, bool truncated = true) {return 1;}
static void RemoveFile(const std::string &filePath) {}
static bool LoadStringFromFileSuccStub(const string& filePath, string& content) {return true;}
static bool LoadStringFromFileFailStub(const string& filePath, string& content) {return false;}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_GetPersistTaskInfoFilePathRead_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(FileExists, FileExistsFileBakSuccStub);

    std::string result = inst.GetPersistTaskInfoFilePathRead();
    EXPECT_EQ(result, inst.TASK_INFO_PERSIST_FILE);
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_GetPersistTaskInfoFilePathRead_test_002, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(FileExists, FileExistsFileBakFailStub);
    std::string result = inst.GetPersistTaskInfoFilePathRead();
    EXPECT_EQ(result, inst.TASK_INFO_PERSIST_FILE);
}

/**
 * GetPersistTaskInfoFilePathWrite
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_GetPersistTaskInfoFilePathWrite_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(FileExists, FileExistsFileSuccStub);

    std::string result = inst.GetPersistTaskInfoFilePathWrite();
    EXPECT_EQ(result, inst.TASK_INFO_PERSIST_FILE);
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_GetPersistTaskInfoFilePathWrite_test_002, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(FileExists, FileExistsFileFailStub);

    std::string result = inst.GetPersistTaskInfoFilePathWrite();
    EXPECT_EQ(result, inst.TASK_INFO_PERSIST_FILE);
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_GetPersistTaskInfoFilePathWrite_test_003, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(FileExists, FileExistsFileBakSuccStub);

    std::string result = inst.GetPersistTaskInfoFilePathWrite();
    EXPECT_EQ(result, inst.TASK_INFO_PERSIST_FILE);
}

/**
 * TaskInfoToLineString
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_TaskInfoToLineString_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    TaskInfo info;
    std::string result = inst.TaskInfoToLineString(info, true);
    EXPECT_NE(result, "");
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_TaskInfoToLineString_test_002, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    TaskInfo info;
    std::string result = inst.TaskInfoToLineString(info, false);
    EXPECT_NE(result, "");
}

/**
 * LineStringToTaskInfo
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_LineStringToTaskInfo_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    TaskInfo info;
    std::vector<std::string> segs;
    segs.push_back(KEY_START_TIME + "=0");
    segs.push_back(KEY_STOP_TIME + "=0");
    segs.push_back(KEY_IS_RUNNING + "=1");
    segs.push_back(KEY_EXCEED_ENERGY + "=0");
    segs.push_back(KEY_EXCEED_ENERGY_TIME + "=0");
    segs.push_back(KEY_IS_COMPLETE + "=0");
    segs.push_back(KEY_TASK_ENABLE + "=0");
    inst.LineStringToTaskInfo(segs, info);
    EXPECT_EQ(info.isRunning, true);
    EXPECT_EQ(info.exceedEnergy, false);
}

/**
 * SaveTaskState
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_SaveTaskState_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    TaskInfo info;
    inst.allTaskInfos_["id"] = info;
    Stub stub;
    stub.set(SaveStringToFile, SaveStringToFileFailStub);
    inst.SaveTaskState(true);
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_SaveTaskState_test_002, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    TaskInfo info;
    inst.allTaskInfos_["id"] = info;
    Stub stub;
    stub.set(SaveStringToFile, SaveStringToFileSuccStub);
    inst.SaveTaskState(true);
}

/**
 * RestoreTaskState
 */
HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_RestoreTaskState_test_001, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    inst.RestoreTaskState();
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_RestoreTaskState_test_002, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(LoadStringFromFile, LoadStringFromFileSuccStub);
    stub.set(FileExists, FileExistsFileSuccStub);
    inst.RestoreTaskState();
}

HWTEST_F(MediaBgtaskMgrTaskInfoMgrTest, media_bgtask_mgr_RestoreTaskState_test_003, TestSize.Level1)
{
    auto &inst = TaskInfoMgr::GetInstance();
    Stub stub;
    stub.set(LoadStringFromFile, LoadStringFromFileFailStub);
    stub.set(FileExists, FileExistsFileSuccStub);
    inst.RestoreTaskState();
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

