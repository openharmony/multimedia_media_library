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

#define MLOG_TAG "MediaBgTask_TaskInfoMgr"

#include "task_info_mgr.h"

#include <cstdio>

#include "directory_ex.h"
#include "file_ex.h"
#include "string_ex.h"

#include "os_account_manager.h"
#include "system_state_mgr.h"
#include "task_schedule_cfg.h"
#include "task_schedule_param_manager.h"
#include "schedule_policy.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_utils.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
static const std::string TASKID_BUNDLE_SEP = ":";
static const std::string TASKID_USERID_SEP = "@";

std::map<std::string, TaskInfo> &TaskInfoMgr::GetAllTask()
{
    return allTaskInfos_;
}

void TaskInfoMgr::InitTaskInfoByCfg(std::vector<TaskScheduleCfg> taskCfgs)
{
    std::vector<int32_t> activeIds = {};
    ErrCode errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeIds);
    if (errCode != ERR_OK) {
        MEDIA_ERR_LOG("QueryActiveOsAccountIds error, ret %{public}d", errCode);
    } else {
        MEDIA_INFO_LOG("QueryActiveOsAccountIds ok, get %{public}zu avtive users", activeIds.size());
    }

    size_t taskSize = taskCfgs.size();
    MEDIA_INFO_LOG("Find task cnt %{public}zu", taskSize);
    for (TaskScheduleCfg &cfg : taskCfgs) {
        if (cfg.type == "app") {
            // 为每个激活用户实例化一个APP任务
            for (int32_t userId : activeIds) {
                TaskInfo info;
                info.taskId = cfg.taskId + TASKID_USERID_SEP + ToString(userId);
                info.userId = userId;
                info.SetCfgInfo(cfg);
                allTaskInfos_.insert(std::make_pair(info.taskId, info));
            }
        } else {
            TaskInfo info;
            info.taskId = cfg.taskId;
            info.SetCfgInfo(cfg);
            allTaskInfos_.insert(std::make_pair(info.taskId, info));
        }
    }
}

bool TaskInfoMgr::IsTaskEnabled(TaskInfo &info)
{
    if (info.taskEnable_ == NO_MODIFY) {
        return info.scheduleCfg.taskPolicy.defaultRun;
    }
    return info.taskEnable_ == MODIDY_ENABLE;
}

// 返回-1表示错误
static int32_t GetUserIdFromTaskId(std::string taskId)
{
    std::vector<std::string> segs;
    SplitStr(taskId, TASKID_USERID_SEP, segs);
    if (segs.size() > 1 && IsNumericStr(segs[1])) {
        return std::stoi(segs[1]);
    }
    return -1;
}

// use below or add cflags_cc = [ "-std=c++20" ]
static inline bool StrEndWith(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) {
        return false;
    }
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

// 删除用户的时候，用户的进程也会被kill掉，任务会停止
void TaskInfoMgr::RemoveTaskForUser(int32_t userId)
{
    int delTaskCnt = 0;
    std::string checkEnd = std::string(TASKID_USERID_SEP) + ToString(userId);
    std::map<std::string, TaskInfo> & taskList = SchedulePolicy::GetInstance().GetAllTaskList();
    for (auto it = allTaskInfos_.begin(); it != allTaskInfos_.end();) {
        const std::string taskId = it->first;
        auto currentIt = it;
        it++;
        if (StrEndWith(taskId, checkEnd)) {
            allTaskInfos_.erase(currentIt);
            taskList.erase(taskId);
            delTaskCnt++;
            MEDIA_INFO_LOG("RemoveTaskForUser taskId = %{public}s", taskId.c_str());
        }
    }
    MEDIA_INFO_LOG("RemoveTaskForUser userId = %{public}d, remove %{public}d task", userId, delTaskCnt);
}

void TaskInfoMgr::AddTaskForNewUserIfNeed(int32_t newUserId)
{
    auto taskCfgs = TaskScheduleParamManager::GetInstance().GetAllTaskCfg();
    int addTaskCnt = 0;
    for (TaskScheduleCfg &cfg : taskCfgs) {
        if (cfg.type == "app") {
            TaskInfo info;
            info.taskId = cfg.taskId + TASKID_USERID_SEP + ToString(newUserId);
            info.userId = newUserId;
            info.SetCfgInfo(cfg);
            allTaskInfos_.insert(std::make_pair(info.taskId, info));
            addTaskCnt++;
        }
    }
    MEDIA_INFO_LOG("AddTaskForNewUserIfNeed userId = %{public}d, add %{public}d task", newUserId, addTaskCnt);
    RestoreTaskState(); // 如果有该用户保存的状态，需要同时恢复
}

// 写文件时，先备份，再写入，再删备份。正常流程没有bak文件，有bak文件说明写入出问题了
// 读文件时候，优先读取bak文件
// 未加锁，后续如果需要支持并发场景需要加锁
std::string TaskInfoMgr::GetPersistTaskInfoFilePathRead()
{
    std::string fileName = TASK_INFO_PERSIST_FILE;
    std::string bakFileName = TASK_INFO_PERSIST_FILE_BAK;

    // 正常写完是没bak文件的，如果有bak文件，说明写出问题了，要读取备份文件
    if (FileExists(bakFileName)) {
        RemoveFile(fileName);
        rename(bakFileName.c_str(), fileName.c_str());
    }
    return fileName;
}

std::string TaskInfoMgr::GetPersistTaskInfoFilePathWrite()
{
    std::string fileName = TASK_INFO_PERSIST_FILE;
    std::string bakFileName = TASK_INFO_PERSIST_FILE_BAK;

    if (FileExists(fileName)) {
        if (FileExists(bakFileName)) {
            // 上次没写完出问题了，删除原文件，保留bak的
            RemoveFile(fileName);
        } else {
            // 上次写没问题，本次写入前先备份
            rename(fileName.c_str(), bakFileName.c_str());
        }
    }
    return fileName;
}

// string格式，不同字段用';'分隔，第一字段是taskId，其余字段的key和value用'='分隔
const std::string KEY_VAL_SEP = "=";
const std::string SEG_SEP = ";";
const std::string LINE_END = "\n";

const std::string KEY_START_TIME = "startTime";
const std::string KEY_STOP_TIME = "lastStopTime";
const std::string KEY_IS_RUNNING = "isRunning";
const std::string KEY_EXCEED_ENERGY = "exceedEnergy";
const std::string KEY_EXCEED_ENERGY_TIME = "exceedEnergySetTime";
const std::string KEY_IS_COMPLETE = "isComplete";
const std::string KEY_TASK_ENABLE = "taskEnable";
const static int EXPECT_MIN_KV_SZIE = 2;

static inline std::string ONE_KEY_VALUE(std::string key, std::string value)
{
    return key + KEY_VAL_SEP + value + SEG_SEP;
}

// 在修改任务、报告超功耗时，onlyCriticalInfo为true；进程退出的时候用false
std::string TaskInfoMgr::TaskInfoToLineString(TaskInfo info, bool onlyCriticalInfo)
{
    std::string infoStr = info.taskId + SEG_SEP + ONE_KEY_VALUE(KEY_EXCEED_ENERGY, ToString(info.exceedEnergy)) +
                          ONE_KEY_VALUE(KEY_EXCEED_ENERGY_TIME, ToString(info.exceedEnergySetTime)) +
                          ONE_KEY_VALUE(KEY_TASK_ENABLE, ToString(info.taskEnable_));
    if (!onlyCriticalInfo) {
        infoStr = infoStr + ONE_KEY_VALUE(KEY_START_TIME, ToString(info.startTime_));
        infoStr = infoStr + ONE_KEY_VALUE(KEY_STOP_TIME, ToString(info.lastStopTime));
        infoStr = infoStr + ONE_KEY_VALUE(KEY_IS_RUNNING, ToString(info.isRunning));
        infoStr = infoStr + ONE_KEY_VALUE(KEY_IS_COMPLETE, ToString(info.isComplete));
    }
    return infoStr;
}

void TaskInfoMgr::LineStringToTaskInfo(std::vector<std::string> segs, TaskInfo &info)
{
    for (size_t i = 1; i < segs.size(); i++) {
        std::vector<std::string> kv;
        SplitStr(segs[i], KEY_VAL_SEP, kv);
        if (kv.size() < EXPECT_MIN_KV_SZIE) {
            MEDIA_ERR_LOG("kv size < 2, size:%{public}zu, index:%{public}zu", kv.size(), i);
            continue;
        }
        if (kv[0] == KEY_START_TIME) {
            CHECK_AND_CONTINUE_ERR_LOG(MediaBgTaskUtils::StrToNumeric(kv[1], info.startTime_),
                "fail to convert key:%{public}s, value:%{public}s to numeric type",
                kv[0].c_str(), kv[1].c_str());
        } else if (kv[0] == KEY_STOP_TIME) {
            CHECK_AND_CONTINUE_ERR_LOG(MediaBgTaskUtils::StrToNumeric(kv[1], info.lastStopTime),
                "fail to convert key:%{public}s, value:%{public}s to numeric type",
                kv[0].c_str(), kv[1].c_str());
        } else if (kv[0] == KEY_IS_RUNNING) {
            info.isRunning = ("1" == kv[1]);
        } else if (kv[0] == KEY_EXCEED_ENERGY) {
            info.exceedEnergy = ("1" == kv[1]);
        } else if (kv[0] == KEY_EXCEED_ENERGY_TIME) {
            CHECK_AND_CONTINUE_ERR_LOG(MediaBgTaskUtils::StrToNumeric(kv[1], info.exceedEnergySetTime),
                "fail to convert key:%{public}s, value:%{public}s to numeric type",
                kv[0].c_str(), kv[1].c_str());
        } else if (kv[0] == KEY_IS_COMPLETE) {
            info.isComplete = ("1" == kv[1]);
        } else if (kv[0] == KEY_TASK_ENABLE) {
            int taskEnable = -1;
            CHECK_AND_CONTINUE_ERR_LOG(MediaBgTaskUtils::StrToNumeric(kv[1], taskEnable),
                "fail to convert key:%{public}s, value:%{public}s to numeric type",
                kv[0].c_str(), kv[1].c_str());
            CHECK_AND_CONTINUE_ERR_LOG(MediaBgTaskUtils::IsValidTaskEnable(taskEnable),
                "key:%{public}s, value:%{public}s invalid value to convert to TaskEnable",
                kv[0].c_str(), kv[1].c_str());
            info.taskEnable_ = (TaskEnable)taskEnable;
        }
    }
}

// 保存任务状态
void TaskInfoMgr::SaveTaskState(bool onlyCriticalInfo)
{
    MEDIA_INFO_LOG("SaveTaskState");
    std::lock_guard<std::mutex> lock(saveStateMutex_);
    std::vector<int32_t> allActiveIds = {};
    ErrCode errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(allActiveIds);
    std::set<int32_t> &allUserIds = SystemStateMgr::GetInstance().GetSystemState().allUserIds;
    std::string resContent;

    // 检查用户的不同状态：删除、激活，并做不同的处理
    std::string readContent;
    // 1、用户存在-已激活：保存最新的状态
    for (auto it = allTaskInfos_.begin(); it != allTaskInfos_.end(); it++) {
        const TaskInfo &info = it->second;
        resContent += TaskInfoToLineString(info, onlyCriticalInfo);
        resContent += LINE_END;
    }

    std::string readFilePath = GetPersistTaskInfoFilePathRead();
    LoadStringFromFile(readFilePath, readContent);
    std::vector<std::string> lines;
    SplitStr(readContent, LINE_END, lines);
    for (size_t i = 0; i < lines.size(); i++) {
        std::string userIdStr;
        GetFirstSubStrBetween(lines[i], TASKID_USERID_SEP, SEG_SEP, userIdStr);
        if (userIdStr == "") {
            // 2、用户不存在：删除任务状态
            MEDIA_INFO_LOG("UserId NOT exist, task info %{public}s", lines[i].c_str());
        } else {
            int32_t userId = std::stoi(userIdStr);
            if (allUserIds.count(userId) == 0) {
                MEDIA_INFO_LOG("UserId %{public}d NOT exist, delete task info %{public}s", userId, lines[i].c_str());
                continue;
            }
            if (std::count(allActiveIds.begin(), allActiveIds.end(), userId) == 0) {
                // 3、用户存在-未激活：保持之前状态
                resContent += lines[i];
                resContent += LINE_END;
            }
            // else 已激活，不使用之前保存的，在1、中从TaskInfo中生成并保存
        }
    }

    // 写入任务信息
    std::string filePath = GetPersistTaskInfoFilePathWrite();
    bool success = SaveStringToFile(filePath, resContent);
    if (success) {
        MEDIA_INFO_LOG("SaveTaskState success");
        RemoveFile(TASK_INFO_PERSIST_FILE_BAK);
    } else {
        MEDIA_ERR_LOG("SaveTaskState fail, error: %{public}d", errno);
    }
}

// 启动的时候，恢复任务状态
void TaskInfoMgr::RestoreTaskState()
{
    MEDIA_INFO_LOG("RestoreTaskState");
    std::string filePath = GetPersistTaskInfoFilePathRead();
    if (!FileExists(filePath)) {
        MEDIA_INFO_LOG("No state file need to restore");
        return;
    }
    std::string content;
    bool success = LoadStringFromFile(filePath, content);
    if (success) {
        MEDIA_INFO_LOG("RestoreTaskState read file success");
    } else {
        MEDIA_ERR_LOG("RestoreTaskState read file fail, error: %{public}d", errno);
        return;
    }
    std::vector<std::string> lines;
    SplitStr(content, LINE_END, lines);
    for (size_t i = 0; i < lines.size(); i++) {
        std::vector<std::string> segs;
        SplitStr(lines[i], SEG_SEP, segs);
        std::string taskId = segs[0];
        auto iter = allTaskInfos_.find(taskId);
        if (iter == allTaskInfos_.end()) {
            MEDIA_WARN_LOG("taskId %{public}s NOT found", taskId.c_str());
        } else {
            TaskInfo &info = iter->second;
            LineStringToTaskInfo(segs, info);
        }
    }
}

bool TaskInfoMgr::IsSaTaskMatchProcess(const TaskInfo &info, int32_t saId)
{
    return info.scheduleCfg.type == "sa" && info.scheduleCfg.saId == saId;
}

bool TaskInfoMgr::IsAppTaskMatchProcess(const TaskInfo &info, const std::string &appBundle, int32_t appUserId)
{
    if (info.scheduleCfg.type == "app") {
        int32_t userId = GetUserIdFromTaskId(info.taskId);
        return userId == appUserId;
    }
    return false;
}

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

