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
#include "task_schedule_cfg.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_utils.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

std::map<std::string, TaskInfo> &TaskInfoMgr::GetAllTask()
{
    // 考虑多用户，新来用户，直接清理之前的信息
    return allTaskInfos_;
}

void TaskInfoMgr::InitTaskInfoByCfg(std::vector<TaskScheduleCfg> taskCfgs)
{
    size_t taskSize = taskCfgs.size();
    MEDIA_INFO_LOG("Find task cnt %{public}zu", taskSize);
    for (TaskScheduleCfg &cfg : taskCfgs) {
        TaskInfo info;
        info.taskId = cfg.taskId;
        info.SetCfgInfo(cfg);
        allTaskInfos_.insert(std::make_pair(cfg.taskId, info));
    }
}

void TaskInfoMgr::AddTaskForNewUserIfNeed(int32_t newUserId)
{}

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

const std::string KEY_VAL_SEP = ",";
const std::string SEG_SEP = ";";
const std::string LINE_END = "\n";

const std::string KEY_START_TIME = "startTime";
const std::string KEY_STOP_TIME = "lastStopTime";
const std::string KEY_IS_RUNNING = "isRunning";
const std::string KEY_EXCEED_ENERGY = "exceedEnergy";
const std::string KEY_EXCEED_ENERGY_TIME = "exceedEnergySetTime";
const std::string KEY_IS_COMPLETE = "isComplete";
const std::string KEY_TASK_ENABLE = "taskEnable";

static inline std::string ONE_KEY_VALUE(std::string key, std::string value)
{
    return key + KEY_VAL_SEP + value + SEG_SEP;
}

// string格式门，不同字段用';'分隔， 以taskId开头，字段的key和value用','分隔
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
        if (kv.empty()) {
            MEDIA_ERR_LOG("kv is empty, size: %{public}zu, %{public}zu.", segs.size(), i);
            continue;
        }
        if (kv[0] == KEY_START_TIME) {
            info.startTime_ = std::stoll(kv[1]);
        } else if (kv[0] == KEY_STOP_TIME) {
            info.lastStopTime = std::stoll(kv[1]);
        } else if (kv[0] == KEY_IS_RUNNING) {
            info.isRunning = ("1" == kv[1]);
        } else if (kv[0] == KEY_EXCEED_ENERGY) {
            info.exceedEnergy = ("1" == kv[1]);
        } else if (kv[0] == KEY_EXCEED_ENERGY_TIME) {
            info.exceedEnergySetTime = std::stoll(kv[1]);
        } else if (kv[0] == KEY_IS_COMPLETE) {
            info.isComplete = ("1" == kv[1]);
        } else if (kv[0] == KEY_TASK_ENABLE) {
            if (!MediaBgTaskUtils::IsNumber(kv[1])) {
                MEDIA_ERR_LOG("kv[1] is not number.");
                continue;
            }
            info.taskEnable_ = (TaskEnable)std::stoi(kv[1]);
        }
    }
}

// 保存任务状态
void TaskInfoMgr::SaveTaskState(bool onlyCriticalInfo)
{
    MEDIA_INFO_LOG("SaveTaskState");
    // 准备任务信息
    std::string content;
    for (auto it = allTaskInfos_.begin(); it != allTaskInfos_.end(); it++) {
        const TaskInfo &info = it->second;
        content += TaskInfoToLineString(info, onlyCriticalInfo);
        content += LINE_END;
    }
    // 写入任务信息
    std::string filePath = GetPersistTaskInfoFilePathWrite();
    bool success = SaveStringToFile(filePath, content);
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

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

