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

#define MLOG_TAG "MediaBgtaskScheduleServiceAbility"

#include "media_bgtask_schedule_service.h"

#include <cstdlib>

#include <string>
#include <map>
#include <thread>

#include "ffrt_inner.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service_ability.h"
#include "media_bgtask_utils.h"
#include "schedule_policy.h"
#include "task_info_mgr.h"
#include "task_runner.h"
#include "task_schedule_param_manager.h"
#include "system_state_mgr.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
static const std::string TASKID_BUNDLE_SEP = ":";
static const std::string TASKID_USERID_SEP = "@";
constexpr int US_TO_S = 1000 * 1000;

void MediaBgtaskScheduleService::AddDelaySchedule(time_t delaySec)
{
    queue_->submit_h(MediaBgtaskScheduleService::HandleTimerCome, ffrt::task_attr().delay(delaySec * US_TO_S));
}

void MediaBgtaskScheduleService::ClearAllSchedule()
{
    if (queue_) {
        ffrt_queue_t *q = reinterpret_cast<ffrt_queue_t*>(queue_.get());
        ffrt_queue_cancel_all(*q);
    }
}

// 任务名字不符合要求，不应该出现在解析后的信息中
std::string MediaBgtaskScheduleService::GetTaskNameFromId(std::string taskId)
{
    size_t posBundle = taskId.find_first_of(TASKID_BUNDLE_SEP);
    size_t posUserId = taskId.find_first_of(TASKID_USERID_SEP);
    posUserId = posUserId == std::string::npos ? INT_MAX : posUserId;
    if (posBundle == std::string::npos) {
        MEDIA_ERR_LOG("Error task Id: [%{public}s]", taskId.c_str());
        return "";
    }
    return std::string(taskId, posBundle + 1, posUserId - posBundle - 1);
}

void MediaBgtaskScheduleService::Init()
{
    // Init cfg file
    if (!TaskScheduleParamManager::GetInstance().InitParams()) {
        MEDIA_ERR_LOG("fail to init scheduleTask params");
        MediaBgtaskScheduleServiceAbility::ExitSelf(INT_MAX);
    }
    // Init schedule policy by cfg
    auto scheduleCfg = TaskScheduleParamManager::GetInstance().GetScheduleCfg();
    SchedulePolicy::GetInstance().SetSchedulePolicy(scheduleCfg);
    // Init taskInfo by cfg
    auto taskCfgs = TaskScheduleParamManager::GetInstance().GetAllTaskCfg();
    queue_ = std::make_shared<ffrt::queue>("media_ffrt");
    TaskInfoMgr::GetInstance().InitTaskInfoByCfg(taskCfgs);
    TaskInfoMgr::GetInstance().RestoreTaskState();
    // Init stateManager
    SystemStateMgr::GetInstance().Init();
    AddDelaySchedule(SCHEDULE_DELAY_DEFAULT_SEC);
}

bool MediaBgtaskScheduleService::CanExit(TaskScheduleResult &compResult)
{
    // 有任务启动，不能停止
    if (compResult.taskStart_.size() > 0) {
        return false;
    }
    // 有任务中止，说明正在运行，但是还没complete，不能停止
    if (compResult.taskStop_.size() > 0) {
        return false;
    }
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    for (auto &it : allTask) {
        TaskInfo &info = it.second;
        if (!TaskInfoMgr::IsTaskEnabled(info)) {
            continue;
        }
        // 任务未完成，不能停止
        if (!info.isComplete) {
            MEDIA_INFO_LOG("Can not exit, task: %{public}s is not completed", it.first.c_str());
            return false;
        }
    }
    return true;
}

void MediaBgtaskScheduleService::HandleStopTask(TaskScheduleResult &compResult)
{
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    for (auto &taskId : compResult.taskStop_) {
        auto iter = allTask.find(taskId);
        if (iter == allTask.end()) {
            MEDIA_ERR_LOG("Task [%{public}s] not found", taskId.c_str());
            continue;
        }
        TaskInfo &task = iter->second;
        int ret = -1;
        if (task.scheduleCfg.type == "sa") {
            MEDIA_INFO_LOG("SA task no need to stop.");
        } else if (task.scheduleCfg.type == "app") {
            AppSvcInfo svcInfo{task.scheduleCfg.bundleName, task.scheduleCfg.abilityName, task.userId};
            ret = TaskRunner::OpsAppTask(TaskOps::STOP, svcInfo, GetTaskNameFromId(taskId), "");
        } else {
            MEDIA_ERR_LOG("Task [%{public}s] type [%{public}s] unknown", taskId.c_str(), task.scheduleCfg.type.c_str());
        }
        if (ret == 0) {
            task.isRunning = false;
            task.lastStopTime = MediaBgTaskUtils::GetNowTime();
            MEDIA_INFO_LOG("Task [%{public}s] type stop ok", taskId.c_str());
        } else {
            MEDIA_ERR_LOG("Task [%{public}s] type stop failed: %{public}d", taskId.c_str(), ret);
        }
    }
}


void MediaBgtaskScheduleService::HandleStartTask(TaskScheduleResult &compResult)
{
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    for (auto &taskId : compResult.taskStart_) {
        auto iter = allTask.find(taskId);
        if (iter == allTask.end()) {
            MEDIA_ERR_LOG("Task [%{public}s] not found", taskId.c_str());
            continue;
        }
        TaskInfo &task = iter->second;
        int ret = -1;
        if (task.scheduleCfg.type == "sa") {
            ret = TaskRunner::OpsSaTask(TaskOps::START, task.scheduleCfg.saId, GetTaskNameFromId(taskId), "");
        } else if (task.scheduleCfg.type == "app") {
            AppSvcInfo svcInfo{task.scheduleCfg.bundleName, task.scheduleCfg.abilityName, task.userId};
            ret = TaskRunner::OpsAppTask(TaskOps::START, svcInfo, GetTaskNameFromId(taskId), "");
        } else {
            MEDIA_ERR_LOG("Task [%{public}s] type [%{public}s] unknown", taskId.c_str(), task.scheduleCfg.type.c_str());
        }

        if (ret == 0) {
            task.isRunning = true;
            task.lastStopTime = 0;
            task.isComplete = false;
            task.startTime_ = MediaBgTaskUtils::GetNowTime();
            MEDIA_INFO_LOG("Task [%{public}s] type start ok", taskId.c_str());
        } else {
            MEDIA_ERR_LOG("Task [%{public}s] type start failed: %{public}d", taskId.c_str(), ret);
        }
    }
}

void MediaBgtaskScheduleService::HandleReschedule()
{
    MEDIA_INFO_LOG("HandleReschedule");
    LOCK_SCHEDULE_AND_CHANGE();
    ClearAllSchedule();
    SystemStateMgr::GetInstance().UpdateDataFreeSpacePercent();
    TaskScheduleResult compResult = SchedulePolicy::GetInstance().ScheduleTasks(
        TaskInfoMgr::GetInstance().GetAllTask(), SystemStateMgr::GetInstance().GetSystemState());
    AddDelaySchedule(compResult.nextComputeTime_);
    HandleStopTask(compResult);
    HandleStartTask(compResult);

    if (CanExit(compResult)) {
        MEDIA_INFO_LOG("media bgtask mgr can exit");
        MediaBgtaskScheduleServiceAbility::ExitSelf(compResult.nextComputeTime_);
    }
}

// 当有调度策略更新的时候，参数管理模块调用这个接口
void MediaBgtaskScheduleService::HandleScheduleParamUpdate()
{
    MEDIA_INFO_LOG("HandleScheduleParamUpdate");
    AddDelaySchedule(SCHEDULE_DELAY_DEFAULT_SEC);
}

// 当系统状态有变化时，调用这个重新计算
void MediaBgtaskScheduleService::HandleSystemStateChange()
{
    MEDIA_INFO_LOG("HandleSystemStateChange");
    AddDelaySchedule(SCHEDULE_DELAY_DEFAULT_SEC);
}

// 当任务状态有变化时，调用这个重新计算
void MediaBgtaskScheduleService::HandleTaskStateChange()
{
    MEDIA_INFO_LOG("HandleTaskStateChange");
    AddDelaySchedule(SCHEDULE_DELAY_TASK_CHANGE_SEC);
}

// 当定时到的时候，调用这个重新计算
void MediaBgtaskScheduleService::HandleTimerCome()
{
    MEDIA_INFO_LOG("HandleTimerCome");
    MediaBgtaskScheduleService::GetInstance().HandleReschedule();
}

bool MediaBgtaskScheduleService::reportTaskComplete(const std::string &taskId, int32_t &funcResult)
{
    LOCK_SCHEDULE_AND_CHANGE();
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    auto iter = allTask.find(taskId);
    if (iter == allTask.end()) {
        funcResult = 1;
        MEDIA_ERR_LOG("Task [%{public}s] not found", taskId.c_str());
        return false;
    }
    TaskInfo &task = iter->second;
    if (task.isComplete == true) {
        funcResult = 1;
        MEDIA_ERR_LOG("Task [%{public}s] already complete", taskId.c_str());
    }
    task.isComplete = true;
    task.isRunning = false;
    task.lastStopTime = MediaBgTaskUtils::GetNowTime();
    task.startTime_ = 0;
    funcResult = 0;
    HandleTaskStateChange();
    MEDIA_INFO_LOG("success reportTaskComplete, taskId: %{public}s.", taskId.c_str());
    return true;
}

bool MediaBgtaskScheduleService::modifyTask(
    const std::string &taskId, const std::string &modifyInfo, int32_t &funcResult)
{
    LOCK_SCHEDULE_AND_CHANGE();
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    auto iter = allTask.find(taskId);
    funcResult = 0;
    if (iter == allTask.end()) {
        funcResult = 1;
        MEDIA_ERR_LOG("Task [%{public}s] not found", taskId.c_str());
        return true;
    }
    TaskInfo &task = iter->second;
    if (modifyInfo.find("taskRun:true") != std::string::npos) {
        task.taskEnable_ = TaskEnable::MODIFY_ENABLE;
        // 这里不马上触发调度，如果需要再触发 HandleTaskStateChange
    } else if (modifyInfo.find("taskRun:false") != std::string::npos) {
        task.taskEnable_ = TaskEnable::MODIFY_DISABLE;
    } else if (modifyInfo.find("taskRun:skipToday") != std::string::npos) {
        task.exceedEnergy = true;
        task.exceedEnergySetTime = MediaBgTaskUtils::GetNowTime();
    } else {
        funcResult = 1;
        MEDIA_ERR_LOG("Unrecognized modifyinfo [%{public}s]", modifyInfo.c_str());
    }
    TaskInfoMgr::GetInstance().SaveTaskState(true);
    MEDIA_INFO_LOG("success modifyTask, taskId: %{public}s, modifyInfo: %{public}s.",
        taskId.c_str(), modifyInfo.c_str());
    return true;
}

void MediaBgtaskScheduleService::HandleTaskProcessDie(TaskInfo &info)
{
    info.lastStopTime = MediaBgTaskUtils::GetNowTime();
    info.isRunning = false;
    // 改变状态，重新调度
    AddDelaySchedule(SCHEDULE_DELAY_DEFAULT_SEC);
}

void MediaBgtaskScheduleService::NotifySaTaskProcessDie(int32_t saId)
{
    LOCK_SCHEDULE_AND_CHANGE();
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    for (auto it = allTask.begin(); it != allTask.end(); it++) {
        TaskInfo &info = it->second;
        if (TaskInfoMgr::IsSaTaskMatchProcess(info, saId)) {
            HandleTaskProcessDie(info);
        }
    }
}

void MediaBgtaskScheduleService::NotifyAppTaskProcessDie(const std::string &appBundle, int32_t appUserId)
{
    LOCK_SCHEDULE_AND_CHANGE();
    std::map<std::string, TaskInfo> &allTask = TaskInfoMgr::GetInstance().GetAllTask();
    for (auto it = allTask.begin(); it != allTask.end(); it++) {
        TaskInfo &info = it->second;
        if (TaskInfoMgr::IsAppTaskMatchProcess(info, appBundle, appUserId)) {
            HandleTaskProcessDie(info);
        }
    }
}
}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

