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

#include "schedule_policy.h"
#include <vector>
#include <algorithm>
#include <iostream>
#include "media_bgtask_utils.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

bool LessSort(AgingFactorMapElement a, AgingFactorMapElement b)
{
    return a.waitingPressure < b.waitingPressure;
}

void SchedulePolicy::SetSchedulePolicy(const UnifySchedulePolicyCfg &policy)
{
    policyCfg_ = policy;
    sort(policyCfg_.agingFactorMap.begin(), policyCfg_.agingFactorMap.end(), LessSort);
}

void UpdateTasksState(TaskInfo &task, TaskInfo &newStateTask)
{
    task = newStateTask;
    task.mustStart = false;
}

void SchedulePolicy::GetTasksState(std::map<std::string, TaskInfo>  &taskInfos)
{
    for (std::map<std::string, TaskInfo>::iterator it = taskInfos.begin(); it != taskInfos.end(); it++) {
        UpdateTasksState(allTasksList_[it->first], it->second);
    }
}

bool SchedulePolicy::SatisfyStorage(const TaskStartSubCondition &condition)
{
    if (condition.storageFreeRangeLow != -1) {
        if (sysInfo_.storageFree < condition.storageFreeRangeLow ||
            sysInfo_.storageFree > condition.storageFreeRangeHig) {
            return false;
        }
    }
    return true;
}

bool SchedulePolicy::SatisfyNetwork(const TaskStartSubCondition &condition)
{
    if ((condition.networkType == "wifi" && !sysInfo_.wifiConnected) ||
        (condition.networkType == "cell" && !sysInfo_.CellularConnect) ||
        (condition.networkType == "any" && !sysInfo_.wifiConnected && !sysInfo_.CellularConnect)) {
        return false;
    }
    return true;
}

bool SchedulePolicy::StartCondition(const TaskStartSubCondition &condition) // LOG
{
    if ((condition.isCharging == 0 && sysInfo_.charging) || (condition.isCharging == 1 && !sysInfo_.charging)) {
        return false;
    }
    if ((condition.screenOff == 0 && sysInfo_.screenOff) || (condition.screenOff == 1 && !sysInfo_.screenOff)) {
        return false;
    }
    if ((condition.batteryCapacity != -1) && (condition.batteryCapacity > sysInfo_.batteryCap)) {
        return false;
    }
    if (!SatisfyStorage(condition)) {
        return false;
    }
    if (!SatisfyNetwork(condition)) {
        return false;
    }
    if (!condition.checkParamBeforeRun.empty()) {
        if (!MediaBgTaskUtils::IsParamTrueOrLtZero(condition.checkParamBeforeRun)) {
            return false;
        }
    }
    return true;
}

int SchedulePolicy::SysLoad()
{
    if (sysInfo_.loadLevel < policyCfg_.sysLoadLowLevel) {
        return SysAndTaskLoad::LOW;
    } else if (sysInfo_.loadLevel < policyCfg_.sysLoadMediumLevel) {
        return SysAndTaskLoad::MEDIUM;
    } else {
        return SysAndTaskLoad::HIGH;
    }
}

bool SchedulePolicy::TaskCanStart(const TaskInfo &task)
{
    if ((task.taskEnable_ == NO_MODIFY && !task.scheduleCfg.taskPolicy.defaultRun) ||
        (task.taskEnable_ == MODIDY_DISABLE)) {
        return false;
    }
    if ((!sysInfo_.charging) && (task.exceedEnergy)) {
        return false;
    }
    if ((!sysInfo_.screenOff) && (SysLoad() == SysAndTaskLoad::MEDIUM) &&
        (task.scheduleCfg.taskPolicy.loadLevel == SysAndTaskLoad::HIGH)) {
        return false;
    }
    if ((!sysInfo_.screenOff) && (SysLoad() == SysAndTaskLoad::HIGH)) {
        return false;
    }
    if (task.isComplete) {
        return false;
    }
    if (task.scheduleCfg.taskPolicy.startCondition.reScheduleInterval != -1) {
        if (sysInfo_.now - task.lastStopTime <
            task.scheduleCfg.taskPolicy.startCondition.reScheduleInterval * SECONDSPERMINUTE_) {
            return false;
        }
    }
    if (task.scheduleCfg.taskPolicy.maxRunningTime != -1) {
        if (task.isRunning &&
           (sysInfo_.now - task.startTime_ >= task.scheduleCfg.taskPolicy.maxRunningTime * SECONDSPERMINUTE_)) {
            return false;
        }
    }
    for (size_t i = 0 ; i < task.scheduleCfg.taskPolicy.startCondition.conditionArray.size(); i++) {
        if (StartCondition(task.scheduleCfg.taskPolicy.startCondition.conditionArray[i])) {
            return true;
        }
    }
    return false;
}

void SchedulePolicy::GetValidTasks()
{
    for (std::map<std::string, TaskInfo>::iterator it = allTasksList_.begin(); it != allTasksList_.end(); it++) {
        if (TaskCanStart(it->second)) {
            validTasks_.push_back(it->second);
            validTasksId_.insert(it->first);
        }
    }
}

float SchedulePolicy::GetAgingFactor(const float &waitPressure)
{
    for (size_t i = 0; i < policyCfg_.agingFactorMap.size(); i++) {
        if (waitPressure < policyCfg_.agingFactorMap[i].waitingPressure) {
            return policyCfg_.agingFactorMap[i].agingFactor;
        }
    }
    return 1e-2;
}

void SchedulePolicy::CalculateVRunTime(TaskInfo &task)
{
    float waitPressure = 0;
    if (!task.isRunning) {
        if (task.scheduleCfg.taskPolicy.maxToleranceTime == 0) {
            task.scheduleCfg.taskPolicy.maxToleranceTime = MAXWAITTINGHOURS_;
        }
        waitPressure = (sysInfo_.now - task.lastStopTime) /
                float(task.scheduleCfg.taskPolicy.maxToleranceTime * SECONDSPERHOUR_);
    }
    float agingFactor = GetAgingFactor(waitPressure);
    task.vrunTime = task.scheduleCfg.taskPolicy.priorityFactor * agingFactor;
    if (waitPressure > policyCfg_.waitingPressureThred) {
        task.mustStart = true;
    }
}

void SchedulePolicy::UpdateValidTasksVRunTime()
{
    for (size_t i = 0; i < validTasks_.size(); ++i) {
        CalculateVRunTime(validTasks_[i]);
    }
}

void SchedulePolicy::SplitTasks()
{
    for (size_t i = 0; i < validTasks_.size(); ++i) {
        if (validTasks_[i].mustStart) {
            validTasksMustStart_.push_back(validTasks_[i]);
            continue;
        }
        validTasksNotMustStart_.push_back(validTasks_[i]);
    }
}

void ClearQueue(std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> &taskQueue)
{
    while (!taskQueue.empty()) {
        taskQueue.pop();
    }
}

void SchedulePolicy::AddValidTaskToQueues(std::vector<TaskInfo> &tasks)
{
    ClearQueue(hTaskQueue_);
    ClearQueue(mTaskQueue_);
    ClearQueue(lTaskQueue_);
    for (size_t i = 0; i < tasks.size(); i++) {
        if (tasks[i].scheduleCfg.taskPolicy.priorityLevel == 0) {
            hTaskQueue_.push(tasks[i]);
        } else if (tasks[i].scheduleCfg.taskPolicy.priorityLevel == 1) {
            mTaskQueue_.push(tasks[i]);
        } else {
            lTaskQueue_.push(tasks[i]);
        }
    }
}

bool SchedulePolicy::CanConcurrency(const TaskInfo &task)
{
    for (size_t i = 0; i < task.scheduleCfg.taskPolicy.conflictedTask.size(); i++) {
        if (selectedTasksId_.find(task.scheduleCfg.taskPolicy.conflictedTask[i]) != selectedTasksId_.end()) {
            return false;
        }
    }
    return true;
}

int SchedulePolicy::TotalLoad()
{
    int totalLoad = 0;
    for (size_t i = 0; i < selectedTasks_.size(); i++) {
        totalLoad += selectedTasks_[i].scheduleCfg.taskPolicy.loadScale;
    }
    return totalLoad;
}

bool SchedulePolicy::CanAddTask(const TaskInfo &task, const int &loadThred)
{
    if ((task.scheduleCfg.taskPolicy.loadScale + TotalLoad() <= loadThred) && CanConcurrency(task)) {
        return true;
    }
    return false;
}

void SchedulePolicy::SelectTaskFromQueue(std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> &taskQueues,
                                         const int &loadThred)
{
    while (!taskQueues.empty()) {
        TaskInfo task = taskQueues.top();
        if (CanAddTask(task, loadThred)) {
            selectedTasks_.push_back(task);
            selectedTasksId_.insert(task.taskId);
        }
        taskQueues.pop();
    }
}

void SchedulePolicy::CommonSchedule(const int &loadThred)
{
    MEDIA_INFO_LOG("hTaskQueue_: %{public}zu, mTaskQueue_: %{public}zu, lTaskQueue_: %{public}zu",
        hTaskQueue_.size(), mTaskQueue_.size(), lTaskQueue_.size());
    if (!hTaskQueue_.empty()) {
        SelectTaskFromQueue(hTaskQueue_, loadThred);
    }
    if (!mTaskQueue_.empty()) {
        SelectTaskFromQueue(mTaskQueue_, loadThred);
    }
    if (!lTaskQueue_.empty()) {
        SelectTaskFromQueue(lTaskQueue_, loadThred);
    }
}

void SchedulePolicy::Schedule()
{
    if (sysInfo_.screenOff) {
        CommonSchedule(policyCfg_.loadThredHigh);
    } else {
        if (SysLoad() == SysAndTaskLoad::LOW) {
            CommonSchedule(policyCfg_.loadThredMedium);
        } else if (SysLoad() == SysAndTaskLoad::MEDIUM) {
            CommonSchedule(policyCfg_.loadThredLow);
        } else {
            selectedTasks_.clear();
        }
    }
}

time_t SchedulePolicy::MinNextScheduleInterval()
{
    time_t minNextInterval = INT_MAX;
    for (size_t i = 0; i < validTasks_.size(); i++) {
        if ((selectedTasksId_.find(validTasks_[i].taskId) == selectedTasksId_.end()) && (!validTasks_[i].isRunning)) {
            time_t waitTime = sysInfo_.now - validTasks_[i].lastStopTime;
            time_t nextInterval = validTasks_[i].scheduleCfg.taskPolicy.maxToleranceTime * SECONDSPERHOUR_ - waitTime;
            minNextInterval = std::min(minNextInterval, nextInterval);
        }
    }
    if (minNextInterval <= 0) {
        minNextInterval = policyCfg_.minNextInterval * SECONDSPERMINUTE_;
    }
    return minNextInterval;
}

void SchedulePolicy::GetSchedulResult(TaskScheduleResult &result)
{
    for (std::map<std::string, TaskInfo>::iterator it = allTasksList_.begin(); it != allTasksList_.end(); it++) {
        bool isRunning = allTasksList_[it->first].isRunning;
        if (selectedTasksId_.find(it->first) != selectedTasksId_.end()) {
            if (isRunning) {
                result.taskRetain_.push_back(it->first);
            } else {
                result.taskStart_.push_back(it->first);
            }
        } else {
            if (!isRunning) {
                result.taskRetain_.push_back(it->first);
            } else {
                result.taskStop_.push_back(it->first);
            }
        }
    }
    result.nextComputeTime_ = MinNextScheduleInterval();
}

void SchedulePolicy::GetNoSchedulResult(TaskScheduleResult &result)
{
    for (std::map<std::string, TaskInfo>::iterator it = allTasksList_.begin(); it != allTasksList_.end(); it++) {
        if (validTasksId_.find(it->first) != validTasksId_.end()) {
            result.taskStart_.push_back(it->first);
            continue;
        }
        result.taskStop_.push_back(it->first);
    }
    result.nextComputeTime_ = INT_MAX;
}

TaskScheduleResult SchedulePolicy::ScheduleTasks(std::map<std::string, TaskInfo> &taskInfos, SystemInfo & sysInfo)
{
    MEDIA_INFO_LOG("current status: %{public}s", sysInfo.ToString().c_str());
    // step0. 获取系统状态
    sysInfo_ = sysInfo;
    validTasks_.clear();
    validTasksId_.clear();
    validTasksMustStart_.clear();
    validTasksNotMustStart_.clear();
    selectedTasks_.clear();
    selectedTasksId_.clear();
    TaskScheduleResult result;
    // step1. 充电、非充电触发温控判断. 此处需确认， 温度档位和温度的关系，是否对应
    if (((sysInfo.charging) && (sysInfo_.thermalLevel > policyCfg_.temperatureLevelThredCharing)) ||
        ((!sysInfo.charging) && (sysInfo_.thermalLevel > policyCfg_.temperatureLevelThredNoCharing))) {
        result.nextComputeTime_ = INT_MAX; // 超温控，返回一个默认值，例如INT_MAX。温控恢复后自然会调用本函数
        result.taskStart_.clear();
        for (std::map<std::string, TaskInfo>::iterator it = allTasksList_.begin(); it != allTasksList_.end(); it++) {
            result.taskStop_.push_back(it->first);
        }
        return result;
    }
    // step2. 更新任务状态
    GetTasksState(taskInfos);
    // step3. 根据当前系统状态+任务状态+任务启停条件，筛选满足执行条件的有效任务
    GetValidTasks();
    // step4. 逃生通道判断，如果走逃生通道，则不进行算法调度，直接启动所有有效任务
    if (!policyCfg_.scheduleEnable) {
        GetNoSchedulResult(result);
        return result;
    }
    // step5. 对有效任务计算vruntime，并找出必须立即启动任务
    UpdateValidTasksVRunTime();
    // step6. 从有效任务中选出必须启动任务（到达等待时间）和其他任务
    SplitTasks();
    // step7. 从有效任务中，先处理必须启动任务;并在当前系统状态下，选择对应的调度策略，从优先级队列中选出最终启动的任务
    AddValidTaskToQueues(validTasksMustStart_);
    Schedule();
    // step8. 从有效任务中，再处理非必须启动任务;并在当前系统状态下，选择对应的调度策略，从优先级队列中选出最终启动的任务
    AddValidTaskToQueues(validTasksNotMustStart_);
    Schedule();
    // step9. 获取启动、停止任务列表，并计算下次调用时间
    GetSchedulResult(result);
    MEDIA_INFO_LOG("success ScheduleTasks, startTask: %{public}zu, stopTask: %{public}zu, retainTask: %{public}zu.",
        result.taskStart_.size(), result.taskStop_.size(), result.taskRetain_.size());
    return result;
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS
