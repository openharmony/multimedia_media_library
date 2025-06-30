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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SCHEDULE_POLICY_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SCHEDULE_POLICY_H

#include <vector>
#include <string>
#include <queue>
#include <unordered_set>
#include "system_state_mgr.h"
#include "task_info_mgr.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

enum SysAndTaskLoad {
    LOW = 0,
    MEDIUM,
    HIGH,
};

struct TaskScheduleResult {
    time_t nextComputeTime_;
    std::vector<std::string> taskStart_;
    std::vector<std::string> taskStop_;
    std::vector<std::string> taskRetain_;
};

struct cmp {
    bool operator()(TaskInfo &task1, TaskInfo &task2)
    {
        return task1.vrunTime > task2.vrunTime;
    }
};

class SchedulePolicy {
public:
    static SchedulePolicy &GetInstance()
    {
        static SchedulePolicy inst;
        return inst;
    }
    SchedulePolicy() {}
    ~SchedulePolicy() {}
    void SetSchedulePolicy(const UnifySchedulePolicyCfg &policy);
    std::map<std::string, TaskInfo> &GetAllTaskList();
    TaskScheduleResult ScheduleTasks(std::map<std::string, TaskInfo> &taskInfos, SystemInfo &systemInfo);

private:
    const int SECONDSPERHOUR_ = 3600;
    const int SECONDSPERMINUTE_ = 60;
    const int MAXWAITTINGHOURS_ = 1;
    UnifySchedulePolicyCfg policyCfg_;
    SystemInfo sysInfo_;  // 系统状态,每次被调度时刷新状态
    std::map<std::string, TaskInfo> allTasksList_;  // 全部任务，每次被调度时刷新状态
    std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> hTaskQueue_;
    std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> mTaskQueue_;
    std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> lTaskQueue_;
    std::vector<TaskInfo> validTasks_;                      // 存放本次满足启动条件的任务列表
    std::unordered_set<std::string> validTasksId_;
    std::vector<TaskInfo> validTasksMustStart_;             // 存放本次满足启动条件的，且必须立即执行的任务列表
    std::vector<TaskInfo> validTasksNotMustStart_;          // 存放本次满足启动条件的，非必须立即执行的任务列表
    std::vector<TaskInfo> selectedTasks_;                   // 存放本次最终选出的要执行的任务列表
    std::unordered_set<std::string> selectedTasksId_;
    bool isNight_;
    void GetTasksState(std::map<std::string, TaskInfo>  &allTasks);
    int SysLoad();
    bool SatisfyStorage(const TaskStartSubCondition &condition);
    bool SatisfyNetwork(const TaskStartSubCondition &condition);
    bool SatisfyThermal(const TaskStartSubCondition &condition);
    bool StartCondition(const TaskStartSubCondition &condition);
    bool TaskCanStart(const TaskInfo &task);
    void GetValidTasks();
    float GetAgingFactor(const float &waitPress);
    void CalculateVRunTime(TaskInfo &task);
    void UpdateValidTasksVRunTime();
    void SplitTasks();
    void AddValidTaskToQueues(std::vector<TaskInfo> &tasks);
    bool CanConcurrency(const TaskInfo &task);
    int TotalLoad();
    bool CanAddTask(const TaskInfo &task, const int &loadThred);
    void SelectTaskFromQueue(std::priority_queue<TaskInfo, std::vector<TaskInfo>, cmp> &taskQueue,
                             const int &loadThred);
    void CommonSchedule(const int &loadThred);
    void Schedule();
    time_t MinNextScheduleInterval();
    void GetSchedulResult(TaskScheduleResult &result);
    void GetNoSchedulResult(TaskScheduleResult &result);
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SCHEDULE_POLICY_H
