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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_INFO_MGR_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_INFO_MGR_H

#include <map>
#include <vector>
#include <mutex>

#include "task_schedule_cfg.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

// 任务的启用、禁用状态
enum TaskEnable {
    // 未修改，用配置文件中的值
    NO_MODIFY,
    // 代码调用使能任务
    MODIDY_ENABLE,
    // 代码调用禁用任务
    MODIDY_DISABLE,
};

// 任务状态版本，所有新增信息都必须面尾部增加
// 做状态持久化时，需要保存下这个版本，如果恢复的时候发现有变化，要做对应处理
constexpr int32_t g_version = 1;

// 配置文件解析出来的任务配置
// 从配置管理引入
// 任务信息，包含静态信息和动态信息
struct TaskInfo {
    // *** 静态参数 ***，由任务配置
    // $(said):taskNameXx 或 $(bundleName):taskName
    // 例子： "10120:cleanCache"、"com.ohos.medialibrary.medialibrarydata:cleanLcd",
    std::string taskId;
    int32_t userId = -1;
    TaskScheduleCfg scheduleCfg;

    // *** 动态参数 ***，表示任务状态
    // 对于正在运行的任务，记录开始执行时间。暂时保留 因为不知道任务要运行多久
    time_t startTime_{0};
    // 上次停止时间，表示方式可能要修改，是否用int表示；框架传入
    time_t lastStopTime{0};
    // 当前是否正在运行；用于判断是否计算下次必须启动时间间隔；框架传入
    bool isRunning{false};
    // 是否超出当日功耗基线，只用于非充电场景进行判断，超出当天不调度；框架传入
    bool exceedEnergy{false};
    time_t exceedEnergySetTime;
    // 是否已完成，进而调用策略函数，本状态下不再调度. 系统切换状态时，由框架置成false；框架传入
    bool isComplete{false};
    // 每轮被调度时，所有任务初始值设为false，通过内部计算得出最终值
    bool mustStart{false};
    // 用于队列内排序，通过内部计算得出最终值
    float vrunTime{0.0};
    // 用户修改后的使能、禁用状态
    TaskEnable taskEnable_{NO_MODIFY};

    void SetCfgInfo(TaskScheduleCfg &cfg)
    {
        scheduleCfg = cfg;
    }
};

class TaskInfoMgr {
public:
    static TaskInfoMgr &GetInstance()
    {
        static TaskInfoMgr inst;
        return inst;
    }

    std::map<std::string, TaskInfo> &GetAllTask();

    // 解析配置的时候，添加新解析到的配置到TaskInfoMgr中
    // TaskScheduleParamManager->GetAllTaskCfg
    void InitTaskInfoByCfg(std::vector<TaskScheduleCfg> taskCfgs);

    void AddTaskForNewUserIfNeed(int32_t newUserId);
    void RemoveTaskForUser(int32_t newUserId);
    // 保存任务状态
    void SaveTaskState(bool onlyCriticalInfo);
    // 启动的时候，恢复任务状态
    void RestoreTaskState();
    static bool IsTaskEnabled(TaskInfo &info);

    // private:
    // 当前的用户信息
    int currentUser_{0};
    // 所有的任务, taskId <-> TaskInfo
    std::map<std::string, TaskInfo> allTaskInfos_;
    static std::string TaskInfoToLineString(TaskInfo info, bool onlyCriticalInfo);
    static void LineStringToTaskInfo(std::vector<std::string> segs, TaskInfo &info);

    static bool IsSaTaskMatchProcess(const TaskInfo &info, int32_t saId);
    static bool IsAppTaskMatchProcess(const TaskInfo &info, const std::string &appBundle, int32_t appUserId);
private:
    std::string TASK_INFO_PERSIST_FILE = "/data/service/el1/public/media_bgtask_mgr/bgtask_task.info";
    std::string TASK_INFO_PERSIST_FILE_BAK = "/data/service/el1/public/media_bgtask_mgr/bgtask_task.info.bak";
    // 获取保存任务的文件路径，注意用atomic file
    std::string GetPersistTaskInfoFilePathRead();
    std::string GetPersistTaskInfoFilePathWrite();
    std::mutex saveStateMutex_;
};

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_INFO_MGR_H
