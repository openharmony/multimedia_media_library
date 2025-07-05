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

#ifndef MEDIALIB_BGTASK_DFX_LOG_H_
#define MEDIALIB_BGTASK_DFX_LOG_H_

#include <mutex>

#include "hisysevent.h"
#include "schedule_policy.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
// 错误码及子错误码
enum class BgtaskMgrErrorType {
    INIT_ERR = 1, // 初始化错误
    CONFIG_ERR, // 配置处理错误
    TASK_PERSIST_ERR, // 任务持久化错误
    SYSTEM_INFO_ERR, // 系统状态错误
    SCHEDULE_ERROR, // SA/Ability拉起/调用相关错误
};

enum class InitErrorCode {
    // SA相关初始化
    SA_PUBLISH_FAILED = 1, // SA publish失败
};

enum class ConfigErrorCode {
    // 配置相关初始化
    COTA_EVENT_SUB_FAILED = 1, // COTA 事件订阅失败
    // 任务配置相关
    TASK_CONFIG_OPEN_FAILED = 100, // 任务配置文件打开失败
    TASK_CONFIG_JSON_FORMAT_ERR, // 任务配置json格式错误
    TASK_CONFIG_PARSE_ERR, // 任务配置解析错误
    // 云推配置相关
    POLICY_CONFIG_OPEN_FAILED = 200, // 云推策略配置文件打开失败
    POLICY_CONFIG_JSON_FORMAT_ERR, // 云推配置文件json格式错误
    POLICY_CONFIG_PARSE_ERR, // 云推配置文件解析错误
};

enum class TaskPersistErrorCode {
    TASK_WRITE_FAILED = 1, // 任务持久化写失败
    TASK_READ_FAILED, // 任务持久化读失败
};

enum class SystemInfoErrorCode {
    // 系统状态相关初始化
    DYNAMIC_EVENT_SUB_FAILED = 1, // 订阅系统状态CES事件失败
    // 系统状态相关
    BATTERY_STATE_ERR = 100, // (查/监听)电池状态错误
    THERMAL_LOAD_ERR, // (查/监听)温控级别状态错误
    NETWORK_STATE_ERR, // (查/监听)查询温控级别状态错误
    FORGROUND_USER_INFO_ERR, // (查/监听)前台用户错误
    STORAGE_INFO_ERR, // (查/监听）剩余存储空间错误
};

enum class ScheduleErrorCode {
    // SA连接相关错误
    SA_LOAD_FAILED = 1, // 拉起SA失败
    SA_CALL_ERR, // SA调用失败
    // APP 连接相关错误
    APP_CONNECT_FAILED = 100,
    APP_CALL_ERR,
};

class Timer {
public:
    Timer();
    bool Is24HoursPassed();
private:
    std::chrono::system_clock::time_point lastTime_;
};

class TaskOpsStatDFXManager {
public:
    struct TaskOpsStatInfo {
        std::string taskName_;
        uint16_t startCounts_ = 0;
        uint16_t stopCounts_ = 0;
        uint16_t completeCounts_ = 0;
        uint16_t modifyEnableCounts_ = 0;
        uint16_t modifyDisableCounts_ = 0;
        uint16_t modifySkitTodayCounts_ = 0;
        uint16_t runningSeconds_ = 0;
    };
    static TaskOpsStatDFXManager& GetInstance()
    {
        static TaskOpsStatDFXManager taskOpsStatDFXMangager;
        return taskOpsStatDFXMangager;
    }
    TaskOpsStatDFXManager(const TaskOpsStatDFXManager&) = delete;
    TaskOpsStatDFXManager& operator=(const TaskOpsStatDFXManager&) = delete;

    void ReportTaskStart(const std::string& taskName);
    void ReportTaskStop(const std::string& taskName);
    void ReportTaskComplete(const std::string& taskName);
    void ReportTaskModifyEnable(const std::string& taskName);
    void ReportTaskModifyDisable(const std::string& taskName);
    void ReportTaskModifySkipToday(const std::string& taskName);
    void UpdateTaskRunningTime(const std::string& taskName, uint16_t elapseSeconds);
private:
    TaskOpsStatDFXManager();
    void CheckAndDoTaskOpsStatDFXLocked();
    void ResetTaskStatLocked();
    bool IsValidTaskName(const std::string& taskName);
    std::mutex mtx_;
    Timer timer_;
    std::unordered_map<std::string, TaskOpsStatInfo> taskOpsStatMap_;
};

class ScheduleStatDFXManager {
public:
    struct ScheduleStatInfo {
        uint32_t totoalScheduleTimes_ = 0;
        uint32_t chargingTempExceedTimes_ = 0;
        uint32_t unChargingTempExceedTimes_ = 0;
        std::vector<uint32_t> systemLoadLevelCount_{0, 0, 0};
        std::vector<uint32_t> taskLoadLevelCount_{0, 0, 0};
    };
    static ScheduleStatDFXManager& GetInstance()
    {
        static ScheduleStatDFXManager scheduleStatDFXManager;
        return scheduleStatDFXManager;
    }
    ScheduleStatDFXManager(const ScheduleStatDFXManager&) = delete;
    ScheduleStatDFXManager& operator=(const ScheduleStatDFXManager&) = delete;

    void ReportSchedule();
    void ReportChargingTempExceed();
    void ReportUnChargingTempExceed();
    void ReportSystemLoadLevel(SysAndTaskLoad systemLoad);
    void ReportTaskLoadLevel(SysAndTaskLoad taskLoad);
private:
    ScheduleStatDFXManager() : timer_() {}
    void CheckAndDoScheduleStatDFXLocked();
    void ResetScheduleStatLocked();
    std::mutex mtx_;
    Timer timer_;
    ScheduleStatInfo scheduleStatInfo_;
};

class MediaLibraryBgTaskDFX {
public:
    using SubErrCodeType = std::variant<InitErrorCode, ConfigErrorCode, TaskPersistErrorCode,\
        SystemInfoErrorCode, ScheduleErrorCode>;
    
    static void TaskMgrErrorDFX(BgtaskMgrErrorType errType, SubErrCodeType errCode, const std::string& taskName = "",
        uint32_t uid = UINT32_MAX);
    static void TaskOpsStatDFX(const std::vector<TaskOpsStatDFXManager::TaskOpsStatInfo>& taskOpsStatVec);
    static void SchedulePolicyUpdateDFX(const std::string& newVersion, const std::string& oldVersion);
    static void ScheduleStat(uint32_t totalScheduleTimes, uint32_t chargingTempExceedTimes,
        uint32_t unChargingTempExceedTimes, const std::vector<uint32_t>& systemLoadLevelCount,
        const std::vector<uint32_t>& taskLoadLevelCount);
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // MEDIALIB_BGTASK_DFX_LOG_H_
