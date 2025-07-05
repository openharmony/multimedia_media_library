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

#define MLOG_TAG "MediaLibraryBgTaskDFX"

#include <sstream>

#include "media_bgtask_dfx.h"
#include "media_bgtask_mgr_log.h"
#include "task_schedule_param_manager.h"
#include "media_bgtask_schedule_service.h"

namespace OHOS::MediaBgtaskSchedule {
// BGTASK_MGR_ERROR
static constexpr char BGTASK_MGR_ERROR[] = "BGTASK_MGR_ERROR";
static constexpr char DOMAIN[] = "MEDIALIBRARY";
static constexpr int DFX_SUCCESS_RET = 0;
static constexpr char ERROR_TYPE[] = "ERROR_TYPE";
static constexpr char ERROR_CODE[] = "ERROR_CODE";
static constexpr char UID[] = "UID";
static constexpr char TASK_NAME[] = "TASK_NAME";
// TASK_OPS_STAT
static constexpr char TASK_OPS_STAT[] = "TASK_OPS_STAT";
static constexpr char TASK_NAMES[] = "TASK_NAMES";
static constexpr char START_COUNTS[] = "START_COUNTS";
static constexpr char STOP_COUNTS[] = "STOP_COUNTS";
static constexpr char COMPLETE_COUNTS[] = "COMPLETE_COUNTS";
static constexpr char MODIFY_ENABLE_COUNTS[] = "MODIFY_ENABLE_COUNTS";
static constexpr char MODIFY_DISABLE_COUNTS[] = "MODIFY_DISABLE_COUNTS";
static constexpr char MODIFY_SKIT_TODAY_COUNTS[] = "MODIFY_SKIT_TODAY_COUNTS";
static constexpr char RUNNING_TIMES[] = "RUNNING_TIMES";
// SCHEDULE_POLICY_UPDATE
static constexpr char SCHEDULE_POLICY_UPDATE[] = "SCHEDULE_POLICY_UPDATE";
static constexpr char NEW_VERSION[] = "NEW_VERSION";
static constexpr char OLD_VERSION[] = "OLD_VERSION";
// SCHEDULE_STAT
static constexpr char SCHEDULE_STAT[] = "SCHEDULE_STAT";
static constexpr char TOTAL_SCHEDULE_TIMES[] = "TOTAL_SCHEDULE_TIMES";
static constexpr char CHARGING_TEMP_EXCEED_TIMES[] = "CHARGING_TEMP_EXCEED_TIMES";
static constexpr char UNCHARGING_TEMP_EXCEED_TIMES[] = "UNCHARGING_TEMP_EXCEED_TIMES";
static constexpr char SYSTEM_LOAD_LEVEL_COUNT[] = "SYSTEM_LOAD_LEVEL_COUNT";
static constexpr char TASK_LOAD_LEVEL_COUNT[] = "TASK_LOAD_LEVEL_COUNT";
static constexpr size_t LEVEL_COUNT_SZIE = 3;

static constexpr int BG_TASK_STAT_REPORT_PERIOD_HOUR = 24;
static constexpr int LOW_LOAD_INDEX = 0;
static constexpr int MEDIUM_LOAD_INDEX = 1;
static constexpr int HIGH_LOAD_INDEX = 2;

Timer::Timer()
{
    lastTime_ = std::chrono::system_clock::now();
}

bool Timer::Is24HoursPassed()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now - lastTime_;
    auto hoursPassed = std::chrono::duration_cast<std::chrono::hours>(duration).count();
    if (hoursPassed >= BG_TASK_STAT_REPORT_PERIOD_HOUR) {
        lastTime_ = now;
        return true;
    } else {
        return false;
    }
}

TaskOpsStatDFXManager::TaskOpsStatDFXManager() : timer_()
{
    ResetTaskStatLocked();
}

// TaskOpsStatDFXManager
void TaskOpsStatDFXManager::CheckAndDoTaskOpsStatDFXLocked()
{
    if (!timer_.Is24HoursPassed()) {
        return;
    }
    MEDIA_INFO_LOG("24hour has passed, try to do taskOpsStat DFX");
    std::vector<TaskOpsStatInfo> taskOpsStatInfoVec;
    for (auto &p : taskOpsStatMap_) {
        taskOpsStatInfoVec.push_back(p.second);
    }
    MEDIA_INFO_LOG("report %{public}zu TaskOpsStatInfo", taskOpsStatInfoVec.size());
    MediaLibraryBgTaskDFX::TaskOpsStatDFX(taskOpsStatInfoVec);
    ResetTaskStatLocked();
}

void TaskOpsStatDFXManager::ResetTaskStatLocked()
{
    taskOpsStatMap_.clear();

    auto allTaskCfg = TaskScheduleParamManager::GetInstance().GetAllTaskCfg();
    for (auto &taskCfg : allTaskCfg) {
        std::string taskName = MediaBgtaskScheduleService::GetTaskNameFromId(taskCfg.taskId);
        if (taskName == "") {
            MEDIA_ERR_LOG("ResetTaskStatLocked failed, fail to get taskName from task id %{public}s",
                taskCfg.taskId.c_str());
            taskOpsStatMap_.clear();
            return;
        }
        taskOpsStatMap_[taskName].taskName_ = taskName;
    }
}

bool TaskOpsStatDFXManager::IsValidTaskName(const std::string& taskName)
{
    return taskOpsStatMap_.count(taskName);
}

void TaskOpsStatDFXManager::ReportTaskStart(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].startCounts_++;
}

void TaskOpsStatDFXManager::ReportTaskStop(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].stopCounts_++;
}

void TaskOpsStatDFXManager::ReportTaskComplete(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].completeCounts_++;
}

void TaskOpsStatDFXManager::ReportTaskModifyEnable(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].modifyEnableCounts_++;
}

void TaskOpsStatDFXManager::ReportTaskModifyDisable(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].modifyDisableCounts_++;
}

void TaskOpsStatDFXManager::ReportTaskModifySkipToday(const std::string& taskName)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].modifySkitTodayCounts_++;
}

void TaskOpsStatDFXManager::UpdateTaskRunningTime(const std::string& taskName, uint16_t elapseSeconds)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoTaskOpsStatDFXLocked();
    if (!IsValidTaskName(taskName)) {
        MEDIA_ERR_LOG("invalid taskName: %{public}s", taskName.c_str());
        return;
    }

    taskOpsStatMap_[taskName].runningSeconds_ += elapseSeconds;
}

// ScheduleStatDFXManager
void ScheduleStatDFXManager::CheckAndDoScheduleStatDFXLocked()
{
    if (!timer_.Is24HoursPassed()) {
        return;
    }
    MEDIA_INFO_LOG("24hour has passed, try to do ScheduleStat DFX");
    MediaLibraryBgTaskDFX::ScheduleStat(scheduleStatInfo_.totoalScheduleTimes_,
        scheduleStatInfo_.chargingTempExceedTimes_, scheduleStatInfo_.unChargingTempExceedTimes_,
        scheduleStatInfo_.systemLoadLevelCount_, scheduleStatInfo_.taskLoadLevelCount_);
    ResetScheduleStatLocked();
}

void ScheduleStatDFXManager::ResetScheduleStatLocked()
{
    scheduleStatInfo_ = ScheduleStatInfo{};
}

void ScheduleStatDFXManager::ReportSchedule()
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoScheduleStatDFXLocked();

    scheduleStatInfo_.totoalScheduleTimes_++;
}

void ScheduleStatDFXManager::ReportChargingTempExceed()
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoScheduleStatDFXLocked();

    scheduleStatInfo_.chargingTempExceedTimes_++;
}

void ScheduleStatDFXManager::ReportUnChargingTempExceed()
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoScheduleStatDFXLocked();

    scheduleStatInfo_.unChargingTempExceedTimes_++;
}

void ScheduleStatDFXManager::ReportSystemLoadLevel(SysAndTaskLoad systemLoad)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoScheduleStatDFXLocked();

    if (systemLoad == SysAndTaskLoad::LOW) {
        scheduleStatInfo_.systemLoadLevelCount_[LOW_LOAD_INDEX]++;
    } else if (systemLoad == SysAndTaskLoad::MEDIUM) {
        scheduleStatInfo_.systemLoadLevelCount_[MEDIUM_LOAD_INDEX]++;
    } else if (systemLoad == SysAndTaskLoad::HIGH) {
        scheduleStatInfo_.systemLoadLevelCount_[HIGH_LOAD_INDEX]++;
    } else {
        MEDIA_ERR_LOG("invalid systemLoad");
    }
}

void ScheduleStatDFXManager::ReportTaskLoadLevel(SysAndTaskLoad taskLoad)
{
    std::lock_guard<std::mutex> lock(mtx_);
    CheckAndDoScheduleStatDFXLocked();

    if (taskLoad == SysAndTaskLoad::LOW) {
        scheduleStatInfo_.taskLoadLevelCount_[LOW_LOAD_INDEX]++;
    } else if (taskLoad == SysAndTaskLoad::MEDIUM) {
        scheduleStatInfo_.taskLoadLevelCount_[MEDIUM_LOAD_INDEX]++;
    } else if (taskLoad == SysAndTaskLoad::HIGH) {
        scheduleStatInfo_.taskLoadLevelCount_[HIGH_LOAD_INDEX]++;
    } else {
        MEDIA_ERR_LOG("invalid taskload");
    }
}

template<typename T>
void CheckAndDoBgTaskMgrErrorDFX(BgtaskMgrErrorType errType, MediaLibraryBgTaskDFX::SubErrCodeType errCode,
    const std::string& taskName, uint32_t uid)
{
    std::visit([=](auto &&arg) {
        if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, T>) {
            int ret = HiSysEventWrite(
                DOMAIN,
                BGTASK_MGR_ERROR,
                HiviewDFX::HiSysEvent::EventType::FAULT,
                ERROR_TYPE, static_cast<uint32_t>(errType),
                ERROR_CODE, static_cast<uint32_t>(arg));
            MEDIA_ERR_LOG("DoBgTaskMgrErrorDFX errType:%{public}u errCode:%{public}d",
                static_cast<uint32_t>(errType), static_cast<uint32_t>(arg));
            if (ret != DFX_SUCCESS_RET) {
                MEDIA_ERR_LOG("fail to report DoBgTaskMgrErrorDFX");
            }
        } else {
            MEDIA_ERR_LOG("invalid subErrCodeType");
        }
        }, errCode);
}


template<>
void CheckAndDoBgTaskMgrErrorDFX<ScheduleErrorCode>(BgtaskMgrErrorType errType,
    MediaLibraryBgTaskDFX::SubErrCodeType errCode, const std::string& taskName, uint32_t uid)
{
    std::visit([=](auto &&arg) {
        if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, ScheduleErrorCode>) {
            int ret = -1;
            if (arg == ScheduleErrorCode::APP_CALL_ERR) {
                ret = HiSysEventWrite(
                    DOMAIN, BGTASK_MGR_ERROR,
                    HiviewDFX::HiSysEvent::EventType::FAULT,
                    ERROR_TYPE, static_cast<uint32_t>(errType),
                    ERROR_CODE, static_cast<uint32_t>(arg),
                    UID, uid, TASK_NAME, taskName.c_str());
            } else if (arg == ScheduleErrorCode::SA_CALL_ERR) {
                ret = HiSysEventWrite(
                    DOMAIN, BGTASK_MGR_ERROR,
                    HiviewDFX::HiSysEvent::EventType::FAULT,
                    ERROR_TYPE, static_cast<uint32_t>(errType),
                    ERROR_CODE, static_cast<uint32_t>(arg),
                    TASK_NAME, taskName.c_str());
            } else {
                ret = HiSysEventWrite(
                    DOMAIN, BGTASK_MGR_ERROR,
                    HiviewDFX::HiSysEvent::EventType::FAULT,
                    ERROR_TYPE, static_cast<uint32_t>(errType),
                    ERROR_CODE, static_cast<uint32_t>(arg));
            }
            MEDIA_ERR_LOG("DoBgTaskMgrErrorDFX errType:%{public}u errCode:%{public}d"
                " uid:%{public}d taskName:%{public}s",
                static_cast<uint32_t>(errType), static_cast<uint32_t>(arg),
                uid, taskName.c_str());
            if (ret != DFX_SUCCESS_RET) {
                MEDIA_ERR_LOG("fail to report DoBgTaskMgrErrorDFX");
            }
        } else {
            MEDIA_ERR_LOG("invalid subErrCodeType");
        }
        }, errCode);
}

void MediaLibraryBgTaskDFX::TaskMgrErrorDFX(BgtaskMgrErrorType errType, SubErrCodeType errCode,
    const std::string& taskName, uint32_t uid)
{
    switch (errType) {
        case BgtaskMgrErrorType::INIT_ERR:
            CheckAndDoBgTaskMgrErrorDFX<InitErrorCode>(errType, errCode, taskName, uid);
            break;
        case BgtaskMgrErrorType::CONFIG_ERR:
            CheckAndDoBgTaskMgrErrorDFX<ConfigErrorCode>(errType, errCode, taskName, uid);
            break;
        case BgtaskMgrErrorType::TASK_PERSIST_ERR:
            CheckAndDoBgTaskMgrErrorDFX<TaskPersistErrorCode>(errType, errCode, taskName, uid);
            break;
        case BgtaskMgrErrorType::SYSTEM_INFO_ERR:
            CheckAndDoBgTaskMgrErrorDFX<SystemInfoErrorCode>(errType, errCode, taskName, uid);
            break;
        case BgtaskMgrErrorType::SCHEDULE_ERROR:
            CheckAndDoBgTaskMgrErrorDFX<ScheduleErrorCode>(errType, errCode, taskName, uid);
            break;
        default:
            MEDIA_ERR_LOG("invalid input errType:%{public}d", static_cast<int>(errType));
            break;
    }
}

void MediaLibraryBgTaskDFX::TaskOpsStatDFX(const std::vector<TaskOpsStatDFXManager::TaskOpsStatInfo>& taskOpsStatVec)
{
    size_t expectedOpsStatInfoSize = TaskScheduleParamManager::GetInstance().GetAllTaskCfg().size();
    if (taskOpsStatVec.size() != expectedOpsStatInfoSize) {
        MEDIA_ERR_LOG("expect %{public}zu taskOpsStatInfo, but got %{public}zu", expectedOpsStatInfoSize,
            taskOpsStatVec.size());
        return;
    }
    std::vector<std::string> taskNames;
    std::vector<uint16_t> startCounts;
    std::vector<uint16_t> stopCounts;
    std::vector<uint16_t> completeCounts;
    std::vector<uint16_t> modifyEnableCounts;
    std::vector<uint16_t> modifyDisableCounts;
    std::vector<uint16_t> modifySkitTodayCounts;
    std::vector<uint16_t> runningTimes;
    for (auto &taskOpsStatInfo : taskOpsStatVec) {
        MEDIA_INFO_LOG("#taskOpsStatInfo: taskName:%{public}s, startCount:%{public}u,"
            " stopCount:%{public}u, completeCounts:%{public}u, modifyEnableCounts:%{public}u"
            " modifyDisableCounts:%{public}u, modifySkitTodayCounts:%{public}u, runningTimes:%{public}u",
            taskOpsStatInfo.taskName_.c_str(), taskOpsStatInfo.startCounts_, taskOpsStatInfo.stopCounts_,
            taskOpsStatInfo.completeCounts_, taskOpsStatInfo.modifyEnableCounts_,
            taskOpsStatInfo.modifyDisableCounts_, taskOpsStatInfo.modifySkitTodayCounts_,
            taskOpsStatInfo.runningSeconds_);
        taskNames.push_back(taskOpsStatInfo.taskName_);
        stopCounts.push_back(taskOpsStatInfo.stopCounts_);
        startCounts.push_back(taskOpsStatInfo.startCounts_);
        completeCounts.push_back(taskOpsStatInfo.completeCounts_);
        modifyEnableCounts.push_back(taskOpsStatInfo.modifyEnableCounts_);
        modifyDisableCounts.push_back(taskOpsStatInfo.modifyDisableCounts_);
        modifySkitTodayCounts.push_back(taskOpsStatInfo.modifySkitTodayCounts_);
        runningTimes.push_back(taskOpsStatInfo.runningSeconds_);
    }
    int ret = HiSysEventWrite(
        DOMAIN,
        TASK_OPS_STAT,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        TASK_NAMES, taskNames,
        START_COUNTS, startCounts,
        STOP_COUNTS, stopCounts,
        COMPLETE_COUNTS, completeCounts,
        MODIFY_ENABLE_COUNTS, modifyEnableCounts,
        MODIFY_DISABLE_COUNTS, modifyDisableCounts,
        MODIFY_SKIT_TODAY_COUNTS, modifySkitTodayCounts,
        RUNNING_TIMES, runningTimes);
    if (ret != DFX_SUCCESS_RET) {
        MEDIA_ERR_LOG("fail to report TaskOpsStatDFX");
    }
}

void MediaLibraryBgTaskDFX::SchedulePolicyUpdateDFX(const std::string& newVersion, const std::string& oldVersion)
{
    MEDIA_INFO_LOG("SchedulePolicyUpdateDFX info: newVersion:%{public}s, oldVersion:%{public}s",
        newVersion.c_str(), oldVersion.c_str());
    int ret = HiSysEventWrite(
        DOMAIN,
        SCHEDULE_POLICY_UPDATE,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        NEW_VERSION, newVersion,
        OLD_VERSION, oldVersion);
    if (ret != DFX_SUCCESS_RET) {
        MEDIA_ERR_LOG("fail to report SchedulePolicyUpdateDFX");
    }
}

static std::string VecToString(const std::vector<uint32_t>& vec)
{
    std::stringstream ss;
    for (auto v : vec) ss << v << ", ";
    return ss.str();
}

void MediaLibraryBgTaskDFX::ScheduleStat(uint32_t totalScheduleTimes, uint32_t chargingTempExceedTimes,
    uint32_t unChargingTempExceedTimes, const std::vector<uint32_t>& systemLoadLevelCount,
    const std::vector<uint32_t>& taskLoadLevelCount)
{
    if (systemLoadLevelCount.size() != LEVEL_COUNT_SZIE || taskLoadLevelCount.size() != LEVEL_COUNT_SZIE) {
        MEDIA_ERR_LOG("expected size of systemLoadLevelCount/taskLoadLevelCount 3, but got"
            " systemLoadLevelCount:%{public}zu, taskLoadLevelCount:%{public}zu",
            systemLoadLevelCount.size(), taskLoadLevelCount.size());
        return;
    }
    MEDIA_INFO_LOG("ScheduleStat info totalScheduleTimes:%{public}u, chargingTempExceedTimes:%{public}u "
        "unChargingTempExceedTimes:%{public}u, systemLoadLevelCount:%{public}s, taskLoadLevelCount:%{public}s",
        totalScheduleTimes, chargingTempExceedTimes, unChargingTempExceedTimes,
        VecToString(systemLoadLevelCount).c_str(), VecToString(taskLoadLevelCount).c_str());

    int ret = HiSysEventWrite(
        DOMAIN,
        SCHEDULE_STAT,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        TOTAL_SCHEDULE_TIMES, totalScheduleTimes,
        CHARGING_TEMP_EXCEED_TIMES, chargingTempExceedTimes,
        UNCHARGING_TEMP_EXCEED_TIMES, unChargingTempExceedTimes,
        SYSTEM_LOAD_LEVEL_COUNT, systemLoadLevelCount,
        TASK_LOAD_LEVEL_COUNT, taskLoadLevelCount);
    if (ret != DFX_SUCCESS_RET) {
        MEDIA_ERR_LOG("fail to report SchedulePolicyUpdateDFX");
    }
}
} // namespace OHOS::MediaBgtaskSchedule
