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

#ifndef TASK_SCH_CFG_H
#define TASK_SCH_CFG_H

#include <map>
#include <set>
#include <string>
#include <vector>

namespace OHOS {
namespace MediaBgtaskSchedule {

constexpr const int MAX_TASK_LIST_LEN = 100;       // 最大任务个数
constexpr const int MAX_CONDITION_ARRAY_LEN = 10;  // 最大组合条件个数
constexpr const int MAX_AGING_FACTOR_MAP_LEN = 10;
constexpr const int MAX_RANGE_NUM_CNT = 2;

constexpr const int MAX_PRIORITY_LEVEL = 2;
constexpr const int MAX_LOAD_LEVEL = 2;
constexpr const int MAX_PRIORITY_FACTOR = 10;
constexpr const int MAX_LOADSCALE = 100;

constexpr const int MAX_TOLERANCE_TIME = 100;         // hour
constexpr const int MAX_RUNNING_TIME = 60 * 24 * 10;  // min

constexpr const int MAX_BATTERYCAPACITY = 100;
constexpr const int MAX_ISCHARGING_VALUE = 1;
constexpr const int MAX_SCREENOFF_VALUE = 1;
constexpr const int MAX_STORAGEFREE = 100;

/* 1. 本地任务调度属性和启停条件配置 */
typedef struct TaskStartSubCondition_ {
    int isCharging = -1;                   // 是否充电：0--非充电 1--充电， -1--表示未配置，不需判断这个条件
    int batteryCapacity = 50;              // 剩余电量：百分比， -1--表示未配置，不需判断这个条件, 非-1必须大于等于
    int storageFreeRangeLow = -1;          // 剩余存储空间低门限, -1表示未配置，不需判断这个条件
    int storageFreeRangeHig = -1;          // 剩余存储空间高门限, -1表示未配置，不需判断这个条件
    int screenOff = -1;                    // 是否灭屏：0--亮屏 1--灭屏， -1--表示未配置，不需判断这个条件
    int startThermalLevelDay = 1; //白天启动温度，默认1。-1--不需判断温控, 1 [35-37), 2 [37,40), 3 [40, 43), 4[43, 46)
    int startThermalLevelNight = 3; // 夜晚启动温度，默认3。-1--不需判断温控, 1 [35-37), 2 [37,40), 3 [40, 43), 4[43, 46)
    std::string networkType = "";          // 网络条件wifi/蜂窝，any--wifi或蜂窝，空字符串--表示未配置，不需判断这个条件
    std::string checkParamBeforeRun = "";  // 运行前先检查param是否非空且不为0/false/null
} TaskStartSubCondition;

typedef struct TaskStartCondition_ {
    int reScheduleInterval = -1; // 非定时任务，任务完成后再调度的间隔时间，单位min， -1--表示未配置，不需判断这个条件
    std::vector<TaskStartSubCondition> conditionArray; // 条件组合，或的关系， 只要有一个满足就可以执行
} TaskStartCondition;

typedef struct TaskPolicy_ {
    int priorityLevel = -1;                   // 优先级: 0--高 1--中 2--低
    int priorityFactor = 5;                   // 同优先级队列内细分优先级，[1-10]值越低优先级约高；默认值--5，智慧分析--1
    int maxToleranceTime = -1;                // 最大容忍等待时间，单位小时 [1, 100]
    int maxRunningTime = 30;                  // 最大运行时间，单位分钟，超过此时间需停止 [1, 60*24*N]
    int loadLevel = -1;                       // 负载程度: int 0-低 1--中 2--高
    int loadScale = -1;                       // 具体负载值[1, 100]: 1-10, 11-20, 21-30
    std::string criticalRes = "";             // 占用资源类型"CPU|IO|NPU [O]"
    std::vector<std::string> conflictedTask;  // 冲突不能并行执行的后台任务
    bool defaultRun = true;                   // 任务是否默认可调度，默认true
    TaskStartCondition startCondition;        // 任务启动条件
} TaskPolicy;

typedef struct TaskScheduleCfg_ {
    std::string taskId = ""; // 任务名称，需要唯一标识，不能重复，命名规则：$(said):taskNameXx 或 $(bundleName):taskNameyy
    std::string type = ""; // 接入类型
    int saId = -1;
    std::string bundleName = "";
    std::string abilityName = "";
    TaskPolicy taskPolicy; // 任务策略及启动条件
} TaskScheduleCfg;

/* 2. 云推统一调度策略配置 */
constexpr const float DEFAULT_WAITING_PRESSURE = 0.3;
constexpr const float DEFAULT_AGING_FACTOR = 1;
typedef struct AgingFactorMapElement_ {
    float waitingPressure = DEFAULT_WAITING_PRESSURE;  // 取值范围[0-1]
    float agingFactor = DEFAULT_AGING_FACTOR;      // 取值范围[0-1]
} AgingFactorMapElement;  // aging-factor 映射表中的元素

constexpr const int MAX_TEMPERATURE_LEVEL = 7;
constexpr const int MAX_LOAD_THRED = 500;
constexpr const float MAX_WAITING_PRESSURE = 1.0;
constexpr const int MAX_SYS_LOAD_LEVEL = 7;
constexpr const int MAX_NEXT_INTERVAL = 60*12;

constexpr const int DEFAULT_TEMP_LEVEL_THRED_NOCHARING = 1;
constexpr const int DEFAULT_TEMP_LEVEL_THRED_CHARING = 3;
constexpr const int DEFAULT_LOAD_THRED_HIGH = 200;
constexpr const int DEFAULT_LOAD_THRED_MEDIUM = 100;
constexpr const int DEFAULT_LOAD_THRED_LOW = 50;
constexpr const float DEFAULT_WAITING_PRESSURE_THRED = 0.97;
constexpr const int DEFAULT_SYSLOAD_L_LVL = 1;
constexpr const int DEFAULT_SYSLOAD_M_LVL = 2;
constexpr const int DEFAULT_NEXT_INTERVAL = 60; // min
typedef struct UnifySchedulePolicyCfg_ {
    bool scheduleEnable = true; // scheduleEnable总开关可以控制特性开启/关闭，false：不走调度逻辑，启动所有满足启停条件的任务
    int temperatureLevelThredNoCharing = DEFAULT_TEMP_LEVEL_THRED_NOCHARING;  // 非充电温控level [0-7]
    int temperatureLevelThredCharing = DEFAULT_TEMP_LEVEL_THRED_CHARING;    // 充电温控level [0-7]
    int loadThredHigh = DEFAULT_LOAD_THRED_HIGH;                   // 任务总负载门限：高门限，默认策略使用 [0-500]
    int loadThredMedium = DEFAULT_LOAD_THRED_MEDIUM;                 // 任务总负载门限：高门限，默认策略使用 [0-500]
    int loadThredLow = DEFAULT_LOAD_THRED_LOW;                    // 任务总负载门限：低门限，低负载场景使用[0-500]
    float waitingPressureThred = DEFAULT_WAITING_PRESSURE_THRED;           // 等待压力门限，触发立即执行[0-1]
    int sysLoadLowLevel = DEFAULT_SYSLOAD_L_LVL; // 系统处于低负载判断门限，小于此值表示系统处于低负载，[0-7]
    int sysLoadMediumLevel = DEFAULT_SYSLOAD_M_LVL; // 系统处于中负载判断门限，小于表示中负载，大于表示高负载，[0-7]
    int minNextInterval = DEFAULT_NEXT_INTERVAL; // 下次调度时间配置，用于处理返回立刻调度的场景，单位分钟，[1~60*12]
    std::vector<AgingFactorMapElement> agingFactorMap;  // ageingFactor 映射表
} UnifySchedulePolicyCfg;

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
#endif  // TASK_SCH_CFG_H
