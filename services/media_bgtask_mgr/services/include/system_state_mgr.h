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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SYSTEM_STATE_MGR_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SYSTEM_STATE_MGR_H

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "res_sched_client.h"

#include <sstream>
#include <string>

namespace OHOS {
namespace MediaBgtaskSchedule {

class LocalSystemStateSubscriber : public EventFwk::CommonEventSubscriber {
public:
    explicit LocalSystemStateSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~LocalSystemStateSubscriber() = default;

    virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
};

struct SystemInfo {
    bool needCompute;   // 如果有状态需要计算置为true。有些变化比如电量变化，可能不需要置为true
    bool unlocked;      // 是否解锁
    bool charging;      // 是否充电
    bool screenOff;      // 是否息屏
    int loadLevel;      // 系统负载档位， 0-7
    int thermalLevel;   // 系统温度级别: 温度和档位是否匹配的
    // 其他条件
    //  电池电量
    int batteryCap;
    bool wifiConnected;
    bool CellularConnect;
    // bool blueTooth;
    // 剩余空间百分比
    int storageFree;
    time_t now; // 当前系统时间,调试用！！！！
    int userId;

    std::string ToString() const
    {
        std::stringstream ss;
        ss << "{"
           << "needCompute: " << needCompute << ", unlocked: " << unlocked << ", charging: " << charging
           << ", screenOff: " << screenOff << ", loadLevel: " << loadLevel << ", thermalLevel: " << thermalLevel
           << ", batteryCap: " << batteryCap << ", wifiConnected: " << wifiConnected
           << ", CellularConnect: " << CellularConnect << ", storageFree: " << storageFree
           << ", now: " << now << ", userId: " << userId
           << "}";
        return ss.str();
    }
};

enum class SystemEventType {
    CHARGING,
    DISCHARGING,
    SCREEN_OFF,
    SCREEN_ON,
    BATTERY_CHANGED,
    THERMAL_LEVEL_CHANGED,
    TIME_TICK
};

class SystemStateMgr {
public:
    static SystemStateMgr &GetInstance()
    {
        static SystemStateMgr mInst;
        return mInst;
    }

    void Init();
    // 每次重新调度前刷新系统空间剩余情况
    void UpdateDataFreeSpacePercent();
    void handleSystemStateChange(const EventFwk::CommonEventData &eventData);
    // 负载变化没有CES，需要单独处理
    void handleSystemLoadLevelChange(int level);

    SystemInfo &GetSystemState();

private:
    SystemInfo systemInfo_;
    // SA启动后注册动态广播
    void registerDynamicEvent();

    // CES不会发送当前的状态，需要首次主动获取各种系统状态
    void InitSystemState();
    void QueryBatteryState();
    void QueryThermalLoadLevel();
    void QueryNetworkState();
    void QueryForegroundUser();
    bool CheckCellularConnectChange(const EventFwk::CommonEventData &eventData);
    bool CheckSocNeedHandle(const AAFwk::Want &want, std::string &action);
    bool IsCharging();
};

class SystemLoadHandler : public ResourceSchedule::ResSchedSystemloadNotifierClient {
public:
    SystemLoadHandler() = default;
    ~SystemLoadHandler() = default;

    void OnSystemloadLevel(int32_t level) override;
};

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_SYSTEM_STATE_MGR_H
