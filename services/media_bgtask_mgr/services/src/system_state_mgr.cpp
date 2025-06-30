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

#define MLOG_TAG "MediaBgTask_LocalSystemStateSubscriber"

#include "system_state_mgr.h"

#include <sys/statvfs.h>
#include "ffrt.h"
#include "want.h"
#include "net_conn_client.h"
#include "battery_srv_client.h"
#include "os_account_manager.h"
#include "power_mgr_client.h"
#include "res_sched_client.h"
#include "thermal_mgr_client.h"

#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service.h"
#include "task_info_mgr.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

LocalSystemStateSubscriber::LocalSystemStateSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{}

void LocalSystemStateSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    SystemStateMgr::GetInstance().handleSystemStateChange(eventData);
}

bool SystemStateMgr::CheckSocNeedHandle(const AAFwk::Want &want, std::string &action)
{
    constexpr char commonEventKey[] = "soc";
    constexpr int invalidValue = -1;
    constexpr int BATTERY_LEVEL_CHECK = 10;
    int capacity = want.GetIntParam(commonEventKey, invalidValue);
    if (capacity == systemInfo_.batteryCap) {
        return false;
    }
    systemInfo_.batteryCap = capacity;
    if (capacity % BATTERY_LEVEL_CHECK != 0) {
        MEDIA_INFO_LOG("SOC not change 10 level, ignore");
        return false;
    }
    return true;
}

bool SystemStateMgr::CheckCellularConnectChange(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want &want = eventData.GetWant();
    std::string action = want.GetAction();
    int netType = want.GetIntParam("NetType", -1);
    bool isNetConnected = eventData.GetCode() == 3; /* NET_CONN_STATE_CONNECTED */
    MEDIA_INFO_LOG("receive %{public}s, netType: %{public}d, isConnected: %{public}d.",
        action.c_str(), netType, static_cast<int32_t>(isNetConnected));
    if (netType != 0) { /* BEARER_CELLULAR */
        MEDIA_INFO_LOG("Not cellular, ignore.");
        return false;
    } else if (isNetConnected == systemInfo_.CellularConnect) {
        MEDIA_INFO_LOG("cellular state NOT change, ignore.");
        return false;
    }
    systemInfo_.CellularConnect = isNetConnected;
    return true;
}

bool SystemStateMgr::IsCharging()
{
    auto chargingStatus = PowerMgr::BatterySrvClient::GetInstance().GetChargingStatus();
    bool isCharging = (chargingStatus == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE);
    bool isBatteryFull = (chargingStatus == PowerMgr::BatteryChargeState::CHARGE_STATE_FULL);
    bool isPlugged =
        PowerMgr::BatterySrvClient::GetInstance().GetPluggedType() != PowerMgr::BatteryPluggedType::PLUGGED_TYPE_NONE;
    bool finalCharging = (isCharging || (isBatteryFull && isPlugged));
    MEDIA_INFO_LOG("charging: %{public}d, IsBatteryFull: %{public}d, plugged: %{public}d, FinalCharging: %{public}d.",
        isCharging, isBatteryFull, isPlugged, finalCharging);
    return finalCharging;
}

void SystemStateMgr::handleSystemStateChange(const EventFwk::CommonEventData &eventData)
{
    LOCK_SCHEDULE_AND_CHANGE();
    const AAFwk::Want &want = eventData.GetWant();
    std::string action = want.GetAction();

    SystemInfo &sysInfo = systemInfo_;
    // 变化最频繁的事件放最上面
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED) {
        if (!CheckSocNeedHandle(want, action)) {
            return;
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        TaskInfoMgr::GetInstance().AddTaskForNewUserIfNeed(eventData.GetCode());
        sysInfo.allUserIds.insert(eventData.GetCode());
        MEDIA_INFO_LOG("receive %{public}s, userId = %{public}d", action.c_str(), eventData.GetCode());
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        TaskInfoMgr::GetInstance().RemoveTaskForUser(eventData.GetCode());
        sysInfo.allUserIds.erase(eventData.GetCode());
        TaskInfoMgr::GetInstance().SaveTaskState(false);
        MEDIA_INFO_LOG("receive %{public}s, userId = %{public}d", action.c_str(), eventData.GetCode());
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) {
        MEDIA_INFO_LOG("receive %{public}s", action.c_str());
        if (IsCharging() == sysInfo.charging) {
            MEDIA_INFO_LOG("final charging status not change, ignore");
            return;
        }
        sysInfo.charging = !sysInfo.charging;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF ||
               action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        sysInfo.screenOff = (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
        MEDIA_INFO_LOG("receive %{public}s", action.c_str());
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        int level = want.GetIntParam("0", -1);
        MEDIA_INFO_LOG("receive %{public}s, level = %{public}d, oldLevel = %{public}d",
            action.c_str(), level, sysInfo.thermalLevel);
        sysInfo.thermalLevel = level;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE) {
        bool connected = (eventData.GetCode() == 4); /* WIFI_STATE_CONNECTED */
        MEDIA_INFO_LOG("receive %{public}s, state = %{public}d, oldState = %{public}d",
            action.c_str(), connected, sysInfo.wifiConnected);
        if (connected == sysInfo.wifiConnected) {
            MEDIA_INFO_LOG("wifi connect state not changed, ignore");
            return;
        }
        sysInfo.wifiConnected = connected;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        if (!CheckCellularConnectChange(eventData)) {
            return;
        }
    } else {
        MEDIA_WARN_LOG("Received other event action:%{public}s.", action.c_str());
        return;
    }
    MediaBgtaskScheduleService::GetInstance().HandleSystemStateChange();
}

void SystemStateMgr::handleSystemLoadLevelChange(int level)
{
    LOCK_SCHEDULE_AND_CHANGE();
    MEDIA_INFO_LOG("receive OnSystemloadLevel %{public}d", level);
    if (level == systemInfo_.loadLevel) {
        MEDIA_INFO_LOG("SystemloadLevel not change, ignore");
        return;
    }
    systemInfo_.loadLevel = level;
    MediaBgtaskScheduleService::GetInstance().HandleSystemStateChange();
}

void SystemLoadHandler::OnSystemloadLevel(int level)
{
    SystemStateMgr::GetInstance().handleSystemLoadLevelChange(level);
}

void SystemStateMgr::registerDynamicEvent()
{
    MEDIA_INFO_LOG("Subscribe event.");

    const std::vector<std::string> events = {
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED,  // "usual.event.SCREEN_UNLOCKED"
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED,
        EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED,
        EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
        EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
        EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
        EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE,
        EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE,
    };

    EventFwk::MatchingSkills matchingSkills;
    for (auto event : events) {
        matchingSkills.AddEvent(event);
    }

    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    MEDIA_INFO_LOG("SetThreadMode CommonEventSubscribeInfo::COMMON");
    static std::shared_ptr<LocalSystemStateSubscriber> subscriber =
        std::make_shared<LocalSystemStateSubscriber>(subscribeInfo);
    bool result = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
    if (result) {
        MEDIA_INFO_LOG("Subscribe event success");
    } else {
        MEDIA_ERR_LOG("Subscribe event fail");
    }

    sptr<SystemLoadHandler> systemLoadHandler = new (std::nothrow) SystemLoadHandler();
    ResourceSchedule::ResSchedClient::GetInstance().RegisterSystemloadNotifier(systemLoadHandler);
}

void SystemStateMgr::QueryBatteryState()
{
    // dep battery_manager:batterysrv_client
    // GET BATTERY CAP
    int32_t batteryCap = PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
    MEDIA_INFO_LOG("Get batteryCap %{public}d", batteryCap);
    batteryCap = std::max(batteryCap, 0);
    constexpr int32_t batteryMaxLimitVal = 100;
    batteryCap = std::min(batteryCap, batteryMaxLimitVal);
    systemInfo_.batteryCap = batteryCap;

    // GET CHARING STATE
    systemInfo_.charging = IsCharging();
}

void SystemStateMgr::QueryThermalLoadLevel()
{
    bool screenOn = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    systemInfo_.screenOff = !screenOn;

    int32_t thermalLevel = static_cast<int32_t>(PowerMgr::ThermalMgrClient::GetInstance().GetThermalLevel());
    systemInfo_.thermalLevel = thermalLevel;

    int32_t loadLevel = ResourceSchedule::ResSchedClient::GetInstance().GetSystemloadLevel();
    systemInfo_.loadLevel = loadLevel;

    MEDIA_INFO_LOG("screenOff: %{public}d, thermalLevel: %{public}d, loadLevel: %{public}d.",
        systemInfo_.screenOff, systemInfo_.thermalLevel, systemInfo_.loadLevel);
}

void SystemStateMgr::UpdateDataFreeSpacePercent()
{
    const std::string DATA_ROOT_PATH = "/data";
    struct statvfs diskInfo;
    int ret = statvfs(DATA_ROOT_PATH.c_str(), &diskInfo);
    if (ret != 0 || diskInfo.f_blocks == 0) {
        MEDIA_ERR_LOG("get freeSize failed, errno: %{public}d.", errno);
        systemInfo_.storageFree = -1;
        return;
    }
    if (diskInfo.f_blocks == 0) {
        MEDIA_ERR_LOG("get freeSize failed, f_blocks: %{public}s.", std::to_string(diskInfo.f_blocks).c_str());
        systemInfo_.storageFree = -1;
        return;
    }
    auto ratio = diskInfo.f_bfree * 100 / diskInfo.f_blocks;
    MEDIA_INFO_LOG("/data free ratio: %{public}s", std::to_string(ratio).c_str());
    systemInfo_.storageFree = ratio;
}

void SystemStateMgr::QueryNetworkState()
{
    systemInfo_.wifiConnected = false;
    systemInfo_.CellularConnect = false;
    NetManagerStandard::NetHandle netHandle;
    int ret = NetManagerStandard::NetConnClient::GetInstance().GetDefaultNet(netHandle);
    if (ret != OHOS::NetManagerStandard::NETMANAGER_SUCCESS) {
        MEDIA_ERR_LOG("GetDefaultNet error, ret =  %{public}d", ret);
        return;
    }

    NetManagerStandard::NetAllCapabilities netAllCap;
    ret = NetManagerStandard::NetConnClient::GetInstance().GetNetCapabilities(netHandle, netAllCap);
    if (ret != NetManagerStandard::NETMANAGER_SUCCESS) {
        MEDIA_ERR_LOG("GetNetCapabilities error, ret =  %{public}d", ret);
        return;
    }

    bool wifiConnected = netAllCap.bearerTypes_.count(NetManagerStandard::NetBearType::BEARER_WIFI) > 0;
    // ethernet当做wifi处理
    bool etherConnected = netAllCap.bearerTypes_.count(NetManagerStandard::NetBearType::BEARER_ETHERNET) > 0;
    systemInfo_.wifiConnected = (wifiConnected || etherConnected);

    bool cellConnected = netAllCap.bearerTypes_.count(NetManagerStandard::NetBearType::BEARER_CELLULAR) > 0;
    systemInfo_.CellularConnect = cellConnected;

    MEDIA_INFO_LOG("wifiConnected: %{public}d, etherConnected: %{public}d, cellConnected: %{public}d.",
        wifiConnected, etherConnected, systemInfo_.CellularConnect);
}

void SystemStateMgr::QueryForegroundUser()
{
    int32_t foregroundUserId;
    ErrCode errCode = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundUserId);
    if (errCode != ERR_OK) {
        MEDIA_ERR_LOG("GetForegroundOsAccountLocalId error, ret %{public}d", errCode);
        return;
    }
    MEDIA_INFO_LOG("GetForegroundOsAccountLocalId get userId %{public}d", foregroundUserId);
    systemInfo_.userId = foregroundUserId;
}

void SystemStateMgr::QueryAllUser()
{
    std::vector<AccountSA::OsAccountInfo> osAccounts;
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    if (errCode != ERR_OK || osAccounts.empty()) {
        MEDIA_ERR_LOG("QueryAllCreatedOsAccounts error, ret %{public}d", errCode);
        return;
    }
    MEDIA_INFO_LOG("QueryAllCreatedOsAccounts get userId cnt %{public}zu", osAccounts.size());
    for (const AccountSA::OsAccountInfo &accountInfo : osAccounts) {
        systemInfo_.allUserIds.insert(accountInfo.GetLocalId());
    }
}

void SystemStateMgr::InitSystemState()
{
    QueryBatteryState();
    QueryThermalLoadLevel();
    QueryNetworkState();
    QueryForegroundUser();
    QueryAllUser();
}

void SystemStateMgr::Init()
{
    InitSystemState();
    registerDynamicEvent();
}

SystemInfo &SystemStateMgr::GetSystemState()
{
    systemInfo_.now = time(0);
    return systemInfo_;
}

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
