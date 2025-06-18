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

#define MLOG_TAG "MediaBgTask_LocalSystemStateSubscriberTest"

#include "mediabgtaskmgr_system_state_mgr_test.h"

#define private public
#include "system_state_mgr.h"
#undef private

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
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t BATTERY_CAPACITY = 50;

static void HandleSystemStateChangeStub(MediaBgtaskScheduleService *obj) {}

void MediaBgtaskMgrSystemStateMgrTest::SetUpTestCase() {}

void MediaBgtaskMgrSystemStateMgrTest::TearDownTestCase() {}

void MediaBgtaskMgrSystemStateMgrTest::SetUp() {}

void MediaBgtaskMgrSystemStateMgrTest::TearDown()
{
    SystemStateMgr::GetInstance().systemInfo_ = {};
}

/**
 * GetSocFromEvent
 */
HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_CheckSocNeedHandle_test_001, TestSize.Level1)
{
    EventFwk::Want want;
    std::string action;
    int result = SystemStateMgr::GetInstance().CheckSocNeedHandle(want, action);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_CheckSocNeedHandle_test_002, TestSize.Level1)
{
    EventFwk::Want want;
    want.SetParam("soc", 51);
    std::string action;
    int result = SystemStateMgr::GetInstance().CheckSocNeedHandle(want, action);
    EXPECT_FALSE(result);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_CheckSocNeedHandle_test_003, TestSize.Level1)
{
    EventFwk::Want want;
    want.SetParam("soc", 50);
    std::string action;
    int result = SystemStateMgr::GetInstance().CheckSocNeedHandle(want, action);
    EXPECT_TRUE(result);
}

/**
 * handleSystemStateChange
 */
HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    EventFwk::Want want;
    want.SetParam("soc", 60);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.batteryCap = BATTERY_CAPACITY;

    // 1. 测试SOC变化10%
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.batteryCap, 60);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    EventFwk::Want want;
    want.SetParam("soc", 59);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.batteryCap = BATTERY_CAPACITY;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.batteryCap, 59);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_003, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    EventFwk::Want want;
    want.SetParam("soc", 50);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.batteryCap = BATTERY_CAPACITY;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.batteryCap, BATTERY_CAPACITY);
}


HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_004, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    EventFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(1); // 用户ID

    // 2. 测试用户解锁事件，更新解锁状态
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.unlocked = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.unlocked, true);
}

static PowerMgr::BatteryChargeState GetChargingStatusStub(PowerMgr::BatterySrvClient *obj)
{
    return PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE;
}

static bool IsChargingStub(SystemStateMgr *obj)
{
    return true;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_005, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    stub.set(ADDR(PowerMgr::BatterySrvClient, GetChargingStatus), GetChargingStatusStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    // 3. 测试充电状态变化事件，更新充电状态
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.charging = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.charging, true);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_006, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    stub.set(ADDR(SystemStateMgr, IsCharging), IsChargingStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.charging = true;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.charging, true);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_007, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    // 4. 测试屏幕关闭事件，更新屏幕状态
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.screenOff = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_TRUE(inst.systemInfo_.screenOff);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_008, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.screenOff = true;
    inst.handleSystemStateChange(eventData);
    EXPECT_FALSE(inst.systemInfo_.screenOff);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_009, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    want.SetParam("0", 2); // 新的热量级别
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);

    // 5. 测试热量级别变化事件，更新热量级别
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.thermalLevel = 0;
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.thermalLevel, 2);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_010, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(4); // WIFI_STATE_CONNECTED

    //  测试WiFi连接状态变化事件，更新WiFi连接状态
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.wifiConnected = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_TRUE(inst.systemInfo_.wifiConnected);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_011, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(0); // WIFI_STATE_CONNECTED

    //  测试WiFi连接状态变化事件，更新WiFi连接状态
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.wifiConnected = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_FALSE(inst.systemInfo_.wifiConnected);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_012, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    want.SetParam("NetType", 1); // BEARER_CELLULAR
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(3); // NET_CONN_STATE_CONNECTED

    auto &inst = SystemStateMgr::GetInstance();
    // 6. 测试蜂窝网络连接状态变化事件，更新蜂窝连接状态
    inst.systemInfo_.CellularConnect = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_FALSE(inst.systemInfo_.CellularConnect);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_013, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    want.SetParam("NetType", 0);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(3); // NET_CONN_STATE_CONNECTED

    auto &inst = SystemStateMgr::GetInstance();
    // 6. 测试蜂窝网络连接状态变化事件，更新蜂窝连接状态
    inst.systemInfo_.CellularConnect = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_TRUE(inst.systemInfo_.CellularConnect);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_014, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    want.SetParam("NetType", 0);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(0);

    auto &inst = SystemStateMgr::GetInstance();
    // 6. 测试蜂窝网络连接状态变化事件，更新蜂窝连接状态
    inst.systemInfo_.CellularConnect = false;
    inst.handleSystemStateChange(eventData);
    EXPECT_FALSE(inst.systemInfo_.CellularConnect);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemStateChange_test_015, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetCode(0);

    // 7. 测试用户切换事件，更新用户ID
    auto &inst = SystemStateMgr::GetInstance();
    inst.handleSystemStateChange(eventData);
    EXPECT_EQ(inst.systemInfo_.userId, 0);
}

/**
 * handleSystemLoadLevelChange
 */
HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_handleSystemLoadLevelChange_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    // 1. 测试当系统负载等级未发生变化时，函数应忽略处理
    auto &inst = SystemStateMgr::GetInstance();
    inst.systemInfo_.loadLevel = 1;
    inst.handleSystemLoadLevelChange(1);
    EXPECT_EQ(1, inst.systemInfo_.loadLevel);

    // 2. 测试当系统负载等级发生变化时，函数应更新等级并触发重新调度
    inst.handleSystemLoadLevelChange(2);
    EXPECT_EQ(2, inst.systemInfo_.loadLevel);

    SystemLoadHandler handler;
    handler.OnSystemloadLevel(2);
    EXPECT_EQ(2, inst.systemInfo_.loadLevel);
}

/**
 * registerDynamicEvent
 */
static bool SubscribeCommonEventStub(const std::shared_ptr<EventFwk::CommonEventSubscriber> &subscriber)
{
    return true;
}

static bool SubscribeCommonEventStubFailed(const std::shared_ptr<EventFwk::CommonEventSubscriber> &subscriber)
{
    return false;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_registerDynamicEvent_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(EventFwk::CommonEventManager, SubscribeCommonEvent), SubscribeCommonEventStub);
    // 1. success
    auto &inst = SystemStateMgr::GetInstance();
    inst.registerDynamicEvent();
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_registerDynamicEvent_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(EventFwk::CommonEventManager, SubscribeCommonEvent), SubscribeCommonEventStubFailed);
    // 1. failed
    auto &inst = SystemStateMgr::GetInstance();
    inst.registerDynamicEvent();
}

/**
 * QueryBatteryState
 */
static int32_t GetCapacityStub(PowerMgr::BatterySrvClient *obj)
{
    return BATTERY_CAPACITY;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryBatteryState_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(PowerMgr::BatterySrvClient, GetCapacity), GetCapacityStub);
    SystemStateMgr::GetInstance().QueryBatteryState();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.batteryCap, BATTERY_CAPACITY);
}

/**
 * QueryThermalLoadLevel
 */
static bool IsScreenOnStub(PowerMgr::PowerMgrClient *obj, bool needPrintLog = true)
{
    return true;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryThermalLoadLevel_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(PowerMgr::PowerMgrClient, IsScreenOn), IsScreenOnStub);
    SystemStateMgr::GetInstance().QueryThermalLoadLevel();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.screenOff, false);
}

/**
 * UpdateDataFreeSpacePercent
 */
static int statvfsSucc(const char *path, struct statvfs *buf)
{
    buf->f_blocks = 1;
    return 0;
}

static int statvfsFail(const char *path, struct statvfs *buf)
{
    return 1;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_UpdateDataFreeSpacePercent_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(statvfs, statvfsSucc);
    SystemStateMgr::GetInstance().UpdateDataFreeSpacePercent();
    EXPECT_NE(SystemStateMgr::GetInstance().systemInfo_.storageFree, -1);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_UpdateDataFreeSpacePercent_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(statvfs, statvfsFail);
    SystemStateMgr::GetInstance().UpdateDataFreeSpacePercent();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.storageFree, -1);
}

/**
 * QueryNetworkState
 */
static int32_t GetDefaultNetSuccessStub(NetManagerStandard::NetConnClient *obj, NetManagerStandard::NetHandle &net)
{
    return OHOS::NetManagerStandard::NETMANAGER_SUCCESS;
}

static int32_t GetDefaultNetFailedStub(NetManagerStandard::NetConnClient *obj, NetManagerStandard::NetHandle &net)
{
    return -1;
}

static int32_t GetNetCapabilitiesStub(NetManagerStandard::NetConnClient *obj,
    const NetManagerStandard::NetHandle &netHandle, NetManagerStandard::NetAllCapabilities &netAllCap)
{
    netAllCap.bearerTypes_.insert(NetManagerStandard::NetBearType::BEARER_WIFI);
    return NetManagerStandard::NETMANAGER_SUCCESS;
}

static int32_t GetNetCapabilitiesFailedStub(NetManagerStandard::NetConnClient *obj,
    const NetManagerStandard::NetHandle &netHandle, NetManagerStandard::NetAllCapabilities &netAllCap)
{
    return -1;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryNetworkState_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(NetManagerStandard::NetConnClient, GetDefaultNet), GetDefaultNetFailedStub);
    SystemStateMgr::GetInstance().QueryNetworkState();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.wifiConnected, false);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryNetworkState_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(NetManagerStandard::NetConnClient, GetDefaultNet), GetDefaultNetSuccessStub);
    stub.set(ADDR(NetManagerStandard::NetConnClient, GetNetCapabilities), GetNetCapabilitiesFailedStub);
    SystemStateMgr::GetInstance().QueryNetworkState();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.wifiConnected, false);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryNetworkState_test_003, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(NetManagerStandard::NetConnClient, GetDefaultNet), GetDefaultNetSuccessStub);
    stub.set(ADDR(NetManagerStandard::NetConnClient, GetNetCapabilities), GetNetCapabilitiesStub);
    SystemStateMgr::GetInstance().QueryNetworkState();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.wifiConnected, true);
}

/**
 * QueryForegroundUser
 */
static ErrCode GetForegroundOsAccountLocalIdStub(int32_t &localId)
{
    localId = 1;
    return ERR_OK;
}

static ErrCode GetForegroundOsAccountLocalIdFailedStub(int32_t &localId)
{
    return -1;
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryForegroundUser_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set((ErrCode(*)(int32_t &))AccountSA::OsAccountManager::GetForegroundOsAccountLocalId,
             GetForegroundOsAccountLocalIdFailedStub);
    SystemStateMgr::GetInstance().QueryForegroundUser();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.userId, 0);
}

HWTEST_F(MediaBgtaskMgrSystemStateMgrTest, media_bgtask_mgr_QueryForegroundUser_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set((ErrCode(*)(int32_t &))AccountSA::OsAccountManager::GetForegroundOsAccountLocalId,
             GetForegroundOsAccountLocalIdStub);
    SystemStateMgr::GetInstance().QueryForegroundUser();
    EXPECT_EQ(SystemStateMgr::GetInstance().systemInfo_.userId, 1);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

