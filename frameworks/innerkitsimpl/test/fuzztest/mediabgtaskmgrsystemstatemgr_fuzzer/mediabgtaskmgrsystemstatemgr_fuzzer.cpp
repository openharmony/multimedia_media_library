/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mediabgtaskmgrsystemstatemgr_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "system_state_mgr.h"
#include "media_bgtask_schedule_service.h"
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
#include "task_info_mgr.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int INT_COUNT = 2;
const int32_t INT32_COUNT = 1;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int) * INT_COUNT;

static const int32_t BATTERY_CHANGED = 0;
static const int32_t USER_UNLOCKED = 1;
static const int32_t CHARGING = 2;
static const int32_t DISCHARGING = 3;
static const int32_t SCREEN_OFF = 4;
static const int32_t SCREEN_ON = 5;
static const int32_t THERMAL_LEVEL_CHANGED = 6;
static const int32_t WIFI_CONN_STATE = 7;

SystemStateMgr &systemStateMgr = SystemStateMgr::GetInstance();
FuzzedDataProvider *FDP = nullptr;

static inline std::string FuzzKey(std::string &action)
{
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED) {
        return "soc";
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        return "NetType";
    }
    return "0";
}

static std::string FuzzAction()
{
    int32_t value = FDP->ConsumeIntegralInRange<int32_t>(0, 8);
    std::string action;
    switch (value) {
        case BATTERY_CHANGED:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED;
            break;
        case USER_UNLOCKED:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
            break;
        case CHARGING:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING;
            break;
        case DISCHARGING:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING;
            break;
        case SCREEN_OFF:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
            break;
        case SCREEN_ON:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
            break;
        case THERMAL_LEVEL_CHANGED:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED;
            break;
        case WIFI_CONN_STATE:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE;
            break;
        default:
            action = EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE;
    }
    return action;
}

static void SystemStateMgrFuzzerTest()
{
    systemStateMgr.Init();

    int level = FDP->ConsumeIntegralInRange<int>(0, 8);
    SystemLoadHandler handler;
    handler.OnSystemloadLevel(level);
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();

    std::string action = FuzzAction();
    std::string key = FuzzKey(action);
    int value = FDP->ConsumeIntegralInRange<int>(0, 60);
    EventFwk::Want want;
    want.SetParam(key, value);
    want.SetAction(action);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    systemStateMgr.handleSystemStateChange(eventData);
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();
}

static void Init()
{
    MediaBgtaskScheduleService::GetInstance().Init();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::FDP = &fdp;

    /* Run your code on data */
    OHOS::SystemStateMgrFuzzerTest();
    return 0;
}
