/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_CLOUD_MANAGER_H
#define OHOS_MEDIA_DFX_CLOUD_MANAGER_H

#include <mutex>
#include <timer.h>

namespace OHOS {
namespace Media {

enum class SyncState : uint16_t {
    INIT_STATE = 0,
    START_STATE,
    END_STATE,
};

enum class CloudSyncStatus : int32_t {
    BEGIN = 0,
    FIRST_FIVE_HUNDRED,
    INCREMENT_DOWNLOAD,
    TOTAL_DOWNLOAD,
    TOTAL_DOWNLOAD_FINISH,
    SYNC_SWITCHED_OFF,
};

class CloudSyncDfxManager;

class InitState {
public:
    static bool StateSwitch(CloudSyncDfxManager& manager);
    static void Process(CloudSyncDfxManager& manager);
};

class StartState {
public:
    static bool StateSwitch(CloudSyncDfxManager& manager);
    static void Process(CloudSyncDfxManager& manager);
};

class EndState {
public:
    static bool StateSwitch(CloudSyncDfxManager& manager);
    static void Process(CloudSyncDfxManager& manager);
};

struct StateProcessFunc {
    bool (*StateSwitch)(CloudSyncDfxManager&);
    void (*Process)(CloudSyncDfxManager& manager);
};

class CloudSyncDfxManager {
public:
    ~CloudSyncDfxManager();
    static CloudSyncDfxManager& GetInstance();
    void ShutDownTimer();
    void RunDfx();

    friend class InitState;
    friend class StartState;
    friend class EndState;
private:
    void InitSyncState();
    CloudSyncDfxManager();
    void StartTimer();
    void SetStartTime();
    void ResetStartTime();
    std::mutex timerMutex_;
    std::mutex endStateMutex_;
    Utils::Timer timer_{ "CloudSyncTimer" };
    uint32_t timerId_{ 0 };
    SyncState syncState_{ SyncState::INIT_STATE };
    std::vector<StateProcessFunc> stateProcessFuncs_ {
        {
            InitState::StateSwitch,
            InitState::Process,
        },
        {
            StartState::StateSwitch,
            StartState::Process,
        },
        {
            EndState::StateSwitch,
            EndState::Process,
        }
    };
};

} // Media
} // OHOS

#endif // OHOS_MEDIA_DFX_CLOUD_MANAGER_H