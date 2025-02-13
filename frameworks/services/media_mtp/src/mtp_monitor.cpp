/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MtpMonitor"
#include "mtp_monitor.h"
#include <thread>
#include "media_log.h"
#include "mtp_file_observer.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_store_observer.h"
using namespace std;
namespace OHOS {
namespace Media {
constexpr int32_t SLEEP_TIME = 1;
constexpr uint32_t MAX_WAIT_TIMES = 100;
constexpr int32_t IPC_SERVER_RELEASED = -204;
constexpr int32_t IPC_OBJECT_INVALID = -4;
constexpr int32_t MAX_ERROR_TIMES = 5;
constexpr int32_t ERROR_SLEEP_TIME = 10;

void MtpMonitor::Start()
{
    MEDIA_INFO_LOG("MtpMonitor::Start threadRunning_:%{public}d", threadRunning_.load());
    errorLimit_.store(MAX_ERROR_TIMES);
    if (!threadRunning_.load()) {
        threadRunning_.store(true);
        std::thread([this] { this->Run(); }).detach();
    }
}

void MtpMonitor::Stop()
{
    errorLimit_.store(0);
    // make sure stop done after other operations.
    MEDIA_INFO_LOG("MtpMonitor::Stop start");
    uint32_t waitTimes = 0;
    while (threadRunning_.load() && waitTimes < MAX_WAIT_TIMES) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
        waitTimes++;
    }
    if (operationPtr_ != nullptr) {
        operationPtr_->Stop();
    }
    MEDIA_INFO_LOG("MtpMonitor::Stop end threadRunning_:%{public}d", threadRunning_.load());
}

void MtpMonitor::Run()
{
    int32_t errorCount = 0;
    string name("MtpMonitor::Run");
    pthread_setname_np(pthread_self(), name.c_str());
    while (errorCount < errorLimit_.load()) {
        if (errorCount > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(ERROR_SLEEP_TIME));
        }
        if (operationPtr_ == nullptr) {
            operationPtr_ = make_shared<MtpOperation>();
        }
        if (operationPtr_ != nullptr) {
            auto errorCode = operationPtr_->Execute();
            if (errorCode == 0) {
                errorCount = 0;
            } else {
                errorCount++;
                MEDIA_ERR_LOG("MtpMonitor::Run errorCode:%{public}d", errorCode);
            }
            if (errorCode == IPC_SERVER_RELEASED || errorCode == IPC_OBJECT_INVALID) {
                MEDIA_ERR_LOG("MtpMonitor::Run break");
                break;
            }
        }
    }
    {
        MtpFileObserver::GetInstance().StopFileInotify();
        MtpStoreObserver::StopObserver();
        MtpMedialibraryManager::GetInstance()->Clear();
    }
    if (operationPtr_ != nullptr) {
        operationPtr_.reset();
    }
    threadRunning_.store(false);
    MEDIA_INFO_LOG("MtpMonitor::Run end errorCount:%{public}d", errorCount);
}
} // namespace Media
} // namespace OHOS
