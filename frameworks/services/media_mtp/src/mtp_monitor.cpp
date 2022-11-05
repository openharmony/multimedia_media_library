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

#include "mtp_monitor.h"
#include <thread>
#include "media_log.h"
using namespace std;
namespace OHOS {
namespace Media {
constexpr int32_t SLEEP_TIME = 10;
MtpMonitor::MtpMonitor(void)
{
    Init();
}

void MtpMonitor::Init()
{
    interruptFlag = false;
}

void MtpMonitor::Start()
{
    std::thread(&MtpMonitor::Run, this).detach();
}

void MtpMonitor::Stop()
{
    interruptFlag = true;
}

void MtpMonitor::Run()
{
    while (!interruptFlag) {
        if (operationPtr_ == nullptr) {
            operationPtr_ = make_shared<MtpOperation>();
        }
        operationPtr_->Execute();
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
}
} // namespace Media
} // namespace OHOS
