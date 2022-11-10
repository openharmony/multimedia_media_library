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
#include "mtp_service.h"
#include "media_log.h"
#include "mtp_file_observer.h"
using namespace std;
namespace OHOS {
namespace Media {
std::shared_ptr<MtpServcie> MtpServcie::mtpServcieInstance_{nullptr};
std::mutex MtpServcie::instanceLock_;

MtpServcie::MtpServcie(void) : monitorPtr_(nullptr), isMonitorRun_(isMonitorRun_)
{
}

std::shared_ptr<MtpServcie> MtpServcie::GetInstance()
{
    if (mtpServcieInstance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceLock_);
        mtpServcieInstance_ = std::shared_ptr<MtpServcie>(new MtpServcie());
        if (mtpServcieInstance_ != nullptr) {
            mtpServcieInstance_->Init();
        }
    }

    return mtpServcieInstance_;
}

void MtpServcie::Init()
{
    monitorPtr_ = make_shared<MtpMonitor>();
}

void MtpServcie::StartService()
{
    if (!isMonitorRun_) {
        monitorPtr_->Start();
        MtpFileObserver::GetInstance().StartFileInotify();
        isMonitorRun_ = true;
    }
}

void MtpServcie::StopService()
{
    monitorPtr_->Stop();
    MtpFileObserver::GetInstance().StopFileInotify();
}
} // namespace Media
} // namespace OHOS