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
#define MLOG_TAG "MtpService"
#include "mtp_service.h"
#include "media_log.h"
#include "mtp_file_observer.h"
#include <thread>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace std;
namespace OHOS {
namespace Media {
std::shared_ptr<MtpService> MtpService::mtpServiceInstance_{nullptr};
std::mutex MtpService::instanceLock_;

MtpService::MtpService(void) : monitorPtr_(nullptr), isMonitorRun_(false)
{
}

std::shared_ptr<MtpService> MtpService::GetInstance()
{
    if (mtpServiceInstance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceLock_);
        mtpServiceInstance_ = std::shared_ptr<MtpService>(new MtpService());
        if (mtpServiceInstance_ != nullptr) {
            mtpServiceInstance_->Init();
        }
    }

    return mtpServiceInstance_;
}

void MtpService::Init()
{
    if (monitorPtr_ == nullptr) {
        monitorPtr_ = make_shared<MtpMonitor>();
    }
}

void MtpService::StartService()
{
    CHECK_AND_RETURN_LOG(monitorPtr_ != nullptr, "MtpService::StartService monitor is nullptr");
    if (!isMonitorRun_) {
        monitorPtr_->Start();
        MtpFileObserver::GetInstance().StartFileInotify();
        isMonitorRun_ = true;
    }
}

void MtpService::StopService()
{
    if (!isMonitorRun_ || monitorPtr_ == nullptr) {
        MEDIA_INFO_LOG("MtpService::StopService monitor is not running");
        return;
    }
    monitorPtr_->Stop();
    MtpFileObserver::GetInstance().StopFileInotify();
    isMonitorRun_ = false;
    mtpServiceInstance_.reset();
    monitorPtr_.reset();
}
} // namespace Media
} // namespace OHOS