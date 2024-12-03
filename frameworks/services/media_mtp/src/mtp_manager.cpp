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
#define MLOG_TAG "MtpManager"

#include "mtp_manager.h"
#include "media_log.h"
#include "mtp_file_observer.h"
#include "mtp_service.h"
#include "mtp_store_observer.h"
#include "mtp_subscriber.h"
#include "os_account_manager.h"
#include "usb_srv_client.h"
#include "usb_srv_support.h"
#include "mtp_medialibrary_manager.h"

#include <thread>

namespace OHOS {
namespace Media {
namespace {
    static std::mutex mutex_;
    std::shared_ptr<MtpService> mtpServicePtr = nullptr;
    std::atomic<bool> isMtpServiceRunning = false;
} // namespace

MtpManager &MtpManager::GetInstance()
{
    static MtpManager instance;
    return instance;
}

std::shared_ptr<MtpService> GetMtpService()
{
    static std::once_flag oc;
    std::call_once(oc, []() {
        mtpServicePtr = std::make_shared<MtpService>();
    });
    return mtpServicePtr;
}

void MtpManager::Init()
{
    std::thread([]() {
        MEDIA_INFO_LOG("MtpManager Init");
        bool result = MtpSubscriber::Subscribe();
        MEDIA_INFO_LOG("MtpManager Subscribe result = %{public}d", result);

        int32_t funcs = 0;
        int ret = OHOS::USB::UsbSrvClient::GetInstance().GetCurrentFunctions(funcs);
        MEDIA_INFO_LOG("MtpManager Init GetCurrentFunctions = %{public}d ret = %{public}d", funcs, ret);
        CHECK_AND_RETURN_LOG(ret == 0, "GetCurrentFunctions failed");
        uint32_t unsignedfuncs = static_cast<uint32_t>(funcs);
        if (unsignedfuncs & USB::UsbSrvSupport::Function::FUNCTION_MTP) {
            MtpManager::GetInstance().StartMtpService(MtpMode::MTP_MODE);
            return;
        }
        if (unsignedfuncs & USB::UsbSrvSupport::Function::FUNCTION_PTP) {
            MtpManager::GetInstance().StartMtpService(MtpMode::PTP_MODE);
            return;
        }
        if (unsignedfuncs & USB::UsbSrvSupport::Function::FUNCTION_HDC) {
            MtpManager::GetInstance().StopMtpService();
        }
        MEDIA_INFO_LOG("MtpManager Init success end");
    }).detach();
}

void MtpManager::StartMtpService(const MtpMode mode)
{
    MEDIA_INFO_LOG("MtpManager::StartMtpService is called");
    bool isForeground = true;
    OHOS::ErrCode errCode = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(isForeground);
    // not current user foreground, return
    if (errCode == ERR_OK && !isForeground) {
        MEDIA_ERR_LOG("StartMtpService errCode = %{public}d isForeground %{public}d", errCode, isForeground);
        return;
    }
    {
        std::unique_lock lock(mutex_);
        if (isMtpServiceRunning.load()) {
            MEDIA_INFO_LOG("MtpManager::StartMtpService -- service is already running");
            return;
        }
        auto service = GetMtpService();
        CHECK_AND_RETURN_LOG(service != nullptr, "MtpManager mtpServicePtr is nullptr");
        if (mtpMode_ != MtpMode::NONE_MODE) {
            service->StopService();
        }
        mtpMode_ = mode;
        if (mode == MtpMode::MTP_MODE) {
            MtpFileObserver::GetInstance().StartFileInotify();
            MtpStoreObserver::StartObserver();
        }
        service->StartService();
        isMtpServiceRunning = true;
    }
}

void MtpManager::StopMtpService()
{
    MEDIA_INFO_LOG("MtpManager::StopMtpService is called");
    {
        std::unique_lock lock(mutex_);
        if (!isMtpServiceRunning.load()) {
            MEDIA_INFO_LOG("MtpManager::StopMtpService -- service is already stopped");
            return;
        }
        auto service = GetMtpService();
        CHECK_AND_RETURN_LOG(service != nullptr, "MtpManager mtpServicePtr is nullptr");
        if (mtpMode_ == MtpMode::MTP_MODE) {
            MtpFileObserver::GetInstance().StopFileInotify();
            MtpStoreObserver::StopObserver();
        } else if (mtpMode_ == MtpMode::PTP_MODE) {
            MtpMedialibraryManager::GetInstance()->Clear();
        }
        mtpMode_ = MtpMode::NONE_MODE;
        service->StopService();
        isMtpServiceRunning = false;
    }
}

} // namespace Media
} // namespace OHOS
