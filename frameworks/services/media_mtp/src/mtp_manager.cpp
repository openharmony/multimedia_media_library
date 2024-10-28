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
#include "mtp_subscriber.h"
#include "usb_srv_support.h"
#include "mtp_service.h"
#include "usb_srv_client.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "access_token.h"

#include <thread>

namespace OHOS {
namespace Media {
namespace {
    std::shared_ptr<MtpService> mtpServicePtr = nullptr;
} // namespace

MtpManager &MtpManager::GetInstance()
{
    static MtpManager instance;
    return instance;
}

std::shared_ptr<MtpService> GetMtpServiceInstance()
{
    if (mtpServicePtr == nullptr) {
        mtpServicePtr = std::make_shared<MtpService>();
        if (mtpServicePtr != nullptr) {
            mtpServicePtr->Init();
        }
    }
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
        if (funcs & USB::UsbSrvSupport::Function::FUNCTION_MTP) {
            MtpManager::GetInstance().StartMtpService(MtpMode::MTP_MODE);
        }
        if (funcs & USB::UsbSrvSupport::Function::FUNCTION_PTP) {
            MtpManager::GetInstance().StartMtpService(MtpMode::PTP_MODE);
        }
        MEDIA_INFO_LOG("MtpManager Init success end");
    }).detach();
}

void MtpManager::StartMtpService(const MtpMode mode)
{
    MEDIA_INFO_LOG("MtpManager::StartMtpService is called");
    auto service = GetMtpServiceInstance();
    CHECK_AND_RETURN_LOG(service != nullptr, "MtpManager::GetInstance failed");
    if (mtpMode_ != MtpMode::NONE_MODE) {
        service->StopService();
    }
    mtpMode_ = mode;
    service->StartService();
}

void MtpManager::StopMtpService()
{
    MEDIA_INFO_LOG("MtpManager::StopMtpService is called");
    auto service = GetMtpServiceInstance();
    CHECK_AND_RETURN_LOG(service != nullptr, "MtpManager::GetInstance failed");
    mtpMode_ = MtpMode::NONE_MODE;
    service->StopService();
    if (mtpServicePtr != nullptr) {
        mtpServicePtr.reset();
    }
}

} // namespace Media
} // namespace OHOS
