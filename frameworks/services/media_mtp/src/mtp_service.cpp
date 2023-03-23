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
#include <thread>

#include "accesstoken_kit.h"
#include "media_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace std;
namespace OHOS {
namespace Media {
std::shared_ptr<MtpService> MtpService::mtpServiceInstance_{nullptr};
std::mutex MtpService::instanceLock_;

static void SetAccessTokenPermission(const std::string &processName,
    const std::vector<std::string> &permission, uint64_t &tokenId)
{
    auto perms = std::make_unique<const char *[]>(permission.size());
    for (size_t i = 0; i < permission.size(); i++) {
        perms[i] = permission[i].c_str();
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permission.size(),
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms.get(),
        .acls = nullptr,
        .processName = processName.c_str(),
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    if (tokenId == 0) {
        MEDIA_ERR_LOG("Get Acess Token Id Failed");
        return;
    }
    int ret = SetSelfTokenID(tokenId);
    if (ret != 0) {
        MEDIA_ERR_LOG("Set Acess Token Id Failed");
        return;
    }
    ret = Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    if (ret < 0) {
        MEDIA_ERR_LOG("Reload Native Token Info Failed");
        return;
    }
}

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
    monitorPtr_ = make_shared<MtpMonitor>();

    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.MEDIA_LOCATION");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    SetAccessTokenPermission("MTPServerService", perms, tokenId);
}

void MtpService::StartService()
{
    if (!isMonitorRun_) {
        monitorPtr_->Start();
        MtpFileObserver::GetInstance().StartFileInotify();
        isMonitorRun_ = true;
    }
}

void MtpService::StopService()
{
    monitorPtr_->Stop();
    MtpFileObserver::GetInstance().StopFileInotify();
}
} // namespace Media
} // namespace OHOS