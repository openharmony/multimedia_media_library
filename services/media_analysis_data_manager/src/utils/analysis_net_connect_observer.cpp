/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "AnalysisNetObserver"

#include "analysis_net_connect_observer.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_related_system_state_manager.h"
#include "lcd_download_operation.h"

using namespace OHOS::NetManagerStandard;

namespace OHOS::Media {

void AnalysisNetConnectObserver::SetNetConnStatus(const NetBearer status)
{
    netStatus_ = status;
}

void AnalysisNetConnectObserver::SetRequiredNetBearerBitmap(uint32_t netBearerBitmap)
{
    requiredNetBearerBitmap_ = netBearerBitmap;
}

uint32_t AnalysisNetConnectObserver::GetCurrentNetBearerBitmap() const
{
    switch (netStatus_) {
        case NetBearer::BEARER_ETHERNET:
            return static_cast<uint32_t>(NetBearer::BEARER_ETHERNET);
        case NetBearer::BEARER_WIFI:
            return static_cast<uint32_t>(NetBearer::BEARER_WIFI);
        case NetBearer::BEARER_CELLULAR:
            return static_cast<uint32_t>(NetBearer::BEARER_CELLULAR);
        default:
            return 0;
    }
}

bool AnalysisNetConnectObserver::IfNeedCanceled() const
{
    uint32_t currentNetBearerBitmap = GetCurrentNetBearerBitmap();
    if (currentNetBearerBitmap == 0) {
        return true;
    }
    if (requiredNetBearerBitmap_ == static_cast<uint32_t>(NetBearer::BEARER_ALL)) {
        return false;
    }
    // 检查当前网络是否满足要求（或者为 WiFi）
    bool isWifi = (currentNetBearerBitmap & static_cast<uint32_t>(NetBearer::BEARER_WIFI)) != 0;
    bool isRequired = (currentNetBearerBitmap & requiredNetBearerBitmap_) != 0;
    return !isWifi && !isRequired;
}

int32_t AnalysisNetConnectObserver::NetCapabilitiesChange(sptr<NetHandle> &netHandle,
    const sptr<NetAllCapabilities> &netAllCap)
{
    CHECK_AND_RETURN_RET_LOG(netAllCap != nullptr, E_ERR, "netAllCap is nullptr");

    if (netAllCap->netCaps_.count(NetCap::NET_CAPABILITY_INTERNET) == 0) {
        return E_OK;
    }

    if (netAllCap->bearerTypes_.count(NetBearType::BEARER_WIFI)) {
        MEDIA_INFO_LOG("wifi connected");
        SetNetConnStatus(NetBearer::BEARER_WIFI);
        MedialibraryRelatedSystemStateManager::GetInstance()->SetWifiConnected(true);
    } else if (netAllCap->bearerTypes_.count(NetBearType::BEARER_CELLULAR)) {
        MEDIA_INFO_LOG("cellular connected");
        SetNetConnStatus(NetBearer::BEARER_CELLULAR);
    } else if (netAllCap->bearerTypes_.count(NetBearType::BEARER_ETHERNET)) {
        MEDIA_INFO_LOG("ethernet connected");
        SetNetConnStatus(NetBearer::BEARER_ETHERNET);
    } else {
        MEDIA_INFO_LOG("other net connected");
        SetNetConnStatus(NetBearer::NO_NETWORK);
    }

    bool needCanceled = IfNeedCanceled();
    if (needCanceled) {
        LcdDownloadOperation::GetInstance()->CancelDownload();
    }
    return E_OK;
}

int32_t AnalysisNetConnectObserver::NetLost(sptr<NetHandle> &netHandle)
{
    MEDIA_INFO_LOG("net lost");
    SetNetConnStatus(NetBearer::NO_NETWORK);
    LcdDownloadOperation::GetInstance()->CancelDownload();
    return E_OK;
}

}  // namespace OHOS::Media