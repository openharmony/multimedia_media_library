/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_scanner_client.h"
#include "media_log.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
using namespace std;

namespace OHOS {
namespace Media {
std::shared_ptr<IMediaScannerClient> MediaScannerHelperFactory::CreateScannerHelper()
{
    return OHOS::Media::MediaScannerClient::GetMediaScannerInstance();
}

std::mutex MediaScannerClient::mutex_;
std::shared_ptr<MediaScannerClient> MediaScannerClient::msInstance_ = nullptr;

std::shared_ptr<MediaScannerClient> MediaScannerClient::GetMediaScannerInstance()
{
    if (msInstance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (msInstance_ == nullptr) {
            msInstance_ = std::make_shared<MediaScannerClient>();
        }
    }

    CHECK_AND_RETURN_RET_LOG(msInstance_ != nullptr, nullptr, "Failed to create new media scanner client");

    return msInstance_;
}

MediaScannerClient::~MediaScannerClient()
{
    connectionState_ = ConnectionState::CONN_NONE;
    abilityMgrProxy_ = nullptr;
    connection_ = nullptr;
    scanList_.clear();
}


int32_t MediaScannerClient::ConnectAbility()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsScannerServiceConnected()) {
        // Obtain ability manager service for connecting to ability
        auto abilityMgr = DelayedSingleton<SysMrgClient>::GetInstance()->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
        CHECK_AND_RETURN_RET_LOG(abilityMgr != nullptr, CONN_ERROR, "Ability Mgr instance not available");

        abilityMgrProxy_ = iface_cast<IAbilityManager>(abilityMgr);
        CHECK_AND_RETURN_RET_LOG(abilityMgrProxy_ != nullptr, CONN_ERROR, "Ability Mgr proxy is null");

        // Create callback stub object and pass to fwk connect request.
        connection_ = new (std::nothrow) MediaScannerConnectCallbackStub();
        CHECK_AND_RETURN_RET_LOG(connection_ != nullptr, CONN_ERROR, "connect cb object create failed");

        Want want;
        want.SetElementName(SCANNER_BUNDLE_NAME, SCANNER_ABILITY_NAME);

        // Connect to the service ability. Dest ability name mentioned in want param
        SetConnectionState(ConnectionState::CONN_IN_PROGRESS);
        int32_t ret = abilityMgrProxy_->ConnectAbility(want, connection_, nullptr);
        if (ret != 0) {
            MEDIA_ERR_LOG("MediaScannerClient:: Connect ability failed %{private}d", ret);
            SetConnectionState(ConnectionState::CONN_ERROR);
            return CONN_ERROR;
        }
    }

    return CONN_SUCCESS;
}

void MediaScannerClient::DisconnectAbility()
{
    CHECK_AND_RETURN_LOG(connection_ != nullptr && abilityMgrProxy_ != nullptr, "Connection unavailable");

    int32_t ret = abilityMgrProxy_->DisconnectAbility(connection_);
    if (ret != 0) {
        MEDIA_ERR_LOG("MediaScannerClient:: Disconnect ability failed %{private}d", ret);
        return;
    }

    connectionState_ = ConnectionState::CONN_NONE;
    abilityMgrProxy_ = nullptr;
    connection_ = nullptr;
    scanList_.clear();
}

void MediaScannerClient::Release()
{
    // If already disconnected, return from here
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsScannerServiceConnected()) {
        MEDIA_ERR_LOG("Scanner Service is not connected");
        return;
    }

    CHECK_AND_RETURN_LOG(abilityProxy_ != nullptr, "Ability service proxy unavailable");

    if (abilityProxy_->IsScannerRunning()) {
        MEDIA_ERR_LOG("scanner is running. Cannot release ability now");
        return;
    }

    // Scanner is not running. Release ability
    DisconnectAbility();
}

ScanState MediaScannerClient::ScanDir(string &scanDirPath, const shared_ptr<IMediaScannerAppCallback> &scanDircb)
{
    return ScanInternal(scanDirPath, scanDircb, ScanType::SCAN_DIR);
}

ScanState MediaScannerClient::ScanFile(string &scanFilePath, const shared_ptr<IMediaScannerAppCallback> &scanFileCb)
{
    return ScanInternal(scanFilePath, scanFileCb, ScanType::SCAN_FILE);
}

ScanState MediaScannerClient::ScanInternal(string &path, const shared_ptr<IMediaScannerAppCallback> &appCb,
    ScanType scanType)
{
    auto connectResult = ConnectAbility();
    CHECK_AND_RETURN_RET_LOG(connectResult == CONN_SUCCESS, SCAN_ERROR, "Service error %{private}d", connectResult);

    sptr<MediaScannerOperationCallbackStub> callbackStub = new(std::nothrow) MediaScannerOperationCallbackStub();
    CHECK_AND_RETURN_RET_LOG(callbackStub != nullptr, SCAN_MEM_ALLOC_FAIL, "ScannerOperCallback creation failed");

    callbackStub->SetApplicationCallback(appCb);

    sptr<IRemoteObject> callbackRemoteObj = callbackStub->AsObject();
    CHECK_AND_RETURN_RET_LOG(callbackRemoteObj != nullptr, SCAN_MEM_ALLOC_FAIL, "callback remote obj is null");

    // If service is not connected, add the request into queue. Queue will be processed OnAbilityConnected callback
    if (GetConnectionState() == ConnectionState::CONN_IN_PROGRESS) {
        ScanRequest scanRequest;
        scanRequest.scanType = scanType;
        scanRequest.path = path;
        scanRequest.serviceCb = callbackRemoteObj;
        scanRequest.appCallback = appCb;

        // Add request to the queue with locked scope
        if (UpdateScanRequestQueue(scanRequest)) {
            return SCAN_SUCCESS;
        }
    }

    CHECK_AND_RETURN_RET_LOG(abilityProxy_ != nullptr, SCAN_ERROR, "Ability service proxy unavailable for scanning");

    if (scanType == ScanType::SCAN_FILE) {
        int32_t ret = abilityProxy_->ScanFileService(path, callbackRemoteObj);
        CHECK_AND_RETURN_RET_LOG(ret == 0, static_cast<ScanState>(ret), "Scan file failed [%{private}d]", ret);
    } else if (scanType == ScanType::SCAN_DIR) {
        int32_t ret = abilityProxy_->ScanDirService(path, callbackRemoteObj);
        CHECK_AND_RETURN_RET_LOG(ret == 0, static_cast<ScanState>(ret), "Scan dir failed [%{private}d]", ret);
    }

    return SCAN_SUCCESS;
}

bool MediaScannerClient::IsScannerServiceConnected()
{
    ConnectionState connState = GetConnectionState();
    if (connState == ConnectionState::CONN_SUCCESS || connState == ConnectionState::CONN_IN_PROGRESS) {
        return true;
    }

    return false;
}

void MediaScannerClient::SetConnectionState(ConnectionState connState)
{
    connectionState_ = connState;
}

ConnectionState MediaScannerClient::GetConnectionState()
{
    return connectionState_;
}

void MediaScannerClient::EmptyScanRequestQueue(bool isConnected)
{
    for (auto &scanRequest : scanList_) {
        if (!isConnected) {
            MEDIA_ERR_LOG("Remote object unavailable. Notify registered clients");
            CHECK_AND_RETURN_LOG(scanRequest.appCallback != nullptr, "Invalid app callback object");
            scanRequest.appCallback->OnScanFinished(SCAN_ERROR, "", scanRequest.path);
            continue;
        }

        CHECK_AND_RETURN_LOG(abilityProxy_ != nullptr, "Ability service unavailable");
        auto ret(0);
        switch (scanRequest.scanType) {
            case SCAN_FILE:
                ret = abilityProxy_->ScanFileService(scanRequest.path, scanRequest.serviceCb);
                if (ret != SCAN_SUCCESS) {
                    MEDIA_ERR_LOG("Scan file operation failed %{private}d", ret);
                    scanRequest.appCallback->OnScanFinished(ret, "", scanRequest.path);
                }
                break;
            case SCAN_DIR:
                ret = abilityProxy_->ScanDirService(scanRequest.path, scanRequest.serviceCb);
                if (ret != SCAN_SUCCESS) {
                    MEDIA_ERR_LOG("Scan dir operation failed %{private}d", ret);
                    scanRequest.appCallback->OnScanFinished(ret, "", scanRequest.path);
                }
                break;
            default:
                break;
        }
    }

    scanList_.clear();
}

bool MediaScannerClient::UpdateScanRequestQueue(ScanRequest &scanRequest)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (GetConnectionState() == ConnectionState::CONN_IN_PROGRESS) {
        scanList_.emplace_back(scanRequest);
        return true;
    }

    return false;
}

void MediaScannerClient::OnConnectAbility(const sptr<IRemoteObject> &remoteObject, int32_t result)
{
    sptr<IMediaScannerAbility> scannerAbilityProxy = iface_cast<IMediaScannerAbility>(remoteObject);

    std::lock_guard<std::mutex> lock(mutex_);
    if (result == 0 && scannerAbilityProxy != nullptr) {
        SetConnectionState(ConnectionState::CONN_SUCCESS);
        abilityProxy_ = scannerAbilityProxy;
        MediaScannerClient::EmptyScanRequestQueue(true);
    } else {
        SetConnectionState(ConnectionState::CONN_ERROR);
        abilityProxy_ = nullptr;
        MediaScannerClient::EmptyScanRequestQueue(false);
    }
}

void MediaScannerClient::OnDisconnectAbility()
{
    abilityProxy_ = nullptr;

    std::lock_guard<std::mutex> lock(mutex_);
    SetConnectionState(ConnectionState::CONN_NONE);

    // Clear all pending requests. Since service is disconnected, we cannot process any requests
    if (!scanList_.empty()) {
        MediaScannerClient::EmptyScanRequestQueue(false);
    }
}

// Connect callback impl
MediaScannerConnectCallbackStub::MediaScannerConnectCallbackStub()
{
    scannerClientInstance_ = MediaScannerClient::GetMediaScannerInstance();
}

MediaScannerConnectCallbackStub::~MediaScannerConnectCallbackStub()
{
    scannerClientInstance_ = nullptr;
}

void MediaScannerConnectCallbackStub::OnAbilityConnectDone(const OHOS::AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t result)
{
    CHECK_AND_RETURN_LOG(scannerClientInstance_ != nullptr, "Scanner instance is down in OnAbilityConnectDone");
    scannerClientInstance_->OnConnectAbility(remoteObject, result);
}

void MediaScannerConnectCallbackStub::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t result)
{
    CHECK_AND_RETURN_LOG(scannerClientInstance_ != nullptr, "Scanner instance is down in OnAbilityDisconnectDone");
    scannerClientInstance_->OnDisconnectAbility();
}
} // namespace Media
} // namespace OHOS
