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

#include "media_scanner_ability_proxy.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
MediaScannerAbilityProxy::MediaScannerAbilityProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMediaScannerAbility>(impl) {}

int32_t MediaScannerAbilityProxy::ScanDirService(std::string &scanDirPath, const sptr<IRemoteObject> &scanDirCb)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaScannerAbilityProxy::GetDescriptor())) {
        MEDIA_ERR_LOG("MediaScannerAbilityProxy interface token write error");
        return SCAN_PROXY_IF_TOKEN_WR_ERR;
    }

    if (!data.WriteString(scanDirPath)) {
        MEDIA_ERR_LOG("MediaScannerAbilityProxy writing scanDir data failed");
        return SCAN_PROXY_WR_ERR;
    }

    if (!data.WriteRemoteObject(scanDirCb)) {
        MEDIA_ERR_LOG("MediaScannerProxy SetCallback write MediaScannerCallback obj failed");
        return SCAN_PROXY_WR_ERR;
    }

    int32_t error = Remote()->SendRequest(MEDIA_SCAN_DIR_ABILITY, data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("%{private}s:: ScanDirService IPC failed, error: %{private}d", __func__, error);
        return SCAN_IPC_ERR;
    }

    int32_t result(0);
    if (!reply.ReadInt32(result)) {
        MEDIA_ERR_LOG("Failed to read Request ID from request reply");
        return SCAN_PROXY_RD_ERR;
    }

    return result;
}

int32_t MediaScannerAbilityProxy::ScanFileService(std::string &scanFilePath, const sptr<IRemoteObject> &scanFileCb)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaScannerAbilityProxy::GetDescriptor())) {
        MEDIA_ERR_LOG("MediaScannerAbilityProxy interface token write error");
        return SCAN_PROXY_IF_TOKEN_WR_ERR;
    }

    if (!data.WriteString(scanFilePath)) {
        MEDIA_ERR_LOG("MediaScannerAbilityProxy writing ScanFile data failed");
        return SCAN_PROXY_WR_ERR;
    }

    if (!data.WriteRemoteObject(scanFileCb)) {
        MEDIA_ERR_LOG("MediaScannerProxy SetCallback write MediaScannerCallback obj failed");
        return SCAN_PROXY_WR_ERR;
    }

    int32_t error = Remote()->SendRequest(MEDIA_SCAN_FILE_ABILITY, data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("%{private}s:: ScanFileService IPC failed, error: %{private}d", __func__, error);
        return SCAN_IPC_ERR;
    }

    int32_t result(0);
    if (!reply.ReadInt32(result)) {
        MEDIA_ERR_LOG("Failed to read Request ID from request reply");
        return SCAN_PROXY_RD_ERR;
    }

    return result;
}

bool MediaScannerAbilityProxy::IsScannerRunning()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaScannerAbilityProxy::GetDescriptor())) {
        MEDIA_ERR_LOG("MediaScannerAbilityProxy interface token write error");
        return false;
    }

    int32_t error = Remote()->SendRequest(MEDIA_GET_SCAN_STATUS, data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("%{private}s:: IsScannerRunning IPC failed, error: %{private}d", __func__, error);
        return false;
    }

    auto result(false);
    reply.ReadBool(result);

    return result;
}
} // namespace Media
} // namespace OHOS
