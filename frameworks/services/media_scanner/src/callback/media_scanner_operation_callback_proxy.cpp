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
#define MLOG_TAG "Scanner"

#include "media_scanner_operation_callback_proxy.h"
#include "media_log.h"
#include "media_scanner_const.h"

namespace OHOS {
namespace Media {
MediaScannerOperationCallbackProxy::MediaScannerOperationCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IMediaScannerOperationCallback>(impl) {}

int32_t MediaScannerOperationCallbackProxy::OnScanFinishedCallback(const int32_t status, const std::string &uri,
    const std::string &path)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(MediaScannerOperationCallbackProxy::GetDescriptor())) {
        MEDIA_ERR_LOG("MediaScannerOperationCallbackProxy interface token write error");
        return SCAN_PROXY_IF_TOKEN_WR_ERR;
    }

    if (!data.WriteInt32(status) || !data.WriteString(uri) || !data.WriteString(path)) {
        MEDIA_ERR_LOG("MediaScannerOperationCallbackProxy writing parcel data failed");
        return IPC_PROXY_ERR;
    }

    int32_t error = Remote()->SendRequest(MEDIA_SCAN_ON_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("MediaScannerOperationCallbackProxy OnScanFinishedCallback failed, error: %{private}d", error);
    }

    return error;
}
} // namespace Media
} // namespace OHOS
