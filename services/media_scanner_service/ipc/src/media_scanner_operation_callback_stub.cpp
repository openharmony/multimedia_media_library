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

#include "media_log.h"
#include "media_scanner_operation_callback_stub.h"

using namespace std;

namespace OHOS {
namespace Media {
MediaScannerOperationCallbackStub::MediaScannerOperationCallbackStub()
{
}

int32_t MediaScannerOperationCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t errCode = ERR_NONE;

    switch (code) {
        case MEDIA_SCAN_ON_CALLBACK:
            errCode = MediaScannerOperationCallbackStub::HandleOnCallback(data);
            break;
        default:
            MEDIA_ERR_LOG("MediaScannerOperationCallbackStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t MediaScannerOperationCallbackStub::HandleOnCallback(MessageParcel& data)
{
    int32_t status(0);
    std::string uri("");
    std::string path("");

    status = data.ReadInt32();
    uri = data.ReadString();
    path = data.ReadString();

    return MediaScannerOperationCallbackStub::OnScanFinishedCallback(status, uri, path);
}

int32_t MediaScannerOperationCallbackStub::OnScanFinishedCallback(const int32_t status, const std::string &uri,
    const std::string &path)
{
    CHECK_AND_RETURN_RET_LOG(scanCallback_ != nullptr, SCAN_IPC_ERR, "Unable to send application callback");

    scanCallback_->OnScanFinished(status, uri, path);

    return SCAN_IPC_SUCCESS;
}

void MediaScannerOperationCallbackStub::SetApplicationCallback(const shared_ptr<IMediaScannerAppCallback> &scanCb)
{
    scanCallback_ = scanCb;
}
} // namespace Media
} // namespace OHOS
