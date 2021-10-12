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

#include "media_scanner_ability_stub.h"
#include "media_scanner_const.h"

namespace OHOS {
namespace Media {
int32_t MediaScannerAbilityStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t errCode = SCAN_IPC_SUCCESS;

    switch (code) {
        case MEDIA_SCAN_DIR_ABILITY:
            errCode = MediaScannerAbilityStub::HandleScanDir(data, reply);
            break;
        case MEDIA_SCAN_FILE_ABILITY:
            errCode = MediaScannerAbilityStub::HandleScanFile(data, reply);
            break;
        default:
            MEDIA_ERR_LOG("MediaScannerAbilityStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t MediaScannerAbilityStub::HandleScanDir(MessageParcel& data, MessageParcel &reply)
{
    std::string dirPath = data.ReadString();
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("MediaScannerServiceStub unable to read remote object");
        return SCAN_STUB_RD_ERR;
    }

    int32_t result = ScanDirService(dirPath, remoteObject);
    reply.WriteInt32(result);

    return ERR_NONE;
}

int32_t MediaScannerAbilityStub::HandleScanFile(MessageParcel& data, MessageParcel &reply)
{
    std::string filePath = data.ReadString();
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("MediaScannerServiceStub unable to read remote object");
        return SCAN_STUB_RD_ERR;
    }

    int32_t result = ScanFileService(filePath, remoteObject);
    reply.WriteInt32(result);

    return ERR_NONE;
}
} // namespace Media
} // namespace OHOS
