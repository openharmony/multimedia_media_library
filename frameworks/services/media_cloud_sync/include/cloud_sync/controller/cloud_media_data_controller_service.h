/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CONTROLLER_SERVICE_H

#include <string>
#include <vector>
#include <map>

#include "message_parcel.h"
#include "i_media_controller_service.h"
#include "cloud_media_data_service.h"
#include "cloud_media_operation_code.h"
#include "medialibrary_errno.h"
#include "user_define_ipc.h"

namespace OHOS::Media::CloudSync {
class CloudMediaDataControllerService : public IPC::IMediaControllerService {
private:
    void FinishCheck(MessageParcel &data, MessageParcel &reply);

private:
    using RequestHandle = void (CloudMediaDataControllerService::*)(MessageParcel &, MessageParcel &);
    const std::map<uint32_t, RequestHandle> HANDLERS = {
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_FINISH_CHECK),
            &CloudMediaDataControllerService::FinishCheck},
    };

public:
    virtual ~CloudMediaDataControllerService() = default;
    bool Accept(uint32_t code) override
    {
        return this->HANDLERS.find(code) != this->HANDLERS.end();
    }
    void OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        auto it = this->HANDLERS.find(code);
        bool errConn = it == this->HANDLERS.end();
        CHECK_AND_RETURN_RET(!errConn, IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND));
        return (this->*(it->second))(data, reply);
    }

private:
    CloudMediaDataService dataService_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CONTROLLER_SERVICE_H