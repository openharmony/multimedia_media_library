/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIA_REFRESH_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_REFRESH_CONTROLLER_SERVICE_H

#include "i_media_controller_service.h"
#include "message_parcel.h"
#include "medialibrary_business_code.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaRefreshControllerService : public IPC::IMediaControllerService {
private:
    void NotifyForReCheck(MessageParcel &data, MessageParcel &reply);

    using RequestHandle = void (MediaRefreshControllerService::*)(MessageParcel &, MessageParcel &);
    const std::map<uint32_t, RequestHandle> HANDLERS = {
        {
            static_cast<uint32_t>(MediaLibraryBusinessCode::NOTIFY_FOR_RECHECK),
            &MediaRefreshControllerService::NotifyForReCheck
        },
    };

public:
    MediaRefreshControllerService() = default;
    virtual ~MediaRefreshControllerService() = default;
    bool Accept(uint32_t code) override;
    void OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, IPC::IPCContext &context) override;
    int32_t GetPermissionPolicy(
        uint32_t code, std::vector<std::vector<PermissionType>> &permissionPolicy, bool &isBypass) override;
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIA_REFRESH_CONTROLLER_SERVICE_H