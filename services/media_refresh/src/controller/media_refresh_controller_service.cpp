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

#define MLOG_TAG "MediRefreshControllerService"

#include "media_refresh_controller_service.h"

#include "album_accurate_refresh.h"
#include "asset_accurate_refresh.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "user_define_ipc.h"

namespace OHOS::Media {

bool MediaRefreshControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end();
}

void MediaRefreshControllerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, IPC::IPCContext &context)
{
    auto it = HANDLERS.find(code);
    if (it == HANDLERS.end()) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
    }
    return (this->*(it->second))(data, reply);
}

void MediaRefreshControllerService::NotifyForReCheck(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("Enter NotifyForReCheck");
    AccurateRefresh::AlbumAccurateRefresh::NotifyForReCheck();
    AccurateRefresh::AssetAccurateRefresh::NotifyForReCheck();
}

int32_t MediaRefreshControllerService::GetPermissionPolicy(
    uint32_t code, std::vector<std::vector<PermissionType>> &permissionPolicy, bool &isBypass)
{
    return 0;
}
} // namespace OHOS::Media