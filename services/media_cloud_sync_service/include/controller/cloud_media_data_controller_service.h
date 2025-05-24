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
#include "datashare_stub.h"
#include "photos_dto.h"
#include "photos_vo.h"
#include "rdb_store.h"
#include "i_media_controller_service.h"
#include "cloud_media_operation_code.h"
#include "medialibrary_errno.h"
#include "media_resp_vo.h"
#include "media_empty_obj_vo.h"
#include "user_define_ipc.h"
#include "cloud_media_data_controller_processor.h"
#include "cloud_media_data_service.h"

namespace OHOS::Media::CloudSync {
class CloudMediaDataControllerService : public IPC::IMediaControllerService {
private:
    void UpdateDirty(MessageParcel &data, MessageParcel &reply);
    void UpdatePosition(MessageParcel &data, MessageParcel &reply);
    void UpdateThmStatus(MessageParcel &data, MessageParcel &reply);
    void GetAgingFile(MessageParcel &data, MessageParcel &reply);
    void GetActiveAgingFile(MessageParcel &data, MessageParcel &reply);
    void GetVideoToCache(MessageParcel &data, MessageParcel &reply);
    void GetFilePosStat(MessageParcel &data, MessageParcel &reply);
    void GetCloudThmStat(MessageParcel &data, MessageParcel &reply);
    void GetDirtyTypeStat(MessageParcel &data, MessageParcel &reply);
    void UpdateLocalFileDirty(MessageParcel &data, MessageParcel &reply);
    void UpdateSyncStatus(MessageParcel &data, MessageParcel &reply);

private:
    using RequestHandle = void (CloudMediaDataControllerService::*)(MessageParcel &, MessageParcel &);
    const std::map<uint32_t, RequestHandle> HANDLERS = {
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_UPDATE_DIRTY_FOR_CLOUD_CHECK),
            &CloudMediaDataControllerService::UpdateDirty},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_UPDATE_POSITION_FOR_CLOUD_CHECK),
            &CloudMediaDataControllerService::UpdatePosition},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_UPDATE_THM_STATUS_FOR_CLOUD_CHECK),
            &CloudMediaDataControllerService::UpdateThmStatus},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_VIDEO_TO_CACHE),
            &CloudMediaDataControllerService::GetVideoToCache},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_FILE_POS_STAT),
            &CloudMediaDataControllerService::GetFilePosStat},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_CLOUD_THM_STAT),
            &CloudMediaDataControllerService::GetCloudThmStat},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_DIRTY_TYPE_STAT),
            &CloudMediaDataControllerService::GetDirtyTypeStat},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_AGING_ASSET),
            &CloudMediaDataControllerService::GetAgingFile},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_GET_ACTIVE_AGING_ASSET),
            &CloudMediaDataControllerService::GetActiveAgingFile},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_UPDATE_LOCAL_FILE_DIRTY),
            &CloudMediaDataControllerService::UpdateLocalFileDirty},
        {static_cast<uint32_t>(CloudMediaOperationCode::CMD_UPDATE_SYNC_STATUS),
            &CloudMediaDataControllerService::UpdateSyncStatus},
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
        if (!this->Accept(code) || it == this->HANDLERS.end()) {
            return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
        }
        return (this->*(it->second))(data, reply);
    }

private:
    CloudMediaDataControllerProcessor processor_;
    CloudMediaDataService dataService_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CONTROLLER_SERVICE_H