/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "cloud_media_data_client.h"

#include <string>
#include <vector>

#include "cloud_media_operation_code.h"
#include "media_log.h"
#include "message_parcel.h"
#include "user_define_ipc_client.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "media_empty_obj_vo.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::CloudSync {
int32_t CloudMediaDataClient::FinishCheck()
{
    MEDIA_INFO_LOG("CloudMediaDataClient::FinishCheck beigin");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaOperationCode::CMD_FINISH_CHECK);
    return IPC::UserDefineIPCClient().Call(operationCode);
}
}  // namespace OHOS::Media::CloudSync