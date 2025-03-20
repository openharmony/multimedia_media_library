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

#define MLOG_TAG "CloudMediaDataControllerService"

#include "cloud_media_data_controller_service.h"

#include "media_log.h"
#include "user_define_ipc.h"

namespace OHOS::Media::CloudSync {
void CloudMediaDataControllerService::FinishCheck(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("CloudMediaDataControllerService::FinishCheck begin");
    int32_t ret = this->dataService_.FinishCheck();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}
}  // namespace OHOS::Media::CloudSync