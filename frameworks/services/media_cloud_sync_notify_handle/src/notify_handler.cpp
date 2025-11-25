/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "notify_handler.h"

#include "dataobs_mgr_client.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;

void NotifyHandler::Handle(const CloudSyncHandleData &handleData)
{
    auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return;
    }
    for (auto &notifyInfo : handleData.notifyInfo) {
        list<Uri> uris;
        for (auto &uriRemarkPair : notifyInfo.second) {
            uris.push_back(uriRemarkPair.first);
        }
        obsMgrClient->NotifyChangeExt({static_cast<ChangeType>(notifyInfo.first), uris});
    }

    if (nextHandler_ != nullptr) {
        nextHandler_->Handle(handleData);
    }
    return ;
}
} //namespace Media
} //namespace OHOS
