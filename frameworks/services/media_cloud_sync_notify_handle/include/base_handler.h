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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_INCLUDE_HANDLE_BASE_HANDLER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_INCLUDE_HANDLE_BASE_HANDLER_H

#include "datashare_helper.h"
#include "cloud_sync_observer.h"

namespace OHOS {
namespace Media {

struct CloudSyncHandleData {
    CloudSyncNotifyInfo orgInfo;
    std::unordered_map<DataShare::DataShareObserver::ChangeType, std::list<std::pair<Uri, std::string>>> notifyInfo;
};

class BaseHandler {
public:
    BaseHandler() = default;
    virtual ~BaseHandler() = default;

public:
    virtual void Handle(const CloudSyncHandleData &handleData) = 0;
    virtual void init() {}
    void SetNextHandler(const std::shared_ptr<BaseHandler> &nextHandler)
    {
        nextHandler_ = nextHandler;
    }

public:
    std::shared_ptr<BaseHandler> nextHandler_;
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_INCLUDE_HANDLE_BASE_HANDLER_H
