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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H

#include "datashare_helper.h"
#include "cloud_sync_observer.h"

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))
class CloudSyncNotifyHandler {
public:
    CloudSyncNotifyHandler(const CloudSyncNotifyInfo &info):notifyInfo_(info) {};
    ~CloudSyncNotifyHandler() = default;
    
    EXPORT void MakeResponsibilityChain();
    void ThumbnailObserverOnChange(const std::list<Uri> &uris, const DataShare::DataShareObserver::ChangeType &type);

    CloudSyncNotifyInfo notifyInfo_;

private:
    void HandleInsertEvent(const std::list<Uri> &uris);
    void HandleDeleteEvent(const std::list<Uri> &uris);
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H
