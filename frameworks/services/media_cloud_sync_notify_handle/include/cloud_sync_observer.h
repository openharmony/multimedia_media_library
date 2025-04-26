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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUDE_SYNC_OBSERVER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUDE_SYNC_OBSERVER_H

#include <mutex>

#include "datashare_helper.h"
#include "medialibrary_async_worker.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
struct CloudSyncNotifyInfo {
    std::list<Uri> uris;
    DataShare::DataShareObserver::ChangeType type;
    const void* data;
};

class EXPORT CloudSyncObserver : public DataShare::DataShareObserver {
public:
    CloudSyncObserver() = default;
    ~CloudSyncObserver() = default;

    void OnChange(const ChangeInfo &changeInfo) override;
    void DealPhotoGallery(CloudSyncNotifyInfo &notifyInfo);
    void DealAlbumGallery(CloudSyncNotifyInfo &notifyInfo);
    void DealCloudSync(const ChangeInfo &changeInfo);
    void DealGalleryDownload(CloudSyncNotifyInfo &notifyInfo);
    void HandleIndex();

    /* delayed trigger */
    bool isPending_ = false;
    std::mutex syncMutex_;
};

class CloudSyncNotifyData : public AsyncTaskData {
public:
    CloudSyncNotifyData(const CloudSyncNotifyInfo &info):notifyInfo_(info) {};
    virtual ~CloudSyncNotifyData() override = default;
    CloudSyncNotifyInfo notifyInfo_;
};
} // namespace Media
} // namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUDE_SYNC_OBSERVER_H
