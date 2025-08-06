/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SERVICE_INCLUDE_CLOUD_SYNC_HELPER_H_
#define FRAMEWORKS_SERVICES_CLOUD_SERVICE_INCLUDE_CLOUD_SYNC_HELPER_H_

#include <mutex>

#include <atomic>
#include <timer.h>

#include "cloud_sync_manager.h"
#include "datashare_helper.h"
#include "datashare_result_set.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))

constexpr int32_t SYNC_INTERVAL = 5000;

class CloudSyncHelper final {
public:
    EXPORT static std::shared_ptr<CloudSyncHelper> GetInstance();
    std::atomic<bool> isThumbnailGenerationCompleted_ = true;
    virtual ~CloudSyncHelper() = default;

    EXPORT void StartSync();
    EXPORT bool IsSyncSwitchOpen();

private:
    void OnTimerCallback();
    bool InitDataShareHelper();

    /* singleton */
    static std::shared_ptr<CloudSyncHelper> instance_;
    static std::mutex instanceMutex_;

    /* delayed trigger */
    std::mutex syncMutex_;
    std::condition_variable skipCond_;

    /* sync switch */
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    std::string uri_;
    std::string QUERY_URI = "datashareproxy://";
    std::string SYNC_SWITCH_SUFFIX = "/sync_switch?user=";
    std::string SWITCH_STATUS_KEY = "isSwitchOn";
    std::string BUNDLE_NAME_KEY = "bundleName";
    std::string GALLERY_BUNDLE_NAME;
};

class MediaCloudSyncCallback : public FileManagement::CloudSync::CloudSyncCallback {
public:
    void OnSyncStateChanged(FileManagement::CloudSync::SyncType type,
        FileManagement::CloudSync::SyncPromptState state) override;
    void OnSyncStateChanged(FileManagement::CloudSync::CloudSyncState state,
        FileManagement::CloudSync::ErrorType error) override;
private:
    std::mutex syncStateMutex_;
    bool isSyncing_ = false;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_CLOUD_SERVICE_INCLUDE_CLOUD_SYNC_HELPER_H_