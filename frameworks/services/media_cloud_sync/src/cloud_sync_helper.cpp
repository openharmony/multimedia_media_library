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

#define MLOG_TAG "Cloud"

#include "cloud_sync_helper.h"

#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace FileManagement::CloudSync;

shared_ptr<CloudSyncHelper> CloudSyncHelper::instance_ = nullptr;
mutex CloudSyncHelper::instanceMutex_;

shared_ptr<CloudSyncHelper> CloudSyncHelper::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> guard(instanceMutex_);
        if (instance_ != nullptr) {
            return instance_;
        }
        instance_ = shared_ptr<CloudSyncHelper>(new (nothrow)CloudSyncHelper());
    }

    return instance_;
}

CloudSyncHelper::CloudSyncHelper() : timer_("CloudSync")
{
    timer_.Setup();
}

CloudSyncHelper::~CloudSyncHelper()
{
    timer_.Unregister(timerId_);
    timer_.Shutdown();
}

void CloudSyncHelper::StartSync()
{
    lock_guard<mutex> lock(syncMutex_);
    if (isPending_) {
        /* cancel the previous timer */
        timer_.Unregister(timerId_);
    } else {
        isPending_ = true;
    }
    timerId_ = timer_.Register(bind(&CloudSyncHelper::OnTimerCallback, this),
        SYNC_INTERVAL, true);
}

void CloudSyncHelper::OnTimerCallback()
{
    unique_lock<mutex> lock(syncMutex_);
    isPending_ = false;
    lock.unlock();

    MEDIA_INFO_LOG("cloud sync manager start sync");
    auto callback = make_shared<MediaCloudSyncCallback>();
    int32_t ret = CloudSyncManager::GetInstance().StartSync(false, callback);
    if (ret != 0) {
        MEDIA_ERR_LOG("cloud sync manager start sync err %{public}d", ret);
    }
}

void MediaCloudSyncCallback::OnSyncStateChanged(SyncType type, SyncPromptState state)
{
    MEDIA_INFO_LOG("sync type %{public}d, state %{public}d", type, state);
}
} // namespace Media
} // namespace OHOS
