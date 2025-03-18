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

#include "medialibrary_all_album_refresh_processor.h"

#include "albums_refresh_manager.h"
#include "cloud_sync_helper.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "medialibrary_album_fusion_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
namespace {
const int64_t REFRESH_ALL_ALBUMS_INTERVAL = 86400000000;  // 24 hours
}

shared_ptr<MediaLibraryAllAlbumRefreshProcessor> MediaLibraryAllAlbumRefreshProcessor::instance_ = nullptr;
mutex MediaLibraryAllAlbumRefreshProcessor::instanceMutex_;

shared_ptr<MediaLibraryAllAlbumRefreshProcessor> MediaLibraryAllAlbumRefreshProcessor::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> guard(instanceMutex_);
        if (instance_ != nullptr) {
            return instance_;
        }
        auto *mediaLibraryAllAlbumRefreshProcessor = new (nothrow)MediaLibraryAllAlbumRefreshProcessor();
        if (mediaLibraryAllAlbumRefreshProcessor == nullptr) {
            MEDIA_ERR_LOG("Failed to new MediaLibraryAllAlbumRefreshProcessor");
        }
        instance_ = shared_ptr<MediaLibraryAllAlbumRefreshProcessor>(mediaLibraryAllAlbumRefreshProcessor);
    }
    return instance_;
}

MediaLibraryAllAlbumRefreshProcessor::MediaLibraryAllAlbumRefreshProcessor()
{
}

int64_t MediaLibraryAllAlbumRefreshProcessor::GetNowTimeUs()
{
    struct timespec t;
    constexpr int64_t SEC_TO_USEC = 1e6;
    constexpr int64_t NSEC_TO_USEC = 1e3;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_USEC + t.tv_nsec / NSEC_TO_USEC;
}

void MediaLibraryAllAlbumRefreshProcessor::OnCurrentStatusChanged(bool currentStatus)
{
    std::lock_guard<std::mutex> lock(refreshAllAlbumsLock_);
    currentStatus_ = currentStatus;
    MEDIA_INFO_LOG("OnCurrentStatusChanged! %{public}d", currentStatus_);
    if (currentStatus_) {
        PostRefreshAllAlbumsTask();
    }
}

void MediaLibraryAllAlbumRefreshProcessor::OnCloudSyncStateChanged(bool isCloudSyncing)
{
    std::lock_guard<std::mutex> lock(refreshAllAlbumsLock_);
    isCloudSyncing_ = isCloudSyncing;
    MEDIA_INFO_LOG("OnCloudSyncStateChanged! %{public}d", isCloudSyncing_);
    if (!isCloudSyncing_) {
        PostRefreshAllAlbumsTask();
    }
}

bool MediaLibraryAllAlbumRefreshProcessor::CheckRefreshConditionLocked()
{
    return currentStatus_ && !isCloudSyncing_ &&
        (lastRefreshAllAlbumsTime_ == 0 || GetNowTimeUs() - lastRefreshAllAlbumsTime_ > REFRESH_ALL_ALBUMS_INTERVAL);
}

void MediaLibraryAllAlbumRefreshProcessor::TryRefreshAllAlbums()
{
    {
        std::lock_guard<std::mutex> lock(refreshAllAlbumsLock_);
        if (!CheckRefreshConditionLocked()) {
            return;
        }
        MEDIA_INFO_LOG("RefreshAllAlbums! now: %{public}lld, last : %{public}lld",
            GetNowTimeUs(), lastRefreshAllAlbumsTime_);
        lastRefreshAllAlbumsTime_ = GetNowTimeUs();
    }
    SyncNotifyInfo info;
    info.forceRefreshType = ForceRefreshType::CYCLE;
    AlbumsRefreshManager::GetInstance().AddAlbumRefreshTask(info);
    ffrt::submit([this]() { TryRefreshAllAlbums(); },
        ffrt::task_attr().delay(REFRESH_ALL_ALBUMS_INTERVAL));
}

void MediaLibraryAllAlbumRefreshProcessor::PostRefreshAllAlbumsTask()
{
    ffrt::submit([this]() { TryRefreshAllAlbums(); });
}
} // namespace Media
} // namespace OHOS
