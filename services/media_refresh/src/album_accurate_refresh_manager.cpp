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

#define MLOG_TAG "AccurateRefresh::AlbumAccurateRefreshManager"

#include <cstdint>
#include "accurate_debug_log.h"
#include "album_accurate_refresh_manager.h"
#include "media_file_utils.h"

namespace OHOS {
namespace Media::AccurateRefresh {

bool AlbumAccurateRefreshManager::IsAlbumAccurateRefresh(int32_t albumId, bool isHidden)
{
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    if (isForceRefresh_) {
        return false;
    }
    if (isHidden) {
        return accurateRefreshHiddenAlbums_.find(albumId) != accurateRefreshHiddenAlbums_.end();
    } else {
        return accurateRefreshAlbums_.find(albumId) != accurateRefreshAlbums_.end();
    }
}

void AlbumAccurateRefreshManager::RemoveAccurateRefreshAlbum(int32_t albumId, bool isHidden)
{
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    if (isHidden) {
        accurateRefreshAlbums_.erase(albumId);
    } else {
        accurateRefreshHiddenAlbums_.erase(albumId);
    }
    
    ACCURATE_DEBUG("remove album[%{public}d], hidden[%{public}d]", albumId, isHidden);
}

void AlbumAccurateRefreshManager::Clear()
{
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    accurateRefreshAlbums_.clear();
    accurateRefreshHiddenAlbums_.clear();
    MEDIA_INFO_LOG("clear");
}

void AlbumAccurateRefreshManager::SetRefreshTimestamp(int32_t albumId, bool isHidden,
    const AlbumRefreshTimestamp &timestamp)
{
    ACCURATE_DEBUG("albumId[%{public}d, %{public}d] refresh timestamp: %{public}s", albumId, isHidden,
        timestamp.ToString().c_str());
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    if (isHidden) {
        accurateRefreshHiddenAlbums_.insert_or_assign(albumId, timestamp);
    } else {
        accurateRefreshAlbums_.insert_or_assign(albumId, timestamp);
    }
}

AlbumRefreshTimestamp AlbumAccurateRefreshManager::GetRefreshTimestamp(int32_t albumId, bool isHidden)
{
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);

    if (isHidden) {
        auto iter = accurateRefreshHiddenAlbums_.find(albumId);
        if (iter == accurateRefreshHiddenAlbums_.end()) {
            ACCURATE_DEBUG("albumId[%{public}d] no refresh hidden timestamp", albumId);
            return AlbumRefreshTimestamp();
        }
        return iter->second;
    } else {
        auto iter = accurateRefreshAlbums_.find(albumId);
        if (iter == accurateRefreshAlbums_.end()) {
            ACCURATE_DEBUG("albumId[%{public}d] no refresh timestamp", albumId);
            return AlbumRefreshTimestamp();
        }
        return iter->second;
    }
}

int64_t AlbumAccurateRefreshManager::GetCurrentRefreshTag()
{
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    refreshTag_++;
    if (refreshTag_ < 0) {
        refreshTag_ = 0;
        accurateRefreshAlbums_.clear();
        accurateRefreshHiddenAlbums_.clear();
        MEDIA_INFO_LOG("reset refreshTag_");
    }
    return refreshTag_;
}

bool AlbumAccurateRefreshManager::IsRefreshTimestampMatch(int32_t albumId, bool isHidden,
    AlbumRefreshTimestamp compareTimestamp)
{
    auto albumTimestamp = GetRefreshTimestamp(albumId, isHidden);
    return albumTimestamp.start_ == compareTimestamp.start_ && albumTimestamp.end_ == compareTimestamp.end_;
}

AssetRefreshAlbumAction AlbumAccurateRefreshManager::GetRefreshAction(AlbumRefreshTimestamp albumTimestamp,
    AlbumRefreshTimestamp compareTimestamp)
{
    if (albumTimestamp.start_ == INVALID_INT64_VALUE || albumTimestamp.end_ == INVALID_INT64_VALUE) {
        return FORCE_REFRESH;
    }
    if (albumTimestamp.start_ > compareTimestamp.end_) {
        return IGNORE;
    }
    if (albumTimestamp.end_ < compareTimestamp.start_) {
        return ACCURATE_REFRESH;
    }
    return FORCE_REFRESH;
}

void AlbumAccurateRefreshManager::SetForceRefresh(bool isForceRefresh, std::string reason)
{
    MEDIA_WARN_LOG("force refresh[%{public}d], reason: %{public}s", isForceRefresh, reason.c_str());
    std::lock_guard<std::mutex> lock(albumRefreshMutex_);
    isForceRefresh_ = isForceRefresh;
}

} // namespace Media::AccurateRefresh
} // namespace OHOS