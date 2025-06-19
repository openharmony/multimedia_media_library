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

namespace OHOS {
namespace Media::AccurateRefresh {
bool AlbumAccurateRefreshManager::IsAlbumAccurateRefresh(int32_t albumId, bool isHidden)
{
    #ifdef MEDIA_REFRESH_TEST
        return true;
    #else
    return isHidden ? accurateRefreshHiddenAlbums_.find(albumId) != accurateRefreshHiddenAlbums_.end() :
        accurateRefreshAlbums_.find(albumId) != accurateRefreshAlbums_.end();
    #endif
}

void AlbumAccurateRefreshManager::SetAlbumAccurateRefresh(int32_t albumId, bool isHidden)
{
    if (isHidden) {
        accurateRefreshHiddenAlbums_.insert(albumId);
    } else {
        accurateRefreshAlbums_.insert(albumId);
    }
    
    ACCURATE_DEBUG("insert album[%{public}d], hidden[%{public}d]", albumId, isHidden);
}

void AlbumAccurateRefreshManager::RemoveAccurateRefreshAlbum(int32_t albumId, bool isHidden)
{
    if (isHidden) {
        accurateRefreshAlbums_.erase(albumId);
    } else {
        accurateRefreshHiddenAlbums_.erase(albumId);
    }
    
    ACCURATE_DEBUG("remove album[%{public}d], hidden[%{public}d]", albumId, isHidden);
}

void AlbumAccurateRefreshManager::Clear()
{
    accurateRefreshAlbums_.clear();
    accurateRefreshHiddenAlbums_.clear();
    MEDIA_INFO_LOG("clear");
}

} // namespace Media::AccurateRefresh
} // namespace OHOS