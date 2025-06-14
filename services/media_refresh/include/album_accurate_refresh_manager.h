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

#ifndef OHOS_MEDIALIBRARY_ALBUM_ACCURATE_REFRESH_MANAGER_H
#define OHOS_MEDIALIBRARY_ALBUM_ACCURATE_REFRESH_MANAGER_H

#include <unordered_set>

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT AlbumAccurateRefreshManager {
public:
    static AlbumAccurateRefreshManager& GetInstance()
    {
        static AlbumAccurateRefreshManager instance;
        return instance;
    }
    bool IsAlbumAccurateRefresh(int32_t albumId, bool isHidden);
    void SetAlbumAccurateRefresh(int32_t albumId, bool isHidden);
    void RemoveAccurateRefreshAlbum(int32_t albumId, bool isHidden);
    void Clear();

private:
    AlbumAccurateRefreshManager() {}
    ~AlbumAccurateRefreshManager() {}
    AlbumAccurateRefreshManager(const AlbumAccurateRefreshManager&) = delete;
    AlbumAccurateRefreshManager& operator=(const AlbumAccurateRefreshManager&) = delete;

private:
    std::unordered_set<int32_t> accurateRefreshAlbums_;
    std::unordered_set<int32_t> accurateRefreshHiddenAlbums_;
};

} // namespace Media::AccurateRefresh
} // namespace OHOS

#endif