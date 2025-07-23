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

#include <mutex>
#include <unordered_map>
#include <sstream>

#include "accurate_common_data.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

struct AlbumRefreshTimestamp {
    int64_t start_ = INVALID_INT64_VALUE;
    int64_t end_ = INVALID_INT64_VALUE;
    AlbumRefreshTimestamp(int64_t start, int64_t end) : start_(start), end_(end) {}
    AlbumRefreshTimestamp(int64_t start) : start_(start), end_(INVALID_INT64_VALUE) {}
    AlbumRefreshTimestamp() : start_(INVALID_INT64_VALUE), end_(INVALID_INT64_VALUE) {}
    std::string ToString() const
    {
        std::stringstream ss;
        ss << "[" << start_ << ", " << end_ << "]";
        return ss.str();
    }
};

enum AssetRefreshAlbumAction {
    IGNORE,
    ACCURATE_REFRESH,
    FORCE_REFRESH
};

class EXPORT AlbumAccurateRefreshManager {
public:
    static AlbumAccurateRefreshManager& GetInstance()
    {
        static AlbumAccurateRefreshManager instance;
        return instance;
    }
    bool IsAlbumAccurateRefresh(int32_t albumId, bool isHidden);
    void RemoveAccurateRefreshAlbum(int32_t albumId, bool isHidden);
    void Clear();
    void SetRefreshTimestamp(int32_t albumId, bool isHidden, const AlbumRefreshTimestamp &timestamp);
    AlbumRefreshTimestamp GetRefreshTimestamp(int32_t albumId, bool isHidden);
    bool IsRefreshTimestampMatch(int32_t albumId, bool isHidden, AlbumRefreshTimestamp compareTimestamp);
    AssetRefreshAlbumAction GetRefreshAction(AlbumRefreshTimestamp albumTimestamp,
        AlbumRefreshTimestamp compareTimestamp);
    static int64_t GetCurrentTimestamp();
    void SetForceRefresh(bool isForceRefresh, std::string reason);

private:
    AlbumAccurateRefreshManager() {}
    ~AlbumAccurateRefreshManager() {}
    AlbumAccurateRefreshManager(const AlbumAccurateRefreshManager&) = delete;
    AlbumAccurateRefreshManager& operator=(const AlbumAccurateRefreshManager&) = delete;

public:
    static std::mutex albumRefreshMutex_;

private:
    std::unordered_map<int32_t, AlbumRefreshTimestamp> accurateRefreshAlbums_;
    std::unordered_map<int32_t, AlbumRefreshTimestamp> accurateRefreshHiddenAlbums_;
    bool isForceRefresh_ = false;
};

class AlbumRefreshTimestampRecord {
public:
    AlbumRefreshTimestampRecord(int32_t albumId, bool isHidden)
    {
        albumId_ = albumId;
        isHidden_ = isHidden;
        start_ = AlbumAccurateRefreshManager::GetCurrentTimestamp();
    }

    ~AlbumRefreshTimestampRecord()
    {
        // 异常情况未执行RefreshAlbumEnd，清除对应的albumId
        if (!isRecord) {
            AlbumAccurateRefreshManager::GetInstance().RemoveAccurateRefreshAlbum(albumId_, isHidden_);
        }
    }

    void ClearRecord()
    {
        isRecord = true;
    }

    void RefreshAlbumEnd()
    {
        AlbumRefreshTimestamp timestamp(start_, AlbumAccurateRefreshManager::GetCurrentTimestamp());
        AlbumAccurateRefreshManager::GetInstance().SetRefreshTimestamp(albumId_, isHidden_, timestamp);
        isRecord = true;
    }

private:
    int32_t albumId_;
    bool isHidden_;
    bool isRecord = false;
    int64_t start_ = 0;
};

} // namespace Media::AccurateRefresh
} // namespace OHOS

#endif