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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_CACHE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_CACHE_H

#include <string>
#include <vector>
#include <unordered_map>

#include "safe_vector.h"
#include "photo_album_po.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;

class EXPORT CloudMediaAlbumCache {
public:
    int32_t SetAlbumCache(const std::vector<PhotoAlbumPo> &albumInfoList);
    int32_t ClearAlbumCache();
    int32_t QueryAlbumByCloudId(const std::string &cloudId, std::optional<PhotoAlbumPo> &albumInfo);
    int32_t QueryAlbumBylPath(const std::string &lPath, std::optional<PhotoAlbumPo> &albumInfo);
    int32_t QueryAlbumBySourcePath(const std::string &sourcePath, std::optional<PhotoAlbumPo> &albumInfo);
    bool IsEmpty();

private:
    std::string ToLower(const std::string &str);

private:
    SafeVector<PhotoAlbumPo> albumInfoList_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_CACHE_H