/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef ALBUM_ASSET_H
#define ALBUM_ASSET_H

#include <string>
#include <vector>

#include "audio_asset.h"
#include "image_asset.h"
#include "video_asset.h"

namespace OHOS {
namespace Media {
using namespace std;
/**
 * @brief Data class for album details
 *
 * @since 1.0
 * @version 1.0
 */
class AlbumAsset {
public:
    AlbumAsset();
    virtual ~AlbumAsset();

    void SetAlbumId(const int32_t albumId);
    void SetAlbumName(const string albumName);
    void SetAlbumPath(const string albumPath);
    void SetAlbumDateModified(const int64_t albumDateModified);
    void SetAlbumVirtual(const bool albumVirtual);
    void SetAlbumRelativePath(const string albumRelativePath);

    int32_t GetAlbumId() const;
    string GetAlbumName() const;
    string GetAlbumPath() const;
    int64_t GetAlbumDateModified() const;
    bool GetAlbumVirtual() const;
    string GetAlbumRelativePath() const;

    bool CreateAlbumAsset();
    bool DeleteAlbumAsset(const std::string &albumUri);
    bool ModifyAlbumAsset(const std::string &albumUri);

    std::vector<std::unique_ptr<ImageAsset>> imageAssetList_;
    std::vector<std::unique_ptr<VideoAsset>> videoAssetList_;

private:
    int32_t albumId_;
    std::string albumName_;
    string albumPath_;
    int64_t albumDateModified_;
    bool albumVirtual_;
    string albumRelativePath_;
};
} // namespace Media
} // namespace OHOS
#endif // ALBUM_ASSET_H
