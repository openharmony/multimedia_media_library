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

#ifndef FILE_ASSET_H
#define FILE_ASSET_H

#include <string>
#include <limits.h>

#include "media_lib_service_const.h"
#include "media_data_ability_const.h"
#include "media_file_utils.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
/**
 * @brief Class for filling all file asset parameters
 *
 * @since 1.0
 * @version 1.0
 */
class FileAsset {
public:
    FileAsset();
    virtual ~FileAsset() = default;

    int32_t GetId() const;
    void SetId(int32_t id);

    const std::string &GetUri() const;
    void SetUri(const std::string &uri);

    const std::string &GetPath() const;
    void SetPath(const std::string &path);

    const std::string &GetRelativePath() const;
    void SetRelativePath(const std::string &relativePath);

    const std::string &GetMimeType() const;
    void SetMimeType(const std::string &mimeType);

    MediaType GetMediaType() const;
    void SetMediaType(MediaType mediaType);

    const std::string &GetDisplayName() const;
    void SetDisplayName(const std::string &displayName);

    int64_t GetSize() const;
    void SetSize(int64_t size);

    int64_t GetDateAdded() const;
    void SetDateAdded(int64_t dataAdded);

    int64_t GetDateModified() const;
    void SetDateModified(int64_t dateModified);

    const std::string &GetTitle() const;
    void SetTitle(const std::string &title);

    const std::string &GetArtist() const;
    void SetArtist(const std::string &artist);

    const std::string &GetAlbum() const;
    void SetAlbum(const std::string &album);

    int32_t GetWidth() const;
    void SetWidth(int32_t width);

    int32_t GetHeight() const;
    void SetHeight(int32_t height);

    int32_t GetDuration() const;
    void SetDuration(int32_t duration);

    int32_t GetOrientation() const;
    void SetOrientation(int32_t orientation);

    int32_t GetAlbumId() const;
    void SetAlbumId(int32_t albumId);

    const std::string &GetAlbumName() const;
    void SetAlbumName(const std::string &albumName);

    int32_t CreateAsset(const std::string &filePath);
    int32_t ModifyAsset(const std::string& oldPath, const std::string &newPath);
    int32_t DeleteAsset(const std::string &filePath);
    int32_t OpenAsset(const std::string &filePath, const std::string &mode);
    int32_t CloseAsset(int32_t fd);

private:
    int32_t id_;
    std::string uri_;
    std::string path_;
    std::string relativePath_;
    std::string mimeType_;
    MediaType mediaType_;
    std::string displayName_;
    int64_t size_;
    int64_t dateAdded_;
    int64_t dateModified_;

    // audio
    std::string title_;
    std::string artist_;
    std::string album_;

    // image,video
    int32_t width_;
    int32_t height_;
    int32_t duration_;
    int32_t orientation_;

    // album
    int32_t albumId_;
    std::string albumName_;
};
} // namespace Media
} // namespace OHOS
#endif  // FILE_ASSET_H