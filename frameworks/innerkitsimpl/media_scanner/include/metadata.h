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

#ifndef METADATA_H
#define METADATA_H

#include "scanner_utils.h"

namespace OHOS {
namespace Media {
class Metadata {
public:
    Metadata();
    ~Metadata() = default;

    void SetFileId(const int32_t id);
    int32_t GetFileId() const;

    void SetFilePath(const std::string path);
    std::string GetFilePath() const;

    void SetUri(const std::string uri);
    std::string GetUri() const;

    void SetRelativePath(const std::string relativePath);
    std::string GetRelativePath() const;

    void SetFileMimeType(const std::string mimeType);
    std::string GetFileMimeType() const;

    void SetFileMediaType(const MediaType mediaType);
    MediaType GetFileMediaType() const;

    void SetFileName(const std::string name);
    std::string GetFileName() const;

    void SetFileSize(const int64_t size);
    int64_t GetFileSize() const;

    void SetFileDateAdded(const int64_t dateAdded);
    int64_t GetFileDateAdded() const;

    void SetFileDateModified(const int64_t dateModified);
    int64_t GetFileDateModified() const;

    void SetFileExtension(const std::string fileExt);
    std::string GetFileExtension() const;

    void SetFileTitle(const std::string title);
    std::string GetFileTitle() const;

    void SetFileArtist(const std::string artist);
    std::string GetFileArtist() const;

    void SetAlbum(const std::string album);
    std::string GetAlbum() const;

    void SetFileHeight(const int32_t height);
    int32_t GetFileHeight() const;

    void SetFileWidth(const int32_t width);
    int32_t GetFileWidth() const;

    void SetOrientation(const int32_t orientation);
    int32_t GetOrientation() const;

    void SetFileDuration(const int32_t duration);
    int32_t GetFileDuration() const;

    int32_t GetParentId() const;
    void SetParentId(const int32_t id);

    void SetAlbumId(const int32_t albumId);
    int32_t GetAlbumId() const;

    void SetAlbumName(const std::string album);
    std::string GetAlbumName() const;

private:
    int32_t id_;
    std::string uri_;
    std::string filePath_;
    std::string relativePath_;

    std::string mimeType_;
    MediaType mediaType_;
    std::string name_;

    int64_t size_;
    int64_t dateModified_;
    int64_t dateAdded_;

    std::string fileExt_;
    int32_t parentId_;

    // audio
    std::string title_;
    std::string artist_;
    std::string album_;

    // video, image
    int32_t height_;
    int32_t width_;
    int32_t duration_;
    int32_t orientation_;

    // album
    int32_t albumId_;
    std::string albumName_;
};
} // namespace Media
} // namespace OHOS

#endif // METADATA_H
