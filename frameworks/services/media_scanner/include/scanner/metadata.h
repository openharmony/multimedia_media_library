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

#include <unordered_map>
#include <variant>
#include "scanner_utils.h"
#include "fetch_result.h"
#include "abs_shared_result_set.h"

namespace OHOS {
namespace Media {
class Metadata {
public:
    Metadata();
    ~Metadata() = default;
    using VariantData = std::variant<int32_t, std::string, int64_t, double>;

    void SetFileId(const VariantData &id);
    int32_t GetFileId() const;

    void SetFilePath(const VariantData &path);
    const std::string &GetFilePath() const;

    void SetUri(const VariantData &uri);
    const std::string &GetUri() const;

    void SetRelativePath(const VariantData &relativePath);
    const std::string &GetRelativePath() const;

    void SetFileMimeType(const VariantData &mimeType);
    const std::string &GetFileMimeType() const;

    void SetFileMediaType(const VariantData &mediaType);
    MediaType GetFileMediaType() const;

    void SetFileName(const VariantData &name);
    const std::string &GetFileName() const;

    void SetFileSize(const VariantData &size);
    int64_t GetFileSize() const;

    void SetFileDateAdded(const VariantData &dateAdded);
    int64_t GetFileDateAdded() const;

    void SetFileDateModified(const VariantData &dateModified);
    int64_t GetFileDateModified() const;

    void SetFileExtension(const VariantData &fileExt);
    const std::string &GetFileExtension() const;

    void SetFileTitle(const VariantData &title);
    const std::string &GetFileTitle() const;

    void SetFileArtist(const VariantData &artist);
    const std::string &GetFileArtist() const;

    void SetAlbum(const VariantData &album);
    const std::string &GetAlbum() const;

    void SetFileHeight(const VariantData &height);
    int32_t GetFileHeight() const;

    void SetFileWidth(const VariantData &width);
    int32_t GetFileWidth() const;

    void SetOrientation(const VariantData &orientation);
    int32_t GetOrientation() const;

    void SetFileDuration(const VariantData &duration);
    int32_t GetFileDuration() const;

    int32_t GetParentId() const;
    void SetParentId(const VariantData &id);

    void SetAlbumId(const VariantData &albumId);
    int32_t GetAlbumId() const;

    void SetAlbumName(const VariantData &album);
    const std::string &GetAlbumName() const;

    void SetRecyclePath(const VariantData &recyclePath);
    const std::string &GetRecyclePath() const;

    void SetDateTaken(const VariantData &dateTaken);
    int64_t GetDateTaken() const;

    void SetLongitude(const VariantData &longitude);
    double GetLongitude() const;

    void SetLatitude(const VariantData &latitude);
    double GetLatitude() const;

    void Init();

    using MetadataFnPtr = void (Metadata::*)(const VariantData &);
    std::unordered_map<std::string, std::pair<ResultSetDataType, MetadataFnPtr>> memberFuncMap_;

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

    // video, audio, image
    int64_t dateTaken_;

    // image
    double longitude_;
    double latitude_;

    // album
    int32_t albumId_;
    std::string albumName_;

    // recycle
    std::string recyclePath_;
};
} // namespace Media
} // namespace OHOS

#endif // METADATA_H
