/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_FILE_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_FILE_ASSET_H_

#include <memory>
#include <mutex>
#include <string>
#include <variant>
#include <unordered_map>
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {

constexpr int MEMBER_TYPE_INT32 = 0;
constexpr int MEMBER_TYPE_INT64 = 1;
constexpr int MEMBER_TYPE_STRING = 2;
constexpr int MEMBER_TYPE_DOUBLE = 3;

constexpr int OPEN_TYPE_READONLY = 0;
constexpr int OPEN_TYPE_WRITE = 1;

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

    int32_t GetCount() const;
    void SetCount(int32_t count);

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

    int32_t GetPosition() const;
    void SetPosition(int32_t position);

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

    int32_t GetParent() const;
    void SetParent(int32_t parent);
    const std::string &GetAlbumUri() const;
    void SetAlbumUri(const std::string &albumUri);
    const std::string &GetTypeMask() const;
    void SetTypeMask(const std::string &typeMask);
    int64_t GetDateTaken() const;
    void SetDateTaken(int64_t dataTaken);

    int64_t GetTimePending() const;
    void SetTimePending(int64_t timePending);

    bool IsFavorite() const;
    void SetFavorite(bool isFavorite);
    int64_t GetDateTrashed() const;
    void SetDateTrashed(int64_t dateTrashed);

    const std::string &GetSelfId() const;
    void SetSelfId(const std::string &selfId);
    int32_t GetIsTrash() const;
    void SetIsTrash(int32_t isTrash);
    const std::string GetOwnerPackage() const;
    void SetOwnerPackage(const std::string &packageName);

    const std::string &GetRecyclePath() const;
    void SetRecyclePath(const std::string &recyclePath);

    ResultNapiType GetResultNapiType() const;
    void SetResultNapiType(const ResultNapiType type);

    void SetOpenStatus(int32_t fd, int32_t openStatus);
    void RemoveOpenStatus(int32_t fd);
    int32_t GetOpenStatus(int32_t fd);

    std::unordered_map<std::string, std::variant<int32_t, int64_t, std::string>> &GetMemberMap();
    std::variant<int32_t, int64_t, std::string> &GetMemberValue(const std::string &name);

    void CommitModify();
    bool IsDirectory();

private:
    const std::string &GetStrMember(const std::string &name) const;
    int32_t GetInt32Member(const std::string &name) const;
    int64_t GetInt64Member(const std::string &name) const;

    std::string albumUri_;
    std::string typeMask_;
    ResultNapiType resultNapiType_;
    int32_t count_;
    std::unordered_map<std::string, std::variant<int32_t, int64_t, std::string>> member_;
    std::mutex openStatusMapMutex_;
    std::shared_ptr<std::unordered_map<int32_t, int32_t>> openStatusMap_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_FILE_ASSET_H_
