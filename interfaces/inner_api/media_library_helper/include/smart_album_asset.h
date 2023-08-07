/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_SMART_ALBUM_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_SMART_ALBUM_ASSET_H_

#include <string>
#include <vector>

#include "medialibrary_type_const.h"
namespace OHOS {
namespace Media {
/**
 * @brief Data class for album details
 *
 * @since 1.0
 * @version 1.0
 */
class SmartAlbumAsset {
public:
    SmartAlbumAsset();
    virtual ~SmartAlbumAsset();

    void SetAlbumId(const int32_t albumId);
    void SetAlbumName(const std::string &albumName);
    void SetAlbumUri(const std::string &albumUri);
    void SetAlbumTag(const std::string &albumTag);
    void SetAlbumCapacity(const int32_t albumCapacity);
    void SetAlbumDateModified(const int64_t albumDateModified);
    void SetCategoryId(const int32_t categoryId);
    void SetCategoryName(const std::string &categoryName);
    void SetCoverUri(const std::string &coverUri);
    void SetAlbumPrivateType(const PrivateAlbumType albumPrivateType);
    void SetResultNapiType(const ResultNapiType type);
    void SetDescription(const std::string &description);
    void SetExpiredTime(const int32_t expiredTime);

    int32_t GetAlbumId() const;
    std::string GetAlbumName() const;
    std::string GetAlbumUri() const;
    std::string GetAlbumTag() const;
    int32_t GetAlbumCapacity() const;
    int64_t GetAlbumDateModified() const;
    int32_t GetCategoryId() const;
    std::string GetCategoryName() const;
    std::string GetCoverUri() const;
    PrivateAlbumType GetAlbumPrivateType() const;
    ResultNapiType GetResultNapiType() const;
    std::string GetDescription() const;
    int32_t GetExpiredTime() const;

private:
    int32_t albumId_;
    std::string albumName_;
    std::string albumUri_;
    std::string albumTag_;
    PrivateAlbumType albumPrivateType_;
    int32_t albumCapacity_;
    int32_t categoryId_;
    int64_t albumDateModified_;
    ResultNapiType resultNapiType_;
    std::string categoryName_;
    std::string coverUri_;
    std::string description_;
    int32_t expiredTime_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_SMART_ALBUM_ASSET_H_
