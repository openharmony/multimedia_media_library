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
#define EXPORT __attribute__ ((visibility ("default")))
/**
 * @brief Data class for album details
 *
 * @since 1.0
 * @version 1.0
 */
class SmartAlbumAsset {
public:
    EXPORT SmartAlbumAsset();
    EXPORT virtual ~SmartAlbumAsset();

    EXPORT void SetAlbumId(const int32_t albumId);
    EXPORT void SetAlbumName(const std::string &albumName);
    EXPORT void SetAlbumUri(const std::string &albumUri);
    EXPORT void SetAlbumTag(const std::string &albumTag);
    EXPORT void SetAlbumCapacity(const int32_t albumCapacity);
    EXPORT void SetAlbumDateModified(const int64_t albumDateModified);
    EXPORT void SetCategoryId(const int32_t categoryId);
    EXPORT void SetCategoryName(const std::string &categoryName);
    EXPORT void SetCoverUri(const std::string &coverUri);
    EXPORT void SetAlbumPrivateType(const PrivateAlbumType albumPrivateType);
    EXPORT void SetResultNapiType(const ResultNapiType type);
    EXPORT void SetDescription(const std::string &description);
    EXPORT void SetExpiredTime(const int32_t expiredTime);

    EXPORT int32_t GetAlbumId() const;
    EXPORT std::string GetAlbumName() const;
    EXPORT std::string GetAlbumUri() const;
    EXPORT std::string GetAlbumTag() const;
    EXPORT int32_t GetAlbumCapacity() const;
    EXPORT int64_t GetAlbumDateModified() const;
    EXPORT int32_t GetCategoryId() const;
    EXPORT std::string GetCategoryName() const;
    EXPORT std::string GetCoverUri() const;
    EXPORT PrivateAlbumType GetAlbumPrivateType() const;
    EXPORT ResultNapiType GetResultNapiType() const;
    EXPORT std::string GetDescription() const;
    EXPORT int32_t GetExpiredTime() const;

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
