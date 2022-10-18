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
using namespace std;
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
    void SetAlbumName(const string albumName);
    void SetAlbumUri(const string albumUri);
    void SetAlbumTag(const string albumTag);
    void SetAlbumCapacity(const int32_t albumCapacity);
    void SetAlbumDateModified(const int64_t albumDateModified);
    void SetCategoryId(const int32_t categoryId);
    void SetCategoryName(const string categoryName);
    void SetCoverUri(const string coverUri);
    void SetTypeMask(const string &typeMask);
    void SetAlbumPrivateType(const PrivateAlbumType albumPrivateType);
    void SetResultNapiType(const ResultNapiType type);

    int32_t GetAlbumId() const;
    string GetAlbumName() const;
    string GetAlbumUri() const;
    string GetAlbumTag() const;
    int32_t GetAlbumCapacity() const;
    int64_t GetAlbumDateModified() const;
    int32_t GetCategoryId() const;
    string GetCategoryName() const;
    string GetCoverUri() const;
    string GetTypeMask() const;
    PrivateAlbumType GetAlbumPrivateType() const;
    ResultNapiType GetResultNapiType() const;

private:
    int32_t albumId_;
    std::string albumName_;
    string albumUri_;
    string albumTag_;
    PrivateAlbumType albumPrivateType_;
    int32_t albumCapacity_;
    int32_t categoryId_;
    int64_t albumDateModified_;
    string categoryName_;
    string coverUri_;
    string typeMask_;
    ResultNapiType resultNapiType_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_SMART_ALBUM_ASSET_H_
