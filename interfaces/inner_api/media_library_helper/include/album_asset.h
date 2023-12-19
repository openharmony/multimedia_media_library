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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_ALBUM_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_ALBUM_ASSET_H_

#include <memory>
#include <string>
#include <vector>
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace std;
/**
 * @brief Data class for album details
 *
 * @since 1.0
 * @version 1.0
 */
class AlbumAsset {
public:
    EXPORT AlbumAsset();
    EXPORT virtual ~AlbumAsset();

    EXPORT void SetAlbumId(const int32_t albumId);
    EXPORT void SetAlbumName(const string albumName);
    EXPORT void SetAlbumUri(const string albumUri);
    EXPORT void SetAlbumDateModified(const int64_t albumDateModified);
    EXPORT void SetCount(const int32_t count);
    EXPORT void SetAlbumRelativePath(const string albumRelativePath);
    EXPORT void SetCoverUri(const string &coverUri);

    EXPORT void SetAlbumPath(const string albumPath);
    EXPORT void SetAlbumVirtual(const bool albumVirtual);
    EXPORT int32_t GetAlbumId() const;
    EXPORT string GetAlbumName() const;
    EXPORT string GetAlbumUri() const;
    EXPORT int64_t GetAlbumDateModified() const;
    EXPORT int32_t GetCount() const;
    EXPORT string GetAlbumRelativePath() const;
    EXPORT string GetCoverUri() const;
    EXPORT string GetAlbumPath() const;
    EXPORT bool GetAlbumVirtual() const;

    EXPORT void SetResultNapiType(const ResultNapiType type);
    EXPORT ResultNapiType GetResultNapiType() const;

#ifdef MEDIALIBRARY_COMPATIBILITY
    EXPORT void SetAlbumType(const PhotoAlbumType albumType);
    EXPORT void SetAlbumSubType(const PhotoAlbumSubType albumSubType);
    EXPORT PhotoAlbumType GetAlbumType() const;
    EXPORT PhotoAlbumSubType GetAlbumSubType() const;
#endif

private:
    int32_t albumId_;
    std::string albumName_;
    string albumUri_;
    int64_t albumDateModified_;
    int32_t count_;
    string albumRelativePath_;
    string coverUri_;

    string albumPath_;
    bool albumVirtual_;
    ResultNapiType resultNapiType_;

#ifdef MEDIALIBRARY_COMPATIBILITY
    PhotoAlbumType albumType_;
    PhotoAlbumSubType albumSubType_;
#endif
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_ALBUM_ASSET_H_
