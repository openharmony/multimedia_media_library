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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_NATIVE_ALBUM_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_NATIVE_ALBUM_ASSET_H_

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
using namespace std;
/**
 * @brief Data class for album details
 *
 * @since 1.0
 * @version 1.0
 */
class NativeAlbumAsset {
public:
    NativeAlbumAsset();
    virtual ~NativeAlbumAsset();

    void SetAlbumId(const int32_t albumId);
    void SetAlbumName(const string albumName);
    void SetAlbumUri(const string albumUri);
    void SetAlbumDateModified(const int64_t albumDateModified);
    void SetCount(const int32_t count);
    void SetAlbumRelativePath(const string albumRelativePath);
    void SetCoverUri(const string coverUri);
    void SetAlbumPath(const string albumPath);
    void SetAlbumVirtual(const bool albumVirtual);
    int32_t GetAlbumId() const;
    string GetAlbumName() const;
    string GetAlbumUri() const;
    int64_t GetAlbumDateModified() const;
    int32_t GetCount() const;
    string GetAlbumRelativePath() const;
    string GetCoverUri() const;
    string GetAlbumPath() const;
    bool GetAlbumVirtual() const;
    bool CreateAlbumAsset();
    bool DeleteAlbumAsset(const std::string &albumUri);
    bool ModifyAlbumAsset(const std::string &albumUri);

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
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_NATIVE_ALBUM_ASSET_H_
