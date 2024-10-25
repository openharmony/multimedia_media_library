/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H
#define OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H

#include <gtest/gtest.h>

#include "photo_album.h"

namespace OHOS::Media {
class AlbumCountCoverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class AlbumInfo {
public:
    AlbumInfo(int32_t count, std::string cover, int32_t hiddenCount, std::string hiddenCover, int32_t containsHidden)
        : count_(count), hiddenCount_(hiddenCount), containsHidden_(containsHidden),
        cover_(move(cover)), hiddenCover_(move(hiddenCover)) {}
    virtual ~AlbumInfo() = default;

    int32_t count_;
    int32_t hiddenCount_;
    int32_t containsHidden_;
    std::string cover_;
    std::string hiddenCover_;

    void CheckUserAlbum(const int32_t albumId) const;

    void CheckSystemAlbum(const int32_t subtype) const;
private:
    void CheckAlbum(const std::unique_ptr<PhotoAlbum> &album, bool hiddenOnly) const;
};
} // namespace OHOS::Media
#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H
