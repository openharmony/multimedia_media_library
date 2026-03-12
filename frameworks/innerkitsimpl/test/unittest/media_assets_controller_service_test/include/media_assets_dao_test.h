/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef MEDIA_ASSETS_DAO_TEST_H
#define MEDIA_ASSETS_DAO_TEST_H

#include <gtest/gtest.h>
#include "media_assets_dao.h"
#include "medialibrary_rdbstore.h"
#include "asset_accurate_refresh.h"

namespace OHOS {
namespace Media {
using namespace Common;
class MediaAssetsDaoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<MediaAssetsDao> mediaAssetsDao_ = nullptr;
    std::shared_ptr<MediaLibraryRdbStore> rdbStore_ = nullptr;
    std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh_ = nullptr;

    static constexpr int32_t TEST_FILE_ID_1 = 1001;
    static constexpr int32_t TEST_FILE_ID_2 = 1002;
    static constexpr int32_t TEST_ALBUM_ID = 2001;
    static constexpr int32_t TEST_FILE_SIZE = 1024000;
    static constexpr int32_t TEST_MEDIA_TYPE_IMAGE = 1;
    static constexpr int32_t TEST_MEDIA_TYPE_VIDEO = 2;
    static constexpr int32_t TEST_ORIENTATION = 0;

    void InitDatabase();
    void CreateTestPhotosTable();
    void CreateTestPhotoAlbumTable();
    void CreateTestPhotoExtTable();
    void InsertTestPhoto(int32_t fileId, const std::string &displayName, int32_t mediaType);
    void InsertTestAlbum(int32_t albumId, const std::string &albumName, const std::string &lpath);
    void InsertTestPhotoExt(const std::string &fileId);
    void CleanTables();
};
}  // namespace Media
}  // namespace OHOS
#endif  // MEDIA_ASSETS_CONTROLLER_TEST_H