/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaAssetTest"

#include "file_asset.h"
#include "media_asset_test.h"
#include "media_asset_base_capi.h"
#include "media_asset_manager_capi.h"
#include "media_asset_capi.h"
#include "media_asset_impl.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void MediaAssetTest::SetUpTestCase(void) {}

void MediaAssetTest::TearDownTestCase(void) {}

void MediaAssetTest::SetUp(void) {}

void MediaAssetTest::TearDown(void) {}

void MediaAssetTest::FreeCharPointer(const char *freeCharPointer)
{
    if (freeCharPointer != nullptr) {
        freeCharPointer = nullptr;
    }
}

HWTEST_F(MediaAssetTest, mediaAsset_GetUri_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    const char *uri = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(uri);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetUri_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDisplayName_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    const char *displayName = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(displayName);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDisplayName_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetSize_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t size = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(mediaAsset, &size);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetSize_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t size = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(nullptr, &size);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetSize(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModifiedMs_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t dateModifiedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModifiedMs_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t dateModifiedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModifiedMs(nullptr, &dateModifiedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateModifiedMs(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetWidth_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t width = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetWidth(mediaAsset, &width);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetWidth_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t width = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetWidth(nullptr, &width);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetWidth(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetHeight_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t height = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetHeight(mediaAsset, &height);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetHeight_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t height = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetHeight(nullptr, &height);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetHeight(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetOrientation_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetOrientation_test_002, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Release_test_001, TestSize.Level0)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto* mediaAsset = new OH_MediaAsset(fileAsset);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(nullptr), MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}
} // namespace Media
} // namespace OHOS
