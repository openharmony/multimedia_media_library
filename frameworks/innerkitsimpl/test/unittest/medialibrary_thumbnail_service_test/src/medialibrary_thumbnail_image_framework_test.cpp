/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_thumbnail_image_framework_test.h"

#include "medialibrary_errno.h"
#include "media_log.h"

#define private public
#define protected public
#include "thumbnail_image_framework_utils.h"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace Media {
const int32_t TEST_PIXELMAP_WIDTH_AND_HEIGHT = 100;

void MediaLibraryThumbnailImageFrameworkTest::SetUpTestCase(void) {}

void MediaLibraryThumbnailImageFrameworkTest::TearDownTestCase(void) {}

void MediaLibraryThumbnailImageFrameworkTest::SetUp() {}

void MediaLibraryThumbnailImageFrameworkTest::TearDown(void) {}

std::shared_ptr<PixelMap> CreateTestPixelMap(PixelFormat format, bool useDMA)
{
    InitializationOptions opts;
    opts.size.width = TEST_PIXELMAP_WIDTH_AND_HEIGHT;
    opts.size.height = TEST_PIXELMAP_WIDTH_AND_HEIGHT;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDMA;
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    return pixelMap;
}

std::shared_ptr<Picture> CreateTestPicture(std::shared_ptr<PixelMap> pixelMap, std::shared_ptr<PixelMap> gainMap)
{
    if (pixelMap == nullptr) {
        return nullptr;
    }

    auto sourcePtr = Picture::Create(pixelMap);
    std::shared_ptr<Picture> picture = std::move(sourcePtr);
    if (gainMap == nullptr) {
        return picture;
    }

    Size gainMapSize = {gainMap->GetWidth(), gainMap->GetHeight()};
    auto auxiliaryPicturePtr = AuxiliaryPicture::Create(gainMap, AuxiliaryPictureType::GAINMAP, gainMapSize);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = std::move(auxiliaryPicturePtr);
    CHECK_AND_RETURN_RET_LOG(auxiliaryPicture != nullptr, nullptr, "Create auxiliaryPicture failed");
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    return picture;
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, IsYuvPixelMap_test_001, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    bool isYuv = ThumbnailImageFrameWorkUtils::IsYuvPixelMap(pixelMap);
    EXPECT_EQ(isYuv, false);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, IsYuvPixelMap_test_002, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::NV21, false);
    ASSERT_NE(pixelMap, nullptr);
    bool isYuv = ThumbnailImageFrameWorkUtils::IsYuvPixelMap(pixelMap);
    EXPECT_EQ(isYuv, true);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, IsYuvPixelMap_test_003, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    ASSERT_NE(pixelMap, nullptr);
    bool isYuv = ThumbnailImageFrameWorkUtils::IsYuvPixelMap(pixelMap);
    EXPECT_EQ(isYuv, false);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPictureSource_test_001, TestSize.Level0)
{
    std::shared_ptr<Picture> picture = nullptr;
    std::shared_ptr<Picture> copyPicture = ThumbnailImageFrameWorkUtils::CopyPictureSource(picture);
    EXPECT_EQ(copyPicture, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPictureSource_test_002, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::NV21, false);
    std::shared_ptr<PixelMap> gainMap = nullptr;
    std::shared_ptr<Picture> picture = CreateTestPicture(pixelMap, gainMap);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<Picture> copyPicture = ThumbnailImageFrameWorkUtils::CopyPictureSource(picture);
    EXPECT_EQ(copyPicture, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPictureSource_test_003, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<PixelMap> gainMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<Picture> picture = CreateTestPicture(pixelMap, gainMap);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<Picture> copyPicture = ThumbnailImageFrameWorkUtils::CopyPictureSource(picture);
    EXPECT_NE(copyPicture, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPixelMapSource_test_001, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    std::shared_ptr<PixelMap> copyPixelMap = ThumbnailImageFrameWorkUtils::CopyPixelMapSource(pixelMap);
    EXPECT_EQ(copyPixelMap, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPixelMapSource_test_002, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    ASSERT_NE(pixelMap, nullptr);
    std::shared_ptr<PixelMap> copyPixelMap = ThumbnailImageFrameWorkUtils::CopyPixelMapSource(pixelMap);
    EXPECT_NE(copyPixelMap, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyPixelMapSource_test_003, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::NV21, false);
    ASSERT_NE(pixelMap, nullptr);
    std::shared_ptr<PixelMap> copyPixelMap = ThumbnailImageFrameWorkUtils::CopyPixelMapSource(pixelMap);
    EXPECT_NE(copyPixelMap, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyNormalPixelmap_test_001, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    ASSERT_NE(pixelMap, nullptr);
    std::shared_ptr<PixelMap> copyPixelMap = ThumbnailImageFrameWorkUtils::CopyNormalPixelmap(pixelMap);
    EXPECT_NE(copyPixelMap, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, CopyYuvPixelmap_test_001, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::NV21, false);
    ASSERT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC, false);
    std::shared_ptr<PixelMap> copyPixelMap = ThumbnailImageFrameWorkUtils::CopyYuvPixelmap(pixelMap);
    EXPECT_NE(copyPixelMap, nullptr);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, GetPictureOrientation_test_001, TestSize.Level0)
{
    std::shared_ptr<Picture> picture = nullptr;
    int32_t orientation = 0;
    int32_t err = ThumbnailImageFrameWorkUtils::GetPictureOrientation(picture, orientation);
    EXPECT_EQ(err, E_ERR);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, GetPictureOrientation_test_002, TestSize.Level0)
{
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<PixelMap> gainMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<Picture> picture = CreateTestPicture(pixelMap, gainMap);
    ASSERT_NE(picture, nullptr);
    int32_t orientation = 0;
    int32_t err = ThumbnailImageFrameWorkUtils::GetPictureOrientation(picture, orientation);
    EXPECT_NE(err, E_OK);
}
} // namespace Media
} // namespace OHOS