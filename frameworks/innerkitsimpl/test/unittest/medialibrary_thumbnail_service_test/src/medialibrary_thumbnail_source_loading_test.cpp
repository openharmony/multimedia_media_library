/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <thread>
#include "foundation/ability/form_fwk/test/mock/include/mock_single_kv_store.h"
#include "kvstore.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_thumbnail_source_loading_test.h"
#include "exif_utils.h"
#include "thumbnail_service.h"
#include "thumbnail_source_loading.h"
#include "media_file_utils.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "image_source.h"
#include "media_errors.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

void MediaLibraryThumbnailSourceLoaderTest::SetUpTestCase(void) {}

void MediaLibraryThumbnailSourceLoaderTest::TearDownTestCase(void) {}

void MediaLibraryThumbnailSourceLoaderTest::SetUp() {}

void MediaLibraryThumbnailSourceLoaderTest::TearDown(void) {}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_getLocalKeyFrameThumbnailPath_test, TestSize.Level0)
{
    Size desiredSize;
    ThumbnailData thumbnailData;
    SourceLoader sourceLoader(desiredSize, thumbnailData);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    Size targetSize;
    targetSize.width = 20;
    targetSize.height = 20;
    auto ret = sourceLoader.GeneratePictureSource(imageSource, targetSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_createImagePixelMap_test, TestSize.Level0)
{
    Size desiredSize;
    ThumbnailData thumbnailData;
    SourceLoader sourceLoader(desiredSize, thumbnailData);
    std::string path = "path";
    auto ret = sourceLoader.CreateImagePixelMap(path);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_generatePixelMapSource_test, TestSize.Level0)
{
    Size desiredSize;
    ThumbnailData thumbnailData;
    SourceLoader sourceLoader(desiredSize, thumbnailData);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    Size targetSize;
    targetSize.width = 20;
    targetSize.height = 20;
    Size sourceSize;
    sourceSize.width = 20;
    sourceSize.height = 20;
    auto ret = sourceLoader.GeneratePixelMapSource(imageSource, sourceSize, targetSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_isSizeAcceptable_test, TestSize.Level0)
{
    Size desiredSize;
    ThumbnailData thumbnailData;
    SourceLoader sourceLoader(desiredSize, thumbnailData);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ImageInfo imageInfo;
    imageSource->GetImageInfo(0, imageInfo);
    auto ret = sourceLoader.IsSizeAcceptable(imageSource, imageInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_localThumbSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/cloud/files";
    LocalThumbSource localThumbSource;
    int32_t error = 0;
    auto result = localThumbSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "");
    int32_t minSize = 349;
    auto ret = localThumbSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, false);
    minSize = 351;
    ret = localThumbSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_localLcdSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/cloud/files";
    LocalLcdSource localLcdSource;
    int32_t error = 0;
    auto result = localLcdSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "");
    int32_t minSize = 349;
    auto ret = localLcdSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, false);
    minSize = 351;
    ret = localLcdSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_localOriginSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/local/files";
    LocalOriginSource localOriginSource;
    int32_t error = 0;
    auto result = localOriginSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "");
    int32_t minSize = 349;
    auto ret = localOriginSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_cloudThumbSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/cloud/files";
    CloudThumbSource cloudThumbSource;
    int32_t error = 0;
    auto result = cloudThumbSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "");
    int32_t minSize = 0;
    auto ret = cloudThumbSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, false);
    minSize = 351;
    ret = cloudThumbSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_cloudLcdSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/cloud/files";
    CloudLcdSource cloudLcdSource;
    int32_t error = 0;
    auto result = cloudLcdSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "");
    int32_t minSize = 349;
    auto ret = cloudLcdSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, false);
    minSize = 351;
    ret = cloudLcdSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryThumbnailSourceLoaderTest, medialib_cloudOriginSource_test, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    thumbnailData.path = "/storage/cloud/files";
    CloudOriginSource cloudOriginSource;
    int32_t error = 0;
    auto result = cloudOriginSource.GetSourcePath(thumbnailData, error);
    EXPECT_EQ(result, "/storage/cloud/files");
    int32_t minSize = 349;
    auto ret = cloudOriginSource.IsSizeLargeEnough(thumbnailData, minSize);
    EXPECT_EQ(ret, true);
}
}
}