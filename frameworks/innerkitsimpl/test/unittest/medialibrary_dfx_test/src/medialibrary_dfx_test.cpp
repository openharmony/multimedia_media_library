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

#include "medialibrary_dfx_test.h"

#include <string>

#include "dfx_manager.h"
#include "dfx_const.h"
#include "dfx_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryDfxTest::SetUpTestCase(void)
{
    DfxManager::GetInstance();
}
void MediaLibraryDfxTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryDfxTest::SetUp() {}

void MediaLibraryDfxTest::TearDown(void) {}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_common_image_test, TestSize.Level0)
{
    std::string path = "common.jpg";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 1;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, COMMON_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_png_test, TestSize.Level0)
{
    std::string path = "other.png";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 1;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, OTHER_FORMAT_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_big_image_test, TestSize.Level0)
{
    std::string path = "big_image.jpg";
    int32_t width = 10000;
    int32_t height = 10000;
    int32_t mediaType = 1;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, BIG_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_common_video_test, TestSize.Level0)
{
    std::string path = "common.mp4";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 2;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, COMMON_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_8K_video_test, TestSize.Level0)
{
    std::string path = "8K.mp4";
    int32_t width = 7680;
    int32_t height = 7680;
    int32_t mediaType = 2;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, BIG_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_safe_path_test, TestSize.Level0)
{
    std::string path = "/storage/cloud/files/DCIM/123";
    std::string safePath = DfxUtils::GetSafePath(path);
    ASSERT_TRUE(safePath == "*DCIM");
}
} // namespace Media
} // namespace OHOS