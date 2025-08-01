/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "exif_rotate_utils_test.h"

#include "exif_rotate_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void ExifRotateUtilsTest::SetUpTestCase(void) {}
void ExifRotateUtilsTest::TearDownTestCase(void) {}
void ExifRotateUtilsTest::SetUp(void) {}
void ExifRotateUtilsTest::TearDown(void) {}

HWTEST_F(ExifRotateUtilsTest, ConvertOrientationKeyToExifRotate_Test_001, TestSize.Level1)
{
    string key = "Top-left";
    int32_t exifRotate = 0;
    bool ret = ExifRotateUtils::ConvertOrientationKeyToExifRotate(key, exifRotate);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ExifRotateUtilsTest, ConvertOrientationKeyToExifRotate_Test_002, TestSize.Level1)
{
    string key = "Top-left-invalid";
    int32_t exifRotate = 0;
    bool ret = ExifRotateUtils::ConvertOrientationKeyToExifRotate(key, exifRotate);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ExifRotateUtilsTest, ConvertOrientationToExifRotate_Test_001, TestSize.Level1)
{
    int32_t orientation = 0;
    int32_t exifRotate = 0;
    bool ret = ExifRotateUtils::ConvertOrientationToExifRotate(orientation, exifRotate);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ExifRotateUtilsTest, ConvertOrientationToExifRotate_Test_002, TestSize.Level1)
{
    int32_t orientation = -1;
    int32_t exifRotate = 0;
    bool ret = ExifRotateUtils::ConvertOrientationToExifRotate(orientation, exifRotate);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ExifRotateUtilsTest, IsExifRotateWithFlip_Test_001, TestSize.Level1)
{
    int32_t exifRotate = static_cast<int32_t>(ExifRotateType::TOP_RIGHT);
    bool ret = ExifRotateUtils::IsExifRotateWithFlip(exifRotate);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ExifRotateUtilsTest, IsExifRotateWithFlip_Test_002, TestSize.Level1)
{
    int32_t exifRotate = static_cast<int32_t>(ExifRotateType::TOP_LEFT);
    bool ret = ExifRotateUtils::IsExifRotateWithFlip(exifRotate);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ExifRotateUtilsTest, GetFlipAndRotateInfo_Test_001, TestSize.Level1)
{
    FlipAndRotateInfo filpRotateInfo;
    int32_t exifRotate = static_cast<int32_t>(ExifRotateType::TOP_RIGHT);
    bool ret = ExifRotateUtils::GetFlipAndRotateInfo(exifRotate, filpRotateInfo);
    EXPECT_EQ(ret, true);
}

} // namespace Media
} // namespace OHOS