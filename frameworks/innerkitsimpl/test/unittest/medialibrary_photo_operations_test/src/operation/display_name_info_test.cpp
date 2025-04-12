/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "DisplayNameInfoTest"

#include "display_name_info_test.h"

#include <string>

#include "display_name_info.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
void DisplayNameInfoTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DisplayNameInfoTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void DisplayNameInfoTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DisplayNameInfoTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

std::string DisplayNameInfoTest::GetTestTitle(int32_t length)
{
    string title = "";
    for (int i = 0; i < length; i++) {
        title += "1";
    }
    return title;
}

HWTEST_F(DisplayNameInfoTest, displayname_distinguish_non_burst_photo, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = "IMG_3025";
    const std::string extension = ".jpg";
    photoAssetInfo.displayName = title + extension;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    DisplayNameInfo displayNameInfo(photoAssetInfo);
    std::string displayName = displayNameInfo.ToString();
    EXPECT_EQ(displayName, photoAssetInfo.displayName);
    for (int32_t curr = 1; curr <= 10; curr++) {
        displayName = displayNameInfo.Next();
        EXPECT_EQ(displayName, title + "_" + std::to_string(curr) + extension);
    }
}

HWTEST_F(DisplayNameInfoTest, displayname_distinguish_burst_photo_without_index, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_20240222_135017_BURST004.jpg
    const std::string prefix = "IMG_";
    const int32_t yearMonthDay = 20240222;
    const int32_t hourMinuteSecond = 135017;
    const std::string suffix = "_BURST004.jpg";
    photoAssetInfo.displayName =
        prefix + std::to_string(yearMonthDay) + "_" + std::to_string(hourMinuteSecond) + suffix;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    DisplayNameInfo displayNameInfo(photoAssetInfo);
    std::string displayName = displayNameInfo.ToString();
    EXPECT_EQ(displayName, photoAssetInfo.displayName);
    for (int32_t curr = 1; curr <= 10; curr++) {
        displayName = displayNameInfo.Next();
        EXPECT_EQ(displayName,
            prefix + std::to_string(yearMonthDay) + "_" + std::to_string(hourMinuteSecond + curr) + suffix);
    }
}

HWTEST_F(DisplayNameInfoTest, displayname_distinguish_burst_photo_with_index, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_20240222_135017_9_BURST004.jpg
    const std::string prefix = "IMG_";
    const int32_t yearMonthDay = 20240222;
    const int32_t hourMinuteSecond = 135017;
    const std::string suffix = "_9_BURST004.jpg";
    photoAssetInfo.displayName =
        prefix + std::to_string(yearMonthDay) + "_" + std::to_string(hourMinuteSecond) + suffix;
    photoAssetInfo.displayName = "IMG_20240222_135017_9_BURST004.jpg";
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    DisplayNameInfo displayNameInfo(photoAssetInfo);
    std::string displayName = displayNameInfo.ToString();
    EXPECT_EQ(displayName, photoAssetInfo.displayName);
    for (int32_t curr = 1; curr <= 10; curr++) {
        displayName = displayNameInfo.Next();
        EXPECT_EQ(displayName,
            prefix + std::to_string(yearMonthDay) + "_" + std::to_string(hourMinuteSecond + curr) + suffix);
    }
}

HWTEST_F(DisplayNameInfoTest, displayname_max_length_limit_255, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = this->GetTestTitle(300);
    const std::string extension = ".jpg";
    photoAssetInfo.displayName = title + extension;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    DisplayNameInfo displayNameInfo(photoAssetInfo);
    std::string displayName = displayNameInfo.ToString();
    EXPECT_EQ(displayName.size(), 255);
    std::string expectedDisplayName =
        title.substr(0, std::min<int32_t>(photoAssetInfo.displayName.size(), 255) - extension.size()) + extension;
    EXPECT_EQ(displayName, expectedDisplayName);
}

HWTEST_F(DisplayNameInfoTest, displayname_max_length_limit_255_with_index, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = this->GetTestTitle(300);
    const std::string extension = ".jpg";
    photoAssetInfo.displayName = title + extension;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    DisplayNameInfo displayNameInfo(photoAssetInfo);
    std::string displayName = displayNameInfo.ToString();
    EXPECT_EQ(displayName.size(), 255);
    for (int32_t curr = 1; curr <= 10; curr++) {
        displayName = displayNameInfo.Next();
        EXPECT_EQ(displayName.size(), 255);
    }
}
}  // namespace OHOS::Media