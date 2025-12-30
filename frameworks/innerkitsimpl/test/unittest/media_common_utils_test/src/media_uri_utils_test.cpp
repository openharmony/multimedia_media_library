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

#include "media_uri_utils_test.h"

#include "media_uri_utils.h"


namespace OHOS {
namespace Media {
using namespace testing::ext;

void MediaUriUtilsUnitTest::SetUpTestCase(void) {}

void MediaUriUtilsUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaUriUtilsUnitTest::SetUp() {}

void MediaUriUtilsUnitTest::TearDown(void) {}

HWTEST_F(MediaUriUtilsUnitTest, medialib_append_key_value_test_001, TestSize.Level1)
{
    std::string uri;
    std::string key;
    std::string value;
    MediaUriUtils::AppendKeyValue(uri, key, value);
    EXPECT_EQ((uri == ""), false);
    EXPECT_EQ((key == ""), true);
    EXPECT_EQ((value == ""), true);

    uri = "datashare://test";
    key = "test";
    value = "testFile";
    MediaUriUtils::AppendKeyValue(uri, key, value);
    EXPECT_EQ((uri == ""), false);
    EXPECT_EQ((key == ""), false);
    EXPECT_EQ((value == ""), false);
    EXPECT_EQ((uri == "datashare://test?test=testFile"), true);
}

HWTEST_F(MediaUriUtilsUnitTest, medialib_create_asset_bucket_test_001, TestSize.Level1)
{
    int32_t bucketNum = -1;
    MediaUriUtils::CreateAssetBucket(-1, bucketNum);
    EXPECT_EQ(bucketNum, -1);
    MediaUriUtils::CreateAssetBucket(0, bucketNum);
    EXPECT_EQ(bucketNum, 16);
}

HWTEST_F(MediaUriUtilsUnitTest, medialib_get_uri_test_001, TestSize.Level1)
{
    std::string prefix1;
    std::string fileId1;
    std::string suffix1;
    std::string str1 = MediaUriUtils::GetUriByExtrConditions(prefix1, fileId1, suffix1);
    EXPECT_EQ(str1, "");

    std::string prefix2 = "test";
    std::string fileId2 = "1234567890";
    std::string suffix2 = "file";
    std::string str2 = MediaUriUtils::GetUriByExtrConditions(prefix2, fileId2, suffix2);
    EXPECT_EQ(str2, "test1234567890file");
}

HWTEST_F(MediaUriUtilsUnitTest, medialib_get_path_from_uri_test_001, TestSize.Level1)
{
    std::string fullUri = "file://media/Photo/1/IMG_123456789_000/test.jpg";
    std::string str1 = MediaUriUtils::GetPathFromUri(fullUri);
    EXPECT_EQ(str1, "");

    std::string uri;
    std::string str2 = MediaUriUtils::GetPathFromUri(uri);
    EXPECT_EQ(str2, "");
}

HWTEST_F(MediaUriUtilsUnitTest, medialib_get_file_id_test_001, TestSize.Level1)
{
    std::string fullUri = "file://media/Photo/1/IMG_123456789_000/test.jpg";
    int32_t id = MediaUriUtils::GetFileId(fullUri);
    EXPECT_EQ(id, 1);

    std::string uri;
    int32_t id2 = MediaUriUtils::GetFileId(uri);
    EXPECT_EQ(id2, -1);
}


} // namespace Media
} // namespace OHOS