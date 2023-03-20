/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FileExtUnitTest"
#include "medialibrary_uri_test.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"
#define private public
#include "thumbnail_uri_utils.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void MediaLibraryExtUnitTest::SetUpTestCase(void) {}

void MediaLibraryExtUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ParseFileUri_test_001, TestSize.Level0)
{
    string uriString = "";
    string outFileId = "";
    string ourNetworkId = "";
    bool ret = ThumbnailUriUtils::ParseFileUri(uriString, outFileId, ourNetworkId);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ParseThumbnailInfo_test_001, TestSize.Level0)
{
    string uriString = "";
    string outFileId = "";
    Size outSize;
    string ourNetworkId = "";
    bool ret = ThumbnailUriUtils::ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
    EXPECT_EQ(ret, false);
    uriString = "ParseThumbnailInfo?" + THUMBNAIL_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL;
    ret = ThumbnailUriUtils::ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
    EXPECT_EQ(ret, false);
    uriString = "ParseThumbnailInfo?=" + MEDIA_DATA_DB_THUMBNAIL + "&" + THUMBNAIL_WIDTH + "=&" +
        THUMBNAIL_HEIGHT + "=";
    ret = ThumbnailUriUtils::ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
    EXPECT_EQ(ret, false);
    uriString = "ParseThumbnailInfo?test=" + MEDIA_DATA_DB_THUMBNAIL + "&" + THUMBNAIL_WIDTH + "=&" +
        THUMBNAIL_HEIGHT + "=";
    ret = ThumbnailUriUtils::ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
    EXPECT_EQ(ret, false);
    uriString = "ParseThumbnailInfo?" + THUMBNAIL_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        THUMBNAIL_WIDTH + "=1&" + THUMBNAIL_HEIGHT + "=1";
    ret = ThumbnailUriUtils::ParseThumbnailInfo(uriString, outFileId, outSize, ourNetworkId);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ParseThumbnailInfo_test_002, TestSize.Level0)
{
    string uri = "";
    bool ret = ThumbnailUriUtils::ParseThumbnailInfo(uri);
    EXPECT_EQ(ret, false);
    uri = "ParseThumbnailInfo?" + THUMBNAIL_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" + THUMBNAIL_WIDTH +
        "=1&" + THUMBNAIL_HEIGHT + "=1";
    ret = ThumbnailUriUtils::ParseThumbnailInfo(uri);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SplitKeyValue_test_001, TestSize.Level0)
{
    string keyValue = "SplitKeyValue=SplitKeyValue";
    string key = "";
    string value = "";
    ThumbnailUriUtils::SplitKeyValue(keyValue, key, value);
    EXPECT_EQ(key, "SplitKeyValue");
    string keyValueTest = "SplitKeyValue";
    string testKey = "";
    ThumbnailUriUtils::SplitKeyValue(keyValueTest, testKey, value);
    EXPECT_EQ(testKey, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SplitKeys_test_001, TestSize.Level0)
{
    string query = "";
    vector<string> keys;
    ThumbnailUriUtils::SplitKeys(query, keys);
    EXPECT_EQ(keys.begin(), keys.end());
    string queryTest = "SplitKeys&SplitKeys";
    ThumbnailUriUtils::SplitKeys(queryTest, keys);
    EXPECT_NE(keys.begin(), keys.end());
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsNumber_test_001, TestSize.Level0)
{
    bool ret = ThumbnailUriUtils::IsNumber("");
    EXPECT_EQ(ret, false);
    string strTest = "test";
    ret = ThumbnailUriUtils::IsNumber(strTest);
    EXPECT_EQ(ret, false);
    string str = "1";
    ret = ThumbnailUriUtils::IsNumber(str);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ParseThumbnailKey_test_001, TestSize.Level0)
{
    string outAction = "";
    string value  = "";
    int outWidth = 0;
    int outHeight = 0;
    ThumbnailUriUtils::ParseThumbnailKey("", value, outAction, outWidth, outHeight);
    EXPECT_EQ(value, "");
    string key = THUMBNAIL_OPERN_KEYWORD;
    ThumbnailUriUtils::ParseThumbnailKey(key, value, outAction, outWidth, outHeight);
    EXPECT_EQ(outAction, value);
    ThumbnailUriUtils::ParseThumbnailKey(THUMBNAIL_WIDTH, value, outAction, outWidth, outHeight);
    EXPECT_EQ(outWidth, 0);
    string valueTest = "1";
    ThumbnailUriUtils::ParseThumbnailKey(THUMBNAIL_WIDTH, valueTest, outAction, outWidth, outHeight);
    EXPECT_EQ(outWidth, 1);
    ThumbnailUriUtils::ParseThumbnailKey(THUMBNAIL_HEIGHT, value, outAction, outWidth, outHeight);
    EXPECT_EQ(outHeight, 0);
    ThumbnailUriUtils::ParseThumbnailKey(THUMBNAIL_HEIGHT, valueTest, outAction, outWidth, outHeight);
    EXPECT_EQ(outHeight, 1);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetNetworkIdFromUri_test_001, TestSize.Level0)
{
    string deviceId = ThumbnailUriUtils::GetNetworkIdFromUri("");
    EXPECT_EQ(deviceId, "");
    deviceId = ThumbnailUriUtils::GetNetworkIdFromUri("GetNetworkIdFromUri");
    EXPECT_EQ(deviceId, "");
    deviceId = ThumbnailUriUtils::GetNetworkIdFromUri(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    EXPECT_EQ(deviceId, "");
    deviceId = ThumbnailUriUtils::GetNetworkIdFromUri(MEDIALIBRARY_DATA_ABILITY_PREFIX + "test");
    EXPECT_EQ(deviceId, "");
    deviceId = ThumbnailUriUtils::GetNetworkIdFromUri(MEDIALIBRARY_DATA_ABILITY_PREFIX + "Uri/test");
    EXPECT_EQ(deviceId, "Uri");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetIdFromUri_test_001, TestSize.Level0)
{
    string rowNum = ThumbnailUriUtils::GetIdFromUri("");
    EXPECT_EQ(rowNum, "-1");
    rowNum = ThumbnailUriUtils::GetIdFromUri("GetIdFromUri/test");
    EXPECT_EQ(rowNum, "test");
}

}// namespace Media
} // namespace OHOS