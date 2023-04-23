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
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_manager_utils_test.h"
#include "appkit/ability_runtime/context/context.h"
#include "ability_context_impl.h"
#include "medialibrary_db_const.h"

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

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetFileName_test_001, TestSize.Level0)
{
    string path = "medialib_GetFileName_test_001/test";
    string dirPath = MediaLibraryDataManagerUtils::GetFileName(path);
    EXPECT_EQ("test", dirPath);
    path = "medialib_GetFileName_test_001";
    dirPath = MediaLibraryDataManagerUtils::GetFileName(path);
    EXPECT_EQ("", dirPath);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetParentPath_test_001, TestSize.Level0)
{
    string path = "medialib_GetParentPath_test_001/test";
    string dirPath = MediaLibraryDataManagerUtils::GetParentPath(path);
    EXPECT_EQ("medialib_GetParentPath_test_001", dirPath);
    path = "medialib_GetParentPath_test_001";
    dirPath = MediaLibraryDataManagerUtils::GetParentPath(path);
    EXPECT_EQ("", dirPath);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsNumber_test_001, TestSize.Level0)
{
    string srt = "";
    bool ret = MediaLibraryDataManagerUtils::IsNumber(srt);
    EXPECT_EQ(ret, false);
    srt = "medialib_IsNumber_test_001";
    ret = MediaLibraryDataManagerUtils::IsNumber(srt);
    EXPECT_EQ(ret, false);
    srt = "1";
    ret = MediaLibraryDataManagerUtils::IsNumber(srt);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetFileTitle_test_001, TestSize.Level0)
{
    string displayName = "";
    string ret = MediaLibraryDataManagerUtils::GetFileTitle(displayName);
    EXPECT_EQ(ret, "");
    displayName = "medialib.test";
    ret = MediaLibraryDataManagerUtils::GetFileTitle(displayName);
    EXPECT_NE(ret, "");
    displayName = "medialib.";
    ret = MediaLibraryDataManagerUtils::GetFileTitle(displayName);
    EXPECT_NE(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetOperationType_test_001, TestSize.Level0)
{
    string uri = "medialib_GetOperationType_test_001/test";
    string ret = MediaLibraryDataManagerUtils::GetOperationType(uri);
    EXPECT_EQ(ret, "test");
    uri = "medialib_GetOperationType_test_001";
    ret = MediaLibraryDataManagerUtils::GetOperationType(uri);
    EXPECT_EQ(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetIdFromUri_test_001, TestSize.Level0)
{
    string uri = "medialib_GetIdFromUri_test_001/Test";
    string ret = MediaLibraryDataManagerUtils::GetIdFromUri(uri);
    EXPECT_EQ(ret, "Test");
    uri = "medialib_GetIdFromUri_test_001";
    ret = MediaLibraryDataManagerUtils::GetIdFromUri(uri);
    EXPECT_EQ(ret, "-1");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetNetworkIdFromUri_test_001, TestSize.Level0)
{
    string uri = "";
    string ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "");
    uri = "medialib_GetNetworkIdFromUri_test_001";
    ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "");
    uri = MEDIALIBRARY_DATA_ABILITY_PREFIX;
    ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "");
    uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + "test";
    ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "");
    uri = "test" + MEDIALIBRARY_MEDIA_PREFIX;
    ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "e:");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetDisPlayNameFromPath_test_001, TestSize.Level0)
{
    string path = "medialib_GetDisPlayNameFromPath_test_001/test";
    string ret = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(path);
    EXPECT_EQ(ret, "test");
    path = "medialib_GetDisPlayNameFromPath_test_001";
    ret = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(path);
    EXPECT_EQ(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SplitKeyValue_test_001, TestSize.Level0)
{
    string key = "";
    string value = "";
    string keyValue = "medialib_SplitKeyValue_test_001";
    MediaLibraryDataManagerUtils::SplitKeyValue(keyValue, key, value);
    EXPECT_EQ(value, "");
    keyValue = "medialib_SplitKeyValue_test_001=test";
    key = "key";
    value = "value";
    MediaLibraryDataManagerUtils::SplitKeyValue(keyValue, key, value);
    EXPECT_EQ(value, "test");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ObtionCondition_test_001, TestSize.Level0)
{
    std::vector<string> whereArgs;
    whereArgs.push_back("medialib_ObtionCondition_test_001");
    string strQueryCondition = "medialib";
    string ret = MediaLibraryDataManagerUtils::ObtionCondition(strQueryCondition, whereArgs);
    EXPECT_EQ(ret, "medialib");
    strQueryCondition = "medialib_?_test";
    ret = MediaLibraryDataManagerUtils::ObtionCondition(strQueryCondition, whereArgs);
    strQueryCondition = "medialib_?_test";
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_RemoveTypeValueFromUri_test_001, TestSize.Level0)
{
    string url = "medialib_RemoveTypeValueFromUri_test_001";
    MediaLibraryDataManagerUtils::RemoveTypeValueFromUri(url);
    EXPECT_EQ("medialib_RemoveTypeValueFromUri_test_001", url);
    url = "medialib_RemoveTypeValueFromUri_test_001_#_test";
    MediaLibraryDataManagerUtils::RemoveTypeValueFromUri(url);
    EXPECT_EQ("medialib_RemoveTypeValueFromUri_test_001_", url);
}


}// namespace Media
} // namespace OHOS