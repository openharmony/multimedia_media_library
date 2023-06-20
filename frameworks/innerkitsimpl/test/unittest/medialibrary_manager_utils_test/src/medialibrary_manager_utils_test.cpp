/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "context.h"
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
    EXPECT_EQ(ret, "-1");
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
    EXPECT_EQ(ret, "test");
    uri = "test" + MEDIALIBRARY_MEDIA_PREFIX;
    ret = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    EXPECT_EQ(ret, "");
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
} // namespace Media
} // namespace OHOS