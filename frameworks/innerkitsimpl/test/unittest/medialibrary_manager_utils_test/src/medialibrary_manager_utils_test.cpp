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

#include <thread>
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

void MediaLibraryManagerUtilsTest::SetUpTestCase(void) {}

void MediaLibraryManagerUtilsTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryManagerUtilsTest::SetUp() {}

void MediaLibraryManagerUtilsTest::TearDown(void) {}

HWTEST_F(MediaLibraryManagerUtilsTest, medialib_IsNumber_test_001, TestSize.Level1)
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

HWTEST_F(MediaLibraryManagerUtilsTest, medialib_GetOperationType_test_001, TestSize.Level1)
{
    string uri = "medialib_GetOperationType_test_001/test";
    string ret = MediaLibraryDataManagerUtils::GetOperationType(uri);
    EXPECT_EQ(ret, "test");
    uri = "medialib_GetOperationType_test_001";
    ret = MediaLibraryDataManagerUtils::GetOperationType(uri);
    EXPECT_EQ(ret, "");
}

HWTEST_F(MediaLibraryManagerUtilsTest, medialib_GetDisPlayNameFromPath_test_001, TestSize.Level1)
{
    string path = "medialib_GetDisPlayNameFromPath_test_001/test";
    string ret = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(path);
    EXPECT_EQ(ret, "test");
    path = "medialib_GetDisPlayNameFromPath_test_001";
    ret = MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(path);
    EXPECT_EQ(ret, "");
}

HWTEST_F(MediaLibraryManagerUtilsTest, medialib_ObtionCondition_test_001, TestSize.Level1)
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