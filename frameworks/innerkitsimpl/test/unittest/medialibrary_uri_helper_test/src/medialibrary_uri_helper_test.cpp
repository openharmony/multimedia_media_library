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
#include "medialibrary_uri_helper_test.h"
#define private public
#include "uri_helper.h"
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

HWTEST_F(MediaLibraryExtUnitTest, medialib_uriType_test_001, TestSize.Level0)
{
    string_view test = "uriType";
    UriHelper uriHelper(test);
    uint8_t ret = uriHelper.UriType();
    EXPECT_NE(ret, UriHelper::URI_TYPE_HTTP);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_formattedUri_test_001, TestSize.Level0)
{
    string_view test = "FormattedUri";
    UriHelper uriHelper(test);
    string ret = uriHelper.FormattedUri();
    EXPECT_NE(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_accessCheck_test_001, TestSize.Level0)
{
    uint8_t flag = 0;
    string_view test = "AccessCheck";
    string_view rhsTest = "accessCheck";
    UriHelper uriHelper(test);
    UriHelper rhs(rhsTest);
    rhs.type_ = UriHelper::URI_TYPE_UNKNOWN;
    uriHelper.Swap(move(rhs));
    bool ret = uriHelper.AccessCheck(flag);
    EXPECT_EQ(ret, false);
    rhs.type_ = UriHelper::URI_TYPE_FILE;
    uriHelper.Swap(move(rhs));
    ret = uriHelper.AccessCheck(flag);
    EXPECT_EQ(ret, false);
    rhs.type_ = UriHelper::URI_TYPE_FD;
    uriHelper.Swap(move(rhs));
    ret = uriHelper.AccessCheck(flag);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_parseFdUri_test_001, TestSize.Level0)
{
    int32_t fd = 0;
    int64_t offset = 0;
    int64_t size = 0;
    string_view rhsTest = "parseFdUri";
    string_view test = "ParseFdUri";
    UriHelper uriHelper(test);
    UriHelper rhs(rhsTest);
    rhs.type_ = UriHelper::URI_TYPE_UNKNOWN;
    uriHelper.Swap(move(rhs));
    bool ret = uriHelper.ParseFdUri(fd, offset, size);
    EXPECT_EQ(ret, false);
    rhs.type_ = UriHelper::URI_TYPE_FD;
    uriHelper.Swap(move(rhs));
    ret = uriHelper.ParseFdUri(fd, offset, size);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_formatMeForUri_test_001, TestSize.Level0)
{
    string_view uri = "//storage/media/local/files";
    string_view rhsTest = "formatMeForUri";
    string_view test = "formatMeForUri";
    UriHelper uriHelper(test);
    uriHelper.FormatMeForUri(uri);
    uint8_t ret = uriHelper.UriType();
    EXPECT_EQ(ret, UriHelper::URI_TYPE_UNKNOWN);
    UriHelper rhs(rhsTest);
    rhs.type_ = UriHelper::URI_TYPE_UNKNOWN;
    rhs.formattedUri_ = "";
    uriHelper.Swap(move(rhs));
    uriHelper.FormatMeForUri(uri);
    ret = uriHelper.UriType();
    EXPECT_NE(ret, UriHelper::URI_TYPE_HTTP);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_formatMeForFd_test_001, TestSize.Level0)
{
    string_view rhsTest = "FormatMeForFd";
    string_view test = "FormatMeForFd";
    UriHelper uriHelper(test);
    uriHelper.FormatMeForFd();
    uint8_t ret = uriHelper.UriType();
    EXPECT_EQ(ret, UriHelper::URI_TYPE_UNKNOWN);
    UriHelper rhs(rhsTest);
    rhs.type_ = UriHelper::URI_TYPE_UNKNOWN;
    rhs.formattedUri_ = "";
    uriHelper.Swap(move(rhs));
    uriHelper.FormatMeForFd();
    ret = uriHelper.UriType();
    EXPECT_EQ(ret, UriHelper::URI_TYPE_FD);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_parseFdUri_test_002, TestSize.Level0)
{
    string_view test = "ParseFdUri";
    UriHelper uriHelper(test);
    string_view uri = "";
    bool ret = uriHelper.ParseFdUri(uri);
    EXPECT_EQ(ret, false);
    uri = "?&";
    ret = uriHelper.ParseFdUri(uri);
    EXPECT_EQ(ret, false);
    uri = "ParseFdUri?&";
    ret = uriHelper.ParseFdUri(uri);
    EXPECT_EQ(ret, false);
    uri = "ParseFdUri?&test";
    ret = uriHelper.ParseFdUri(uri);
    EXPECT_EQ(ret, false);
    uri = "ParseFdUri?info&test";
    ret = uriHelper.ParseFdUri(uri);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_correctFdParam_test_001, TestSize.Level0)
{
    string_view rhsTest = "CorrectFdParam";
    string_view test = "CorrectFdParam";
    UriHelper uriHelper(test);
    bool ret = uriHelper.CorrectFdParam();
    EXPECT_EQ(ret, false);
    UriHelper rhs(rhsTest);
    rhs.fd_ = 0;
    uriHelper.Swap(move(rhs));
    ret = uriHelper.CorrectFdParam();
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Copy_test_001, TestSize.Level0)
{
    string_view rhsTest = "CorrectFdParam";
    string_view test = "CorrectFdParam";
    UriHelper uriHelper(test);
    UriHelper rhs(rhsTest);
    rhs.type_ = UriHelper::URI_TYPE_HTTP;
    rhs.offset_ = 0;
    rhs.size_ = 0;
    rhs.fd_ = -1;
    rhs.formattedUri_ = "Copy";
    uriHelper.Copy(rhs);
    uint8_t ret = uriHelper.UriType();
    EXPECT_EQ(ret, UriHelper::URI_TYPE_HTTP);
}
} // namespace Media
} // namespace OHOS