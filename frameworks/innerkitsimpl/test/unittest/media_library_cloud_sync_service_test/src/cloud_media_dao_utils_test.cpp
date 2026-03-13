/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaCloudSync"

#include "cloud_media_dao_utils_test.h"

#include "media_log.h"
#include "cloud_media_dao_utils.h"
#include "cloud_media_photos_dao.h"
#include "cloud_mdkrecord_photos_vo.h"
#include "photos_po.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
using namespace testing::ext;

void CloudMediaDaoUtilsTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaDaoUtilsTest::SetUpTestCase");
}

void CloudMediaDaoUtilsTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaDaoUtilsTest::TearDownTestCase");
}

void CloudMediaDaoUtilsTest::SetUp()
{
    MEDIA_INFO_LOG("setup");
}

void CloudMediaDaoUtilsTest::TearDown(void) {}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_EmptyVector, TestSize.Level1)
{
    std::vector<std::string> values;
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_SingleElement, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("hello");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'hello'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_TwoElements, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("hello");
    values.emplace_back("world");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'hello','world'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_MultipleElements, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("a");
    values.emplace_back("b");
    values.emplace_back("c");
    values.emplace_back("d");
    values.emplace_back("e");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'a','b','c','d','e'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_EmptyString, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "''");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_SpecialCharacters, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("hello'world");
    values.emplace_back("test\"data");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'hello'world','test\"data'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_NumericStrings, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("123");
    values.emplace_back("456");
    values.emplace_back("789");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'123','456','789'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_EmptyVector, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_SingleElement, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("1");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "1");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_TwoElements, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("1");
    fileIds.emplace_back("2");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "1,2");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_MultipleElements, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("1");
    fileIds.emplace_back("2");
    fileIds.emplace_back("3");
    fileIds.emplace_back("4");
    fileIds.emplace_back("5");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "1,2,3,4,5");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_StringIds, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("abc");
    fileIds.emplace_back("def");
    fileIds.emplace_back("ghi");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "abc,def,ghi");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_LongStrings, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("very_long_string_id_12345");
    fileIds.emplace_back("another_long_string_id_67890");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "very_long_string_id_12345,another_long_string_id_67890");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_NoPlaceholders, TestSize.Level1)
{
    std::string sql = "SELECT name, score FROM Stu WHERE age >= 18 AND age <= 45;";
    std::vector<std::string> bindArgs;
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, sql);
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_SinglePlaceholder, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE age >= {0};";
    std::vector<std::string> bindArgs = {"18"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE age >= 18;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_MultiplePlaceholders, TestSize.Level1)
{
    std::string sql = "SELECT name, score FROM Stu WHERE age >= {0} AND age <= {1};";
    std::vector<std::string> bindArgs = {"18", "45"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name, score FROM Stu WHERE age >= 18 AND age <= 45;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_RepeatedPlaceholder, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE age = {0} OR score = {0};";
    std::vector<std::string> bindArgs = {"100"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE age = 100 OR score = 100;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_MultipleRepeatedPlaceholders, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE age = {0} OR age = {1} OR score = {0} OR score = {1};";
    std::vector<std::string> bindArgs = {"18", "45"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE age = 18 OR age = 45 OR score = 18 OR score = 45;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_EmptyPlaceholderValue, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE name = {0};";
    std::vector<std::string> bindArgs = {""};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE name = ;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_StringWithSpecialChars, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE name = {0};";
    std::vector<std::string> bindArgs = {"John's Test"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE name = John's Test;");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_LargePlaceholderIndex, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE id = {9};{0}";
    std::vector<std::string> bindArgs = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE id = j;a");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_NoBindArgs, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE age >= {0} AND age <= {1};";
    std::vector<std::string> bindArgs;
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, sql);
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_MoreBindArgsThanPlaceholders, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE age = {0};";
    std::vector<std::string> bindArgs = {"18", "45", "90"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE age = 18;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_EmptyVector, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_AllNumbers, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("1");
    albumIds.emplace_back("2");
    albumIds.emplace_back("3");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "1");
    EXPECT_EQ(result[1], "2");
    EXPECT_EQ(result[2], "3");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_AllStrings, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("hello");
    albumIds.emplace_back("world");
    albumIds.emplace_back("test");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_Mixed, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("hello");
    albumIds.emplace_back("1");
    albumIds.emplace_back("world");
    albumIds.emplace_back("2");
    albumIds.emplace_back("test");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "1");
    EXPECT_EQ(result[1], "2");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_NegativeNumbers, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("-1");
    albumIds.emplace_back("-2");
    albumIds.emplace_back("-3");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_Zero, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("0");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "0");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_LargeNumbers, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("999999");
    albumIds.emplace_back("1000000");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_DecimalNumbers, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("1.5");
    albumIds.emplace_back("2.7");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_Alphanumeric, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("abc123");
    albumIds.emplace_back("123abc");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_ValidPositiveNumber, TestSize.Level1)
{
    std::string str = "123";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 123);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_ValidNegativeNumber, TestSize.Level1)
{
    std::string str = "-456";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, -456);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Zero, TestSize.Level1)
{
    std::string str = "0";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_MaxInt32, TestSize.Level1)
{
    std::string str = "2147483647";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, INT_MAX);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_MinInt32, TestSize.Level1)
{
    std::string str = "-2147483648";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, INT_MIN);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Overflow, TestSize.Level1)
{
    std::string str = "2147483648";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Underflow, TestSize.Level1)
{
    std::string str = "-2147483649";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_InvalidString, TestSize.Level1)
{
    std::string str = "abc";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_EmptyString, TestSize.Level1)
{
    std::string str = "";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_PartialNumber, TestSize.Level1)
{
    std::string str = "123abc";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_NumberWithSpace, TestSize.Level1)
{
    std::string str = "123 456";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Decimal, TestSize.Level1)
{
    std::string str = "123.456";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_WithPlusSign, TestSize.Level1)
{
    std::string str = "+123";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 123);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_EmptyVector, TestSize.Level1)
{
    std::vector<int32_t> intVals;
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_SingleElement, TestSize.Level1)
{
    std::vector<int32_t> intVals = {123};
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "123");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_MultipleElements, TestSize.Level1)
{
    std::vector<int32_t> intVals = {1, 2, 3, 4, 5};
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 5);
    EXPECT_EQ(result[0], "1");
    EXPECT_EQ(result[1], "2");
    EXPECT_EQ(result[2], "3");
    EXPECT_EQ(result[3], "4");
    EXPECT_EQ(result[4], "5");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_NegativeNumbers, TestSize.Level1)
{
    std::vector<int32_t> intVals = {-1, -2, -3};
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "-1");
    EXPECT_EQ(result[1], "-2");
    EXPECT_EQ(result[2], "-3");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_Zero, TestSize.Level1)
{
    std::vector<int32_t> intVals = {0};
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "0");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_LargeNumbers, TestSize.Level1)
{
    std::vector<int32_t> intVals = {INT_MAX, INT_MIN};
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "2147483647");
    EXPECT_EQ(result[1], "-2147483648");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_EmptyVector, TestSize.Level1)
{
    std::vector<uint64_t> vec;
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_SingleElement, TestSize.Level1)
{
    std::vector<uint64_t> vec = {1};
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[1]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_MultipleElements, TestSize.Level1)
{
    std::vector<uint64_t> vec = {1, 2, 3, 4, 5};
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[1, 2, 3, 4, 5]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_CustomSeparator, TestSize.Level1)
{
    std::vector<uint64_t> vec = {1, 2, 3};
    std::string result = CloudMediaDaoUtils::VectorToString(vec, "|");
    EXPECT_EQ(result, "[1|2|3]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_LargeNumbers, TestSize.Level1)
{
    std::vector<uint64_t> vec = {18446744073709551615ULL, 999999999999ULL};
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[18446744073709551615, 999999999999]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_Zero, TestSize.Level1)
{
    std::vector<uint64_t> vec = {0};
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[0]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_MultipleZeros, TestSize.Level1)
{
    std::vector<uint64_t> vec = {0, 0, 0};
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_EQ(result, "[0, 0, 0]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_EmptySeparator, TestSize.Level1)
{
    std::vector<uint64_t> vec = {1, 2, 3};
    std::string result = CloudMediaDaoUtils::VectorToString(vec, "");
    EXPECT_EQ(result, "[123]");
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_LongSeparator, TestSize.Level1)
{
    std::vector<uint64_t> vec = {1, 2, 3};
    std::string result = CloudMediaDaoUtils::VectorToString(vec, "SEPARATOR");
    EXPECT_EQ(result, "[1SEPARATOR2SEPARATOR3]");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_InvalidPath, TestSize.Level1)
{
    std::string path = "/invalid/path";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_EmptyPath, TestSize.Level1)
{
    std::string path = "";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_ValidPath, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test/path";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_DifferentUserId, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test/path";
    int32_t userId = 200;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/200/hmdfs/account/files/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPathPathWithNoSubPath, TestSize.Level1)
{
    std::string path = "/storage/cloud/files";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_ComplexPath, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/Photo/2025/03/06/test.jpg";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files/Photo/2025/03/06/test.jpg");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_ZeroUserId, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test";
    int32_t userId = 0;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/0/hmdfs/account/files/test");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_NegativeUserId, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test";
    int32_t userId = -1;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/-1/hmdfs/account/files/test");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_NonLakeFile, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test/path";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/data/service/el2/100/hmdfs/account/files/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_LakeFile, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 3;
    photosVo.storagePath = "/storage/lake/test/path";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_EmptyData, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_EmptyStoragePath, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 3;
    photosVo.storagePath = "";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_DifferentFileSourceType, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 1;
    photosVo.data = "/storage/cloud/files/test/path";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/data/service/el2/100/hmdfs/account/files/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_LakeFileWithDifferentUserId, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 3;
    photosVo.storagePath = "/storage/lake/test/path";
    std::string localPath;
    int32_t userId = 200;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_NoValue, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    pullData.localPhotosPoOp = std::nullopt;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_NonLakeFile, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test/path";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_LakeFile, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 3;
    photosPo.storagePath = "/storage/lake/test/path";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_EmptyData, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_EmptyStoragePath, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 3;
    photosPo.storagePath = "";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_DifferentFileSourceType, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 1;
    photosPo.data = "/test/path";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_NonLakeFile, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_LakeFile, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 3;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/storage/lake/test");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_EmptyPaths, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "";
    pathInfo.storagePath = "";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_LakeFileEmptyStoragePath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 3;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_NonLakeFileEmptyFilePath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_DifferentFileSourceType, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 1;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_FileSourceType2, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 2;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/test/path");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_LongPaths, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/very/long/path/to/the/file/that/should/be/used/for/testing/purposes/only";
    pathInfo.storagePath = "/another/very/long/storage/path/for/testing/the/functionality";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/very/long/path/to/the/file/that/should/be/used/for/testing/purposes/only");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_SpecialCharactersInPath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path_with-special.chars";
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(localPath, "/test/path_with-special.chars");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_VeryLongString, TestSize.Level1)
{
    std::vector<std::string> values;
    std::string longString(1000, 'a');
    values.emplace_back(longString);
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result.length(), longString.length() + 2);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_VeryLongString, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    std::string longString(1000, 'b');
    fileIds.emplace_back(longString);
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result.length(), longString.length());
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_VeryLongPlaceholderValue, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE name = {0};";
    std::string longString(1000, 'c');
    std::vector<std::string> bindArgs = {longString};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result.length(), sql.length() - 3 + longString.length());
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_VeryLongNumber, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    std::string longNumber(100, '9');
    albumIds.emplace_back(longNumber);
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 1);
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_ManyElements, TestSize.Level1)
{
    std::vector<uint64_t> vec;
    for (int i = 0; i < 100; i++) {
        vec.push_back(i);
    }
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_GT(result.length(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_PathWithTrailingSlash, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test/path/";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files/test/path/");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_AllFieldsSet, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test/path";
    photosVo.storagePath = "/storage/lake/test";
    photosVo.title = "test_title";
    photosVo.mediaType = 1;
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_AllFieldsSet, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test/path";
    photosPo.storagePath = "/storage/lake/test";
    photosPo.title = "test_title";
    photosPo.mediaType = 1;
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_AllFieldsSet, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    pathInfo.userId = 100;
    pathInfo.hidden = 0;
    pathInfo.dateTrashed = 0;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_UnicodeString, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("hello世界");
    values.emplace_back("world🌍");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_GT(result.length(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_UnicodeString, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("测试123");
    fileIds.emplace_back("abc中文");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_GT(result.length(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_UnicodePlaceholderValue, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE name = {0};";
    std::vector<std::string> bindArgs = {"测试"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE name = 测试;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_UnicodePath, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/测试/path";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_UnicodePath, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/测试/path";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_UnicodePath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/测试/path";
    pathInfo.storagePath = "/storage/lake/测试";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_MaxUserId, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test/path";
    std::string localPath;
    int32_t userId = INT_MAX;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_MinUserId, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test/path";
    std::string localPath;
    int32_t userId = INT_MIN;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_NegativeUserId, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    pathInfo.userId = -1;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PositiveHidden, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    pathInfo.hidden = 1;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PositiveDateTrashed, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test/path";
    pathInfo.storagePath = "/storage/lake/test";
    pathInfo.dateTrashed = 123456789;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_SingleQuoteInString, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("test'quote");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'test'quote'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_SingleQuoteInString, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("test'quote");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "test'quote");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_SingleQuoteInPlaceholderValue, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE name = {0};";
    std::vector<std::string> bindArgs = {"test'quote"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE name = test'quote;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_WithSlashInPath, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test//path";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_WithSlashInPath, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test//path";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_WithSlashInPath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test//path";
    pathInfo.storagePath = "/storage/lake//test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_LeadingZeros, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("001");
    albumIds.emplace_back("002");
    albumIds.emplace_back("003");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 3);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_LeadingZeros, TestSize.Level1)
{
    std::string str = "00123";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 123);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetStringVector_LargeVector, TestSize.Level1)
{
    std::vector<int32_t> intVals;
    for (int i = 0; i < 1000; i++) {
        intVals.push_back(i);
    }
    auto result = CloudMediaDaoUtils::GetStringVector(intVals);
    EXPECT_EQ(result.size(), 1000);
}

HWTEST_F(CloudMediaDaoUtilsTest, VectorToString_LargeVector, TestSize.Level1)
{
    std::vector<uint64_t> vec;
    for (int i = 0; i < 1000; i++) {
        vec.push_back(i);
    }
    std::string result = CloudMediaDaoUtils::VectorToString(vec);
    EXPECT_GT(result.length(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_PathWithSpaces, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test path/file name";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files/test path/file name");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithSpaces, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test path/file name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithSpaces, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test path/file name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithSpaces, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test path/file name";
    pathInfo.storagePath = "/storage/lake/test path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithSpaces, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test path/file name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test path/file name'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithSpaces, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test path/file name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test path/file name");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithSpaces, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test path/file name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test path/file name;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_ScientificNotation, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("1e10");
    albumIds.emplace_back("2.5e3");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_ScientificNotation, TestSize.Level1)
{
    std::string str = "1e10";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_VeryLongPath, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    std::string longPath(1000, 'a');
    photosVo.data = "/storage/cloud/files/" + longPath;
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_VeryLongPath, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    std::string longPath(1000, 'b');
    photosPo.data = "/" + longPath;
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_VeryLongPath, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    std::string longPath(1000, 'c');
    pathInfo.filePath = "/" + longPath;
    pathInfo.storagePath = "/storage/lake/test";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLowerPath_PathWithDot, TestSize.Level1)
{
    std::string path = "/storage/cloud/files/test.path/file.name";
    int32_t userId = 100;
    std::string result = CloudMediaDaoUtils::GetLowerPath(path, userId);
    EXPECT_EQ(result, "/data/service/el2/100/hmdfs/account/files/test.path/file.name");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithDot, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test.path/file.name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithDot, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test.path/file.name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithDot, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test.path/file.name";
    pathInfo.storagePath = "/storage/lake/test.path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithDot, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test.path/file.name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test.path/file.name'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithDot, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test.path/file.name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test.path/file.name");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithDot, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test.path/file.name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test.path/file.name;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_Hexadecimal, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("0x1A");
    albumIds.emplace_back("0xFF");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Hexadecimal, TestSize.Level1)
{
    std::string str = "0x1A";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 0);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithUnderscore, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test_path/file_name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithUnderscore, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test_path/file_name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithUnderscore, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test_path/file_name";
    pathInfo.storagePath = "/storage/lake/test_path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithUnderscore, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test_path/file_name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test_path/file_name'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithUnderscore, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test_path/file_name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test_path/file_name");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithUnderscore, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test_path/file_name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test_path/file_name;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithDash, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test-path/file-name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithDash, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test-path/file-name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithDash, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test-path/file-name";
    pathInfo.storagePath = "/storage/lake/test-path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithDash, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test-path/file-name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test-path/file-name'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithDash, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test-path/file-name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test-path/file-name");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithDash, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test-path/file-name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test-path/file-name;");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetNumbers_Octal, TestSize.Level1)
{
    std::vector<std::string> albumIds;
    albumIds.emplace_back("0123");
    auto result = CloudMediaDaoUtils::GetNumbers(albumIds);
    EXPECT_EQ(result.size(), 1);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToInt32_Octal, TestSize.Level1)
{
    std::string str = "0123";
    int32_t result = CloudMediaDaoUtils::ToInt32(str);
    EXPECT_EQ(result, 123);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithParentheses, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test(path)/file(name)";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithParentheses, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test(path)/file(name)";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithParentheses, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test(path)/file(name)";
    pathInfo.storagePath = "/storage/lake/test(path)";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithParentheses, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test(path)/file(name)");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test(path)/file(name)'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithParentheses, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test(path)/file(name)");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test(path)/file(name)");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithParentheses, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test(path)/file(name)"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test(path)/file(name);");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithBrackets, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test[path]/file[name]";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithBrackets, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test[path]/file[name]";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithBrackets, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test[path]/file[name]";
    pathInfo.storagePath = "/storage/lake/test[path]";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithBrackets, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test[path]/file[name]");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test[path]/file[name]'");
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithComma_PathWithBrackets, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test[path]/file[name]");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test[path]/file[name]");
}

HWTEST_F(CloudMediaDaoUtilsTest, FillParams_PathWithBrackets, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test[path]/file[name]"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test[path]/file[name];");
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPhotosVo_PathWithBraces, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test{path}/file{name}";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathByPullData_PathWithBraces, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test{path}/file{name}";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, GetLocalPathWithAnco_PathWithBraces, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test{path}/file{name}";
    pathInfo.storagePath = "/storage/lake/test{path}";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsTest, ToStringWithCommaAndQuote_PathWithBraces, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test{path}/file{name}");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test{path}/file{name}'");
}
}
