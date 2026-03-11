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

#define MLOG_TAG "DaoUtilsTest"

#include "dao_utils_test.h"

#include <string>

#include "dao_utils.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media {

void DaoUtilsTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DaoUtilsTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void DaoUtilsTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DaoUtilsTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_001 start");
    std::string sql = "SELECT * FROM table WHERE id = {0} AND name = '{1}' AND value = {2}";
    std::vector<std::string> bindArgs = {"100", "test", "value"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("100"), std::string::npos);
    EXPECT_NE(result.find("'test'"), std::string::npos);
    EXPECT_NE(result.find("value"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_001 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_002 start");
    std::string sql = "INSERT INTO table (col1, col2) VALUES ({0}, {1})";
    std::vector<std::string> bindArgs = {"value1", "value2"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("value1"), std::string::npos);
    EXPECT_NE(result.find("value2"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_002 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_003 start");
    std::string sql = "SELECT * FROM table";
    std::vector<std::string> bindArgs = {};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_EQ(result, sql);
    MEDIA_INFO_LOG("FillParams_Test_003 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_004 start");
    std::string sql = "UPDATE table SET col = {0} WHERE id = {1}";
    std::vector<std::string> bindArgs = {"new_value", "123"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("new_value"), std::string::npos);
    EXPECT_NE(result.find("123"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_004 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_005 start");
    std::string sql = "DELETE FROM table WHERE id = {0}";
    std::vector<std::string> bindArgs = {"999"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("999"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_005 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_006 start");
    std::string sql = "SELECT * FROM table WHERE col1 = {0} AND col2 = {1} AND col3 = {2} AND col4 = {3}";
    std::vector<std::string> bindArgs = {"a", "b", "c", "d"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("a"), std::string::npos);
    EXPECT_NE(result.find("b"), std::string::npos);
    EXPECT_NE(result.find("c"), std::string::npos);
    EXPECT_NE(result.find("d"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_006 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_007 start");
    std::string sql = "{0}";
    std::vector<std::string> bindArgs = {"single_param"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_EQ(result, "single_param");
    MEDIA_INFO_LOG("FillParams_Test_007 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_008 start");
    std::string sql = "SELECT * FROM table WHERE id IN ({0}, {1}, {2})";
    std::vector<std::string> bindArgs = {"1", "2", "3"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("1"), std::string::npos);
    EXPECT_NE(result.find("2"), std::string::npos);
    EXPECT_NE(result.find("3"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_008 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_009 start");
    std::string sql = "SELECT * FROM table WHERE name LIKE '%{0}%' AND value = {1}";
    std::vector<std::string> bindArgs = {"test", "100"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("%test%"), std::string::npos);
    EXPECT_NE(result.find("100"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_009 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_010 start");
    std::string sql = "SELECT * FROM table WHERE col1 = {0} AND col2 = {1} AND col3 = {2} AND col4 = {3} AND col5 = {4}";
    std::vector<std::string> bindArgs = {"val1", "val2", "val3", "val4", "val5"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("val1"), std::string::npos);
    EXPECT_NE(result.find("val2"), std::string::npos);
    EXPECT_NE(result.find("val3"), std::string::npos);
    EXPECT_NE(result.find("val4"), std::string::npos);
    EXPECT_NE(result.find("val5"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_010 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_011 start");
    std::string sql = "SELECT * FROM table WHERE id = {0}";
    std::vector<std::string> bindArgs = {"0"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("0"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_011 end");
}

HWTEST_F(DaoUtilsTest, FillParams_Test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("FillParams_Test_012 start");
    std::string sql = "SELECT * FROM table WHERE id = {0} AND name = '{1}' AND value = {2} AND status = {3}";
    std::vector<std::string> bindArgs = {"123", "test_name", "test_value", "active"};
    
    std::string result = DaoUtils::FillParams(sql, bindArgs);
    
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("123"), std::string::npos);
    EXPECT_NE(result.find("'test_name'"), std::string::npos);
    EXPECT_NE(result.find("test_value"), std::string::npos);
    EXPECT_NE(result.find("active"), std::string::npos);
    MEDIA_INFO_LOG("FillParams_Test_012 end");
}
}  // namespace OHOS::Media