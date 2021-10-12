/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "mediadataability_module_test.h"
#include "media_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
MediaDataAbility g_rdbStoreTest;
void MediaDataAbilityModuleTest::SetUpTestCase(void)
{
}

void MediaDataAbilityModuleTest::TearDownTestCase(void)
{
}

void MediaDataAbilityModuleTest::SetUp(void)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityModuleTest::SetUp\n");
    g_rdbStoreTest.InitMediaRdbStore();
}

void MediaDataAbilityModuleTest::TearDown(void)
{
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityInsertTest_001, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityInsertTest_001::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 0);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test0"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 0);
    Uri uri(MEDIA_DATA_URI);
    ret = g_rdbStoreTest.Insert(uri, values);
    EXPECT_EQ(ret, 1);
    OHOS::NativeRdb::ValuesBucket values1;
    values1.PutInt(MEDIA_DATA_DB_ID, 1);
    values1.PutString(MEDIA_DATA_DB_NAME, std::string("test1"));
    values1.PutInt(MEDIA_DATA_DB_SIZE, 10);
    ret = g_rdbStoreTest.Insert(uri, values1);
    EXPECT_EQ(ret, 2);
    MEDIA_DEBUG_LOG("MediaDataAbilityInsertTest_001::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityInsertTest_002, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityInsertTest_002::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 2);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test2"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 11);
    Uri uri(MEDIA_DATA_URI);
    ret = g_rdbStoreTest.Insert(uri, values);
    EXPECT_EQ(ret, 3);
    MEDIA_DEBUG_LOG("MediaDataAbilityInsertTest_002::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityDeleteTest_001, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_001::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test2");
    Uri uri(MEDIA_DATA_URI);
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, 1);
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_001::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityDeleteTest_002, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_002::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test-uk");
    Uri uri(MEDIA_DATA_URI);
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_002::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityDeleteTest_003, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_003::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIA_DATA_URI + "/abc");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, FAIL);
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_003::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityDeleteTest_004, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_004::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIA_DATA_URI + "/1");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, 1);
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_004::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityDeleteTest_005, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_005::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIA_DATA_URI + "/1ab2");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, FAIL);
    MEDIA_DEBUG_LOG("MediaDataAbilityDeleteTest_005::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityUpdateTest_001, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_001::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test1");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI);
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 3);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test3"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 12);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, 1);
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_001::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityUpdateTest_002, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_002::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test2");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI);
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 4);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test4"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_002::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityUpdateTest_003, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_003::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/a2b");
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 4);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
        EXPECT_EQ(ret, FAIL);
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_003::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityUpdateTest_004, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_004::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/abc");
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 4);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, FAIL);
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_004::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityUpdateTest_005, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_005::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/2");
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt(MEDIA_DATA_DB_ID, 4);
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, 1);
    MEDIA_DEBUG_LOG("MediaDataAbilityUpdateTest_005::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityQueryTest_001, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_001::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1;
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "new-modify");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI);
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;
    ret = resultSet->GetColumnIndexForName(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);

    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(4, intVal);

    ret = resultSet->GetColumnIndexForName(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ("new-modify", strVal);
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_001::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityQueryTest_002, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_002::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1;
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test4");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI);
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, OHOS::NativeRdb::E_STEP_RESULT_IS_AFTER_LAST);
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_002::end\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityQueryTest_003, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_003::Start\n");
    OHOS::NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/abc");
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_EQ(resultSet, nullptr);
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_003::end\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityQueryTest_004, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_004::Start\n");
    OHOS::NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/");
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_EQ(resultSet, nullptr);
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_004::end\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityQueryTest_005, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_005::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIA_DATA_URI + "/2");
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;
    ret = resultSet->GetColumnIndexForName(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);

    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(4, intVal);

    ret = resultSet->GetColumnIndexForName(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ("new-modify", strVal);
    MEDIA_DEBUG_LOG("MediaDataAbilityQueryTest_005::End\n");
}

HWTEST_F(MediaDataAbilityModuleTest, MediaDataAbilityBatchInsertTest_001, TestSize.Level1)
{
    MEDIA_DEBUG_LOG("MediaDataAbilityBatchInsertTest_001::Start\n");
    int32_t ret = -1;
    OHOS::NativeRdb::ValuesBucket values1;
    values1.PutInt(MEDIA_DATA_DB_ID, 11);
    values1.PutString(MEDIA_DATA_DB_NAME, std::string("test11"));
    values1.PutInt(MEDIA_DATA_DB_SIZE, 11);

    OHOS::NativeRdb::ValuesBucket values2;
    values2.PutInt(MEDIA_DATA_DB_ID, 10);
    values2.PutString(MEDIA_DATA_DB_NAME, std::string("test10"));
    values2.PutInt(MEDIA_DATA_DB_SIZE, 10);

    OHOS::NativeRdb::ValuesBucket values3;
    values3.PutInt(MEDIA_DATA_DB_ID, 12);
    values3.PutString(MEDIA_DATA_DB_NAME, std::string("test12"));
    values3.PutInt(MEDIA_DATA_DB_SIZE, 12);

    std::vector<OHOS::NativeRdb::ValuesBucket> values;
    values.push_back(values1);
    values.push_back(values2);
    values.push_back(values3);
    Uri uri(MEDIA_DATA_URI);
    ret = g_rdbStoreTest.BatchInsert(uri, values);
    EXPECT_EQ(ret, 3);
    MEDIA_DEBUG_LOG("MediaDataAbilityBatchInsertTest_001::End\n");
}
} // namespace Media
} // namespace OHOS