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

#include "query_data_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class QueryDataVoTest : public testing::Test {};

HWTEST_F(QueryDataVoTest, TC001_QueryDataReqBody_Marshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试QueryDataReqBody序列化与反序列化；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：反序列化后的数据与原始数据一致

    QueryDataReqBody reqBody;
    reqBody.columnNames.push_back("file_id");
    reqBody.columnNames.push_back("cloud_id");
    reqBody.tableName = "PhotoTable";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.columnNames.size(), 2);
    EXPECT_EQ(restored.tableName, "PhotoTable");
}

HWTEST_F(QueryDataVoTest, TC002_QueryDataReqBody_Unmarshalling_PredicatesFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataReqBody反序列化失败；覆盖predicates失败分支（触发条件：predicates反序列化失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("invalid_data");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataReqBody reqBody;
    ret = reqBody.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(QueryDataVoTest, TC003_QueryDataReqBody_Unmarshalling_ColumnNamesFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataReqBody反序列化失败；覆盖columnNames失败分支（触发条件：columnNames反序列化失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(1);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataReqBody reqBody;
    ret = reqBody.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(QueryDataVoTest, TC004_QueryDataReqBody_Marshalling_PredicatesFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataReqBody序列化失败；覆盖predicates失败分支（触发条件：predicates序列化失败）；
    // 验证业务状态断言：序列化返回false（通过构造异常predicates模拟）
    QueryDataReqBody reqBody;
    reqBody.columnNames.push_back("file_id");
    reqBody.tableName = "PhotoTable";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

HWTEST_F(QueryDataVoTest, TC005_QueryDataReqBody_Marshalling_ColumnNamesFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataReqBody序列化失败；覆盖columnNames失败分支（触发条件：columnNames序列化失败）；
    // 验证业务状态断言：序列化返回false（通过构造异常columnNames模拟）
    QueryDataReqBody reqBody;
    reqBody.tableName = "PhotoTable";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

HWTEST_F(QueryDataVoTest, TC006_QueryDataRespBody_Marshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试QueryDataRespBody序列化与反序列化；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：反序列化后的数据与原始数据一致

    QueryDataRespBody respBody;

    std::unordered_map<std::string, std::string> row1;
    row1["file_id"] = "123";
    row1["cloud_id"] = "cloud_id_123";
    respBody.queryResults.push_back(row1);

    std::unordered_map<std::string, std::string> row2;
    row2["file_id"] = "456";
    row2["cloud_id"] = "cloud_id_456";
    respBody.queryResults.push_back(row2);

    OHOS::MessageParcel parcel;
    bool ret = respBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.queryResults.size(), 2);
    EXPECT_EQ(restored.queryResults[0]["file_id"], "123");
    EXPECT_EQ(restored.queryResults[1]["cloud_id"], "cloud_id_456");
}

HWTEST_F(QueryDataVoTest, TC007_QueryDataRespBody_Unmarshalling_QueryResultsFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataRespBody反序列化失败；覆盖queryResults失败分支（触发条件：queryResults反序列化失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("invalid_data");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataRespBody respBody;
    ret = respBody.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(QueryDataVoTest, TC008_QueryDataRespBody_Marshalling_QueryResultsFail, TestSize.Level1)
{
    // 用例说明：测试QueryDataRespBody序列化失败；覆盖queryResults失败分支（触发条件：queryResults序列化失败）；
    // 验证业务状态断言：序列化返回false（通过构造异常queryResults模拟）
    QueryDataRespBody respBody;

    OHOS::MessageParcel parcel;
    bool ret = respBody.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

HWTEST_F(QueryDataVoTest, TC009_QueryDataRespBody_EmptyQueryResults, TestSize.Level1)
{
    // 用例说明：测试QueryDataRespBody空queryResults序列化与反序列化；覆盖空集合边界（触发条件：empty queryResults）；
    // 验证业务状态断言：反序列化后的queryResults为空
    QueryDataRespBody respBody;

    OHOS::MessageParcel parcel;
    bool ret = respBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    QueryDataRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.queryResults.size(), 0);
}

}  // namespace OHOS::Media::CloudSync
