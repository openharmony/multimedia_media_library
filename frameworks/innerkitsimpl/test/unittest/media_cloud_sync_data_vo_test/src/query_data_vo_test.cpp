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
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

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

HWTEST_F(QueryDataVoTest, TC002_QueryDataDataRespBody_Marshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

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
}

}  // namespace OHOS::Media::CloudSync
