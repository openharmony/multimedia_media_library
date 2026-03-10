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

#include "update_data_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class UpdateDataVoTest : public testing::Test {};

HWTEST_F(UpdateDataVoTest, TC001_UpdateDataReqBody_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    UpdateDataReqBody reqBody;
    reqBody.tableName = "PhotoTable";
    reqBody.operateName = "UPDATE";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateDataReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.tableName, "PhotoTable");
    EXPECT_EQ(restored.operateName, "UPDATE");
}

HWTEST_F(UpdateDataVoTest, TC002_UpdateDataReqBody_Marshalling_Unmarshalling_WithValueMap, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    UpdateDataReqBody reqBody;
    reqBody.tableName = "PhotoTable";
    reqBody.operateName = "UPDATE";
    reqBody.value.valuesMap["file_id"] = "123";
    reqBody.value.valuesMap["cloud_id"] = "cloud_123";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateDataReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.tableName, "PhotoTable");
    EXPECT_EQ(restored.value.valuesMap.size(), 2);
}

}  // namespace OHOS::Media::CloudSync
