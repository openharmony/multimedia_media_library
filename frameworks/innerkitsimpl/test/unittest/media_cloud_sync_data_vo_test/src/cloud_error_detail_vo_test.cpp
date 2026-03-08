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

#include "cloud_error_detail_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class CloudErrorDetailVoTest : public testing::Test {};

HWTEST_F(CloudErrorDetailVoTest, TC001_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试CloudErrorDetail序列化/反序列化成功路径；覆盖所有字段正常读写（触发条件：所有字段有效）；验证业务状态断言：反序列化后字段值与原值一致

    CloudErrorDetail original;
    original.domain = "test_domain";
    original.reason = "test_reason";
    original.errorCode = "ERR_001";
    original.description = "test description";
    original.errorPos = "position_1";
    original.errorParam = "param_1";
    original.detailCode = 100;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudErrorDetail restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.domain, original.domain);
    EXPECT_EQ(restored.reason, original.reason);
    EXPECT_EQ(restored.errorCode, original.errorCode);
    EXPECT_EQ(restored.description, original.description);
    EXPECT_EQ(restored.errorPos, original.errorPos);
    EXPECT_EQ(restored.errorParam, original.errorParam);
    EXPECT_EQ(restored.detailCode, original.detailCode);
}

HWTEST_F(CloudErrorDetailVoTest, TC002_Unmarshalling_ReadStringDomain_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudErrorDetail反序列化失败路径；覆盖domain字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    parcel.WriteString("test_domain");

    parcel.RewindRead(0);
    CloudErrorDetail vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudErrorDetailVoTest, TC003_Unmarshalling_ReadStringReason_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    OHOS::MessageParcel parcel;
    parcel.WriteString("test_domain");
    parcel.WriteString("test_reason");

    parcel.RewindRead(0);
    CloudErrorDetail vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudErrorDetailVoTest, TC004_Unmarshalling_ReadInt32DetailCode_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudErrorDetail反序列化失败路径；覆盖detailCode字段读取失败（触发条件：MessageParcel.ReadInt32失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    parcel.WriteString("test_domain");
    parcel.WriteString("test_reason");
    parcel.WriteString("ERR_001");
    parcel.WriteString("test description");
    parcel.WriteString("position_1");
    parcel.WriteString("param_1");

    parcel.RewindRead(0);
    CloudErrorDetail vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
