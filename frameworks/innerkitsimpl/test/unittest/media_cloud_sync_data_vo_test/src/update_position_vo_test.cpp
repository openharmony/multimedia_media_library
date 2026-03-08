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

#include "update_position_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

class UpdatePositionVoTest : public testing::Test {};

HWTEST_F(UpdatePositionVoTest, TC001_ReqBody_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    UpdatePositionReqBody original;
    original.cloudIds.push_back("cloud_id_123");
    original.position = 1024;
    original.fileSourceType = 0;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdatePositionReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), original.cloudIds.size());
    EXPECT_EQ(restored.position, original.position);
}

HWTEST_F(UpdatePositionVoTest, TC002_ReqBody_Unmarshalling_EmptyCloudIds, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(0);
    parcel.WriteInt32(1024);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    UpdatePositionReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
}

HWTEST_F(UpdatePositionVoTest, TC003_ReqBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    UpdatePositionReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(UpdatePositionVoTest, TC004_ReqBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    UpdatePositionReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(UpdatePositionVoTest, TC005_ReqBody_ToString, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    UpdatePositionReqBody vo;
    vo.cloudIds.push_back("cloud_id_123");
    vo.position = 1024;
    vo.fileSourceType = 0;

    std::string str = vo.ToString();
    EXPECT_FALSE(str.empty());
}

}  // namespace OHOS::Media::CloudSync
