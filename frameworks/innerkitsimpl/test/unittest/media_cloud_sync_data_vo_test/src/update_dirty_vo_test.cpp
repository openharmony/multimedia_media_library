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

#include "update_dirty_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class UpdateDirtyVoTest : public testing::Test {};

HWTEST_F(UpdateDirtyVoTest, TC001_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    UpdateDirtyReqBody original;
    original.cloudId = "cloud_id_123";
    original.dirtyType = 1;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateDirtyReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.dirtyType, original.dirtyType);
}

HWTEST_F(UpdateDirtyVoTest, TC002_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("cloud_id_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateDirtyReqBody vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(UpdateDirtyVoTest, TC003_Unmarshalling_ReadInt32DirtyType_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("cloud_id_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateDirtyReqBody vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(UpdateDirtyVoTest, TC004_Marshalling_WriteStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    UpdateDirtyReqBody vo;
    vo.cloudId = "cloud_id_123";
    vo.dirtyType = 1;

    OHOS::MessageParcel parcel;
    bool ret = vo.Marshalling(parcel);
    ASSERT_TRUE(ret);
}

HWTEST_F(UpdateDirtyVoTest, TC005_Marshalling_WriteInt32DirtyType_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    UpdateDirtyReqBody vo;
    vo.cloudId = "cloud_id_123";
    vo.dirtyType = 1;

    OHOS::MessageParcel parcel;
    bool ret = vo.Marshalling(parcel);
    ASSERT_TRUE(ret);
}

}  // namespace OHOS::Media::CloudSync
