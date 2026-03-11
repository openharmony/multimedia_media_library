/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under * Apache License, Version 2.0 (the "License");
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

#include "update_local_file_dirty_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class UpdateLocalFileDirtyVoTest : public testing::Test {};

HWTEST_F(UpdateLocalFileDirtyVoTest, TC001_UpdateLocalFileDirtyReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败

    UpdateLocalFileDirtyReqBody reqBody;
    reqBody.cloudIds.clear();

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateLocalFileDirtyReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 0);
}

HWTEST_F(UpdateLocalFileDirtyVoTest, TC002_UpdateLocalFileDirtyReqBody_Marshalling_Unmarshalling_Skt, TestSize.Level1)
{
    // 用例说明：测试单元素序列化与反序列化；覆盖正常路径（触发条件：单元素数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    UpdateLocalFileDirtyReqBody reqBody;
    reqBody.cloudIds.push_back("cloud_id_123");

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateLocalFileDirtyReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_123");
}

HWTEST_F(UpdateLocalFileDirtyVoTest,
         TC003_UpdateLocalFileDirtyReqBody_Marshalling_Unmarshalling_Multiple,
         TestSize.Level1)
{
    // 用例说明：测试多元素序列化与反序列化；覆盖正常路径（触发条件：多元素数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    UpdateLocalFileDirtyReqBody reqBody;
    reqBody.cloudIds.push_back("cloud_id_1");
    reqBody.cloudIds.push_back("cloud_id_2");
    reqBody.cloudIds.push_back("cloud_id_3");

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    UpdateLocalFileDirtyReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 3);
}

}  // namespace OHOS::Media::CloudSync
