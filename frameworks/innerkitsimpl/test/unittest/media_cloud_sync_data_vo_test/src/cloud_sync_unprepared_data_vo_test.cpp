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

#include "cloud_sync_unprepared_data_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

class CloudSyncUnpreparedDataVoTest : public testing::Test {};

HWTEST_F(CloudSyncUnpreparedDataVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    CloudSyncUnPreparedDataRespBody original;
    original.count = 5;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudSyncUnPreparedDataRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.count, original.count);
}

HWTEST_F(CloudSyncUnpreparedDataVoTest, TC002_Unmarshalling_ReadInt32Count_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    CloudSyncUnPreparedDataRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudSyncUnpreparedDataVoTest, TC002_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudSyncUnpreparedData反序列化失败路径；覆盖cloudId字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("cloud_id_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudSyncUnPreparedDataRespBody vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudSyncUnpreparedDataVoTest, TC003_Unmarshalling_ReadBoolRecycled_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("/local/photo.jpg");

    parcel.RewindRead(0);
    CloudSyncUnPreparedDataRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
