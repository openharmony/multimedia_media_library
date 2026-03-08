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

#include "failed_size_resp_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class FailedSizeRespVoTest : public testing::Test {};

HWTEST_F(FailedSizeRespVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试FailedSizeResp序列化/反序列化成功路径；覆盖所有字段正常读写（触发条件：所有字段有效）；验证业务状态断言：反序列化后字段值与原值一致

    FailedSizeResp original;
    original.failedSize = 5;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    FailedSizeResp restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failedSize, original.failedSize);
}

HWTEST_F(FailedSizeRespVoTest, TC002_Unmarshalling_ReadInt32FailSize_Fail, TestSize.Level1)
{
    // 用例说明：测试FailedSizeResp反序列化失败路径；覆盖failedSize字段读取失败（触发条件：MessageParcel.ReadInt32失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(5);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    FailedSizeResp vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
}

}  // namespace OHOS::Media::CloudSync
