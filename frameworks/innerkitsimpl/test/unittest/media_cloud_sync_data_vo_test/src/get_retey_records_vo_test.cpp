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

#include "get_retey_records_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class GetRetryRecordsVoTest : public testing::Test {};

HWTEST_F(GetRetryRecordsVoTest, TC001_Marshalling_Unmarshalling_Empty_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    original.cloudIds.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 0);
}

HWTEST_F(GetRetryRecordsVoTest, TC002_Marshalling_Unmarshalling_Single_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    original.cloudIds.push_back("cloud_id_001");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_001");
}

HWTEST_F(GetRetryRecordsVoTest, TC003_Marshalling_Unmarshalling_Multiple_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    original.cloudIds.push_back("cloud_id_001");
    original.cloudIds.push_back("cloud_id_002");
    original.cloudIds.push_back("cloud_id_003");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 3);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_001");
    EXPECT_EQ(restored.cloudIds[1], "cloud_id_002");
    EXPECT_EQ(restored.cloudIds[2], "cloud_id_003");
}

HWTEST_F(GetRetryRecordsVoTest, TC004_Marshalling_Unmarshalling_LongString_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    std::string longCloudId(1000, 'A');
    original.cloudIds.push_back(longCloudId);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], longCloudId);
}

HWTEST_F(GetRetryRecordsVoTest, TC005_Marshalling_Unmarshalling_SpecialString_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    original.cloudIds.push_back("");
    original.cloudIds.push_back("cloud_id_with_中文");
    original.cloudIds.push_back("cloud_id_with_special!@#$%^&*()");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 3);
    EXPECT_EQ(restored.cloudIds[0], "");
    EXPECT_EQ(restored.cloudIds[1], "cloud_id_with_中文");
    EXPECT_EQ(restored.cloudIds[2], "cloud_id_with_special!@#$%^&*()");
}

HWTEST_F(GetRetryRecordsVoTest, TC006_Marshalling_Unmarshalling_LargeVector_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetRetryRecordsRespBody original;
    for (int i = 0; i < 100; i++) {
        original.cloudIds.push_back("cloud_id_" + std::to_string(i));
    }

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetRetryRecordsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 100);
    for (int i = 0; i < 100; i++) {
        EXPECT_EQ(restored.cloudIds[i], "cloud_id_" + std::to_string(i));
    }
}

}  // namespace OHOS::Media::CloudSync
