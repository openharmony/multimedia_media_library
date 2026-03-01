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

#include "media_operate_result_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class MediaOperateResultVoTest : public testing::Test {};

HWTEST_F(MediaOperateResultVoTest, TC001_ResultNode_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBodyResultNode original;
    original.cloudId = "cloud_id_001";
    original.errorCode = 0;
    original.errorMsg = "success";

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBodyResultNode restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.errorCode, original.errorCode);
    EXPECT_EQ(restored.errorMsg, original.errorMsg);
}

HWTEST_F(MediaOperateResultVoTest, TC002_ResultNode_Marshalling_Unmarshalling_Error_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBodyResultNode original;
    original.cloudId = "cloud_id_002";
    original.errorCode = -1;
    original.errorMsg = "operation failed";

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBodyResultNode restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.errorCode, original.errorCode);
    EXPECT_EQ(restored.errorMsg, original.errorMsg);
}

HWTEST_F(MediaOperateResultVoTest, TC003_ResultNode_Marshalling_Unmarshalling_EmptyStrings_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBodyResultNode original;
    original.cloudId = "";
    original.errorCode = 123;
    original.errorMsg = "";

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBodyResultNode restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, "");
    EXPECT_EQ(restored.errorCode, 123);
    EXPECT_EQ(restored.errorMsg, "");
}

HWTEST_F(MediaOperateResultVoTest, TC005_RespBody_Marshalling_Unmarshalling_Empty_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBody original;
    original.result.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.result.size(), 0);
}

HWTEST_F(MediaOperateResultVoTest, TC006_RespBody_Marshalling_Unmarshalling_Single_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBody original;
    MediaOperateResultRespBodyResultNode node;
    node.cloudId = "cloud_id_001";
    node.errorCode = 0;
    node.errorMsg = "success";
    original.result.push_back(node);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.result.size(), 1);
    EXPECT_EQ(restored.result[0].cloudId, "cloud_id_001");
}

HWTEST_F(MediaOperateResultVoTest, TC007_RespBody_Marshalling_Unmarshalling_Multiple_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBody original;

    MediaOperateResultRespBodyResultNode node1;
    node1.cloudId = "cloud_id_001";
    node1.errorCode = 0;
    node1.errorMsg = "success";
    original.result.push_back(node1);

    MediaOperateResultRespBodyResultNode node2;
    node2.cloudId = "cloud_id_002";
    node2.errorCode = -1;
    node2.errorMsg = "failed";
    original.result.push_back(node2);

    MediaOperateResultRespBodyResultNode node3;
    node3.cloudId = "cloud_id_003";
    node3.errorCode = 0;
    node3.errorMsg = "success";
    original.result.push_back(node3);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.result.size(), 3);
    EXPECT_EQ(restored.result[0].cloudId, "cloud_id_001");
    EXPECT_EQ(restored.result[1].cloudId, "cloud_id_002");
    EXPECT_EQ(restored.result[2].cloudId, "cloud_id_003");
}

HWTEST_F(MediaOperateResultVoTest, TC008_GetFailSize_AllSuccess_ReturnZero, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBody body;

    MediaOperateResultRespBodyResultNode node1;
    node1.errorCode = 0;
    body.result.push_back(node1);

    MediaOperateResultRespBodyResultNode node2;
    node2.errorCode = 0;
    body.result.push_back(node2);

    int32_t failSize = body.GetFailSize();
    EXPECT_EQ(failSize, 0);
}

HWTEST_F(MediaOperateResultVoTest, TC009_GetFailSize_AllFailed_ReturnCount, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    MediaOperateResultRespBody body;

    MediaOperateResultRespBodyResultNode node1;
    node1.errorCode = -1;
    body.result.push_back(node1);

    MediaOperateResultRespBodyResultNode node2;
    node2.errorCode = 1;
    body.result.push_back(node2);

    MediaOperateResultRespBodyResultNode node3;
    node3.errorCode = -2;
    body.result.push_back(node3);

    int32_t failSize = body.GetFailSize();
    EXPECT_EQ(failSize, 3);
}

HWTEST_F(MediaOperateResultVoTest, TC010_GetFailSize_Mixed_ReturnCorrectCount, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    MediaOperateResultRespBody body;

    MediaOperateResultRespBodyResultNode node1;
    node1.errorCode = 0;
    body.result.push_back(node1);

    MediaOperateResultRespBodyResultNode node2;
    node2.errorCode = -1;
    body.result.push_back(node2);

    MediaOperateResultRespBodyResultNode node3;
    node3.errorCode = 0;
    body.result.push_back(node3);

    MediaOperateResultRespBodyResultNode node4;
    node4.errorCode = 1;
    body.result.push_back(node4);

    int32_t failSize = body.GetFailSize();
    EXPECT_EQ(failSize, 2);
}

HWTEST_F(MediaOperateResultVoTest, TC011_GetFailSize_Empty_ReturnZero, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    MediaOperateResultRespBody body;
    body.result.clear();

    int32_t failSize = body.GetFailSize();
    EXPECT_EQ(failSize, 0);
}

HWTEST_F(MediaOperateResultVoTest, TC015_RespBody_Marshalling_Unmarshalling_LargeVector_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    MediaOperateResultRespBody original;
    for (int i = 0; i < 100; i++) {
        MediaOperateResultRespBodyResultNode node;
        node.cloudId = "cloud_id_" + std::to_string(i);
        node.errorCode = (i % 2 == 0) ? 0 : -1;
        node.errorMsg = (i % 2 == 0) ? "success" : "failed";
        original.result.push_back(node);
    }

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    MediaOperateResultRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.result.size(), 100);
    EXPECT_EQ(restored.GetFailSize(), 50);
}

}  // namespace OHOS::Media::CloudSync
