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

#include "cloud_file_data_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class CloudFileDataVoTest : public testing::Test {};

HWTEST_F(CloudFileDataVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    CloudFileDataVo original;
    original.fileName = "test_file.jpg";
    original.filePath = "/storage/test/test_file.jpg";
    original.size = 1024;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudFileDataVo restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.fileName, original.fileName);
    EXPECT_EQ(restored.filePath, original.filePath);
    EXPECT_EQ(restored.size, original.size);
}

HWTEST_F(CloudFileDataVoTest, TC002_Unmarshalling_NegativeSize, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo反序列化负数size；覆盖错误路径（触发条件：size为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteString("test_file.jpg");
    parcel.WriteString("/storage/test/test_file.jpg");
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    CloudFileDataVo vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudFileDataVoTest, TC003_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo反序列化溢出size；覆盖错误路径（触发条件：size为INT32_MAX）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteString("test_file.jpg");
    parcel.WriteString("/storage/test/test_file.jpg");
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    CloudFileDataVo vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudFileDataVoTest, TC004_MapMarshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo
    // map序列化与反序列化；覆盖正常路径（触发条件：正常map数据）；验证业务状态断言：反序列化后的map数据与原始数据一致

    std::map<std::string, CloudFileDataVo> originalMap;
    CloudFileDataVo vo1;
    vo1.fileName = "file1.jpg";
    vo1.filePath = "/path1/file1.jpg";
    vo1.size = 1024;
    originalMap["key1"] = vo1;

    CloudFileDataVo vo2;
    vo2.fileName = "file2.jpg";
    vo2.filePath = "/path2/file2.jpg";
    vo2.size = 2048;
    originalMap["key2"] = vo2;

    OHOS::MessageParcel parcel;
    bool ret = CloudFileDataVo::Marshalling(originalMap, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> restoredMap;
    ret = CloudFileDataVo::Unmarshalling(restoredMap, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredMap.size(), originalMap.size());
    EXPECT_EQ(restoredMap["key1"].fileName, originalMap["key1"].fileName);
    EXPECT_EQ(restoredMap["key2"].size, originalMap["key2"].size);
}

HWTEST_F(CloudFileDataVoTest, TC005_MapUnmarshalling_NegativeSize, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo
    // map反序列化负数size；覆盖错误路径（触发条件：map
    // size为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> voMap;
    bool ret = CloudFileDataVo::Unmarshalling(voMap, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudFileDataVoTest, TC006_MapMarshalling_EmptyMap_Success, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo空map序列化与反序列化；覆盖边界路径（触发条件：空map）；验证业务状态断言：反序列化后的map为空

    std::map<std::string, CloudFileDataVo> emptyMap;

    OHOS::MessageParcel parcel;
    bool ret = CloudFileDataVo::Marshalling(emptyMap, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> restoredMap;
    ret = CloudFileDataVo::Unmarshalling(restoredMap, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredMap.size(), 0);
}

HWTEST_F(CloudFileDataVoTest, TC007_MapMarshalling_SingleElement_Success, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo单元素map序列化与反序列化；覆盖边界路径（触发条件：单元素map）；验证业务状态断言：反序列化后的数据与原始数据一致

    std::map<std::string, CloudFileDataVo> singleMap;
    CloudFileDataVo vo;
    vo.fileName = "file1.jpg";
    vo.filePath = "/path1/file1.jpg";
    vo.size = 1024;
    singleMap["key1"] = vo;

    OHOS::MessageParcel parcel;
    bool ret = CloudFileDataVo::Marshalling(singleMap, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> restoredMap;
    ret = CloudFileDataVo::Unmarshalling(restoredMap, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredMap.size(), 1);
    EXPECT_EQ(restoredMap["key1"].fileName, "file1.jpg");
    EXPECT_EQ(restoredMap["key1"].size, 1024);
}

HWTEST_F(CloudFileDataVoTest, TC008_MapMarshalling_MultipleElements_Success, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo多元素map序列化与反序列化；覆盖正常路径（触发条件：多元素map）；验证业务状态断言：反序列化后的数据与原始数据一致

    std::map<std::string, CloudFileDataVo> multiMap;
    CloudFileDataVo vo1;
    vo1.fileName = "file1.jpg";
    vo1.filePath = "/path1/file1.jpg";
    vo1.size = 1024;
    multiMap["key1"] = vo1;

    CloudFileDataVo vo2;
    vo2.fileName = "file2.jpg";
    vo2.filePath = "/path2/file2.jpg";
    vo2.size = 2048;
    multiMap["key2"] = vo2;

    OHOS::MessageParcel parcel;
    bool ret = CloudFileDataVo::Marshalling(multiMap, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> restoredMap;
    ret = CloudFileDataVo::Unmarshalling(restoredMap, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredMap.size(), 2);
    EXPECT_EQ(restoredMap["key1"].fileName, "file1.jpg");
    EXPECT_EQ(restoredMap["key2"].fileName, "file2.jpg");
    EXPECT_EQ(restoredMap["key1"].size, 1024);
    EXPECT_EQ(restoredMap["key2"].size, 2048);
}

HWTEST_F(CloudFileDataVoTest, TC009_MapMarshalling_NegativeSize_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo
    // map反序列化负数size失败；覆盖错误路径（触发条件：map
    // size为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> voMap;
    bool ret = CloudFileDataVo::Unmarshalling(voMap, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudFileDataVoTest, TC010_MapMarshalling_SizeOverflow_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudFileDataVo
    // map反序列化溢出size失败；覆盖错误路径（触发条件：map
    // size为INT32_MAX）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    std::map<std::string, CloudFileDataVo> voMap;
    bool ret = CloudFileDataVo::Unmarshalling(voMap, parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
