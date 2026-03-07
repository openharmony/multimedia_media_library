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

#include "get_aging_file_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

class GetAgingFileVoTest : public testing::Test {};

HWTEST_F(GetAgingFileVoTest, TC001_ReqBody_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetAgingFileReqBody original;
    original.time = 1704067200;
    original.mediaType = 1;
    original.sizeLimit = 1024000;
    original.offset = 0;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetAgingFileReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.time, original.time);
    EXPECT_EQ(restored.mediaType, original.mediaType);
    EXPECT_EQ(restored.sizeLimit, original.sizeLimit);
}

HWTEST_F(GetAgingFileVoTest, TC002_ReqBody_Unmarshalling_ReadInt64Time_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt64(1704067200);

    parcel.RewindRead(0);
    GetAgingFileReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetAgingFileVoTest, TC003_ReqBody_Unmarshalling_ReadInt32MediaType_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt64(1704067200);
    parcel.WriteInt32(1);

    parcel.RewindRead(0);
    GetAgingFileReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetAgingFileVoTest, TC004_ReqBody_Unmarshalling_ReadInt32SizeLimit_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt64(1704067200);
    parcel.WriteInt32(1);
    parcel.WriteInt32(1024000);

    parcel.RewindRead(0);
    GetAgingFileReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetAgingFileVoTest, TC005_ReqBody_Unmarshalling_ReadInt32Offset_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt64(1704067200);
    parcel.WriteInt32(1);
    parcel.WriteInt32(1024000);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    GetAgingFileReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetAgingFileVoTest, TC006_RespBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    GetAgingFileRespBody original;
    ASSERT_EQ(original.photos.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetAgingFileRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 0);
}

HWTEST_F(GetAgingFileVoTest, TC007_RespBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetAgingFileRespBody original;
    PhotosVo photo;
    photo.fileId = 123;
    photo.cloudId = "cloud_id_123";
    photo.size = 1024;
    photo.fileName = "photo.jpg";
    original.photos.push_back(photo);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetAgingFileRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 1);
    EXPECT_EQ(restored.photos[0].fileId, 123);
}

HWTEST_F(GetAgingFileVoTest, TC008_RespBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetAgingFileRespBody original;
    PhotosVo photo1;
    photo1.fileId = 123;
    photo1.cloudId = "cloud_id_123";
    photo1.size = 1024;
    photo1.fileName = "photo1.jpg";
    original.photos.push_back(photo1);

    PhotosVo photo2;
    photo2.fileId = 456;
    photo2.cloudId = "cloud_id_456";
    photo2.size = 2048;
    photo2.fileName = "photo2.jpg";
    original.photos.push_back(photo2);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetAgingFileRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 2);
    EXPECT_EQ(restored.photos[1].fileId, 456);
}

}  // namespace OHOS::Media::CloudSync
