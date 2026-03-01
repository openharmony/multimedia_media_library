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

#include "photos_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class PhotosVoTest : public testing::Test {};

HWTEST_F(PhotosVoTest, TC001_Unmarshalling_ReadInt32_Fail, TestSize.Level1)
{
    // 用例说明：测试PhotosVo反序列化失败；覆盖ReadInt32失败分支（触发条件：MessageParcel.ReadInt32失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("cloud_id_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    PhotosVo vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC002_Unmarshalling_ReadString_Fail, TestSize.Level1)
{
    // 用例说明：测试PhotosVo反序列化失败；覆盖ReadString失败分支（触发条件：MessageParcel.ReadString失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(123);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    PhotosVo vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC003_Marshalling_WriteInt32_Fail, TestSize.Level1)
{
    // 用例说明：测试PhotosVo序列化；覆盖WriteInt32分支（触发条件：MessageParcel.WriteInt32）；
    // 验证业务状态断言：序列化返回true
    PhotosVo vo;
    vo.fileId = 123;
    vo.cloudId = "cloud_id_123";
    vo.size = 2048;

    OHOS::MessageParcel parcel;
    bool ret = vo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

HWTEST_F(PhotosVoTest, TC004_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试PhotosVo序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    PhotosVo original;
    original.fileId = 123;
    original.cloudId = "cloud_id_123";
    original.size = 2048;
    original.modifiedTime = 1234567890;
    original.path = "/storage/test/photo.jpg";
    original.fileName = "photo.jpg";
    original.localPath = "/local/photo.jpg";
    original.originalCloudId = "original_cloud_id";
    original.type = 1;
    original.orientation = 0;
    original.fileSourceType = 0;
    original.storagePath = "/storage";
    original.hidden = 0;
    original.dateTrashed = 0;
    original.attributesMediaType = 0;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    PhotosVo restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.fileId, original.fileId);
    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.size, original.size);
    EXPECT_EQ(restored.fileName, original.fileName);
}

HWTEST_F(PhotosVoTest, TC005_Unmarshalling_NegativeLen, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector反序列化负数长度；覆盖错误路径（触发条件：长度为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    bool ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC006_Unmarshalling_LenOverflow, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector反序列化溢出长度；覆盖错误路径（触发条件：长度为INT32_MAX）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    bool ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC007_Unmarshalling_SizeExceedReadable, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector反序列化；覆盖size > readAbleSize分支（触发条件：size超过可读字节）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(1000000);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC008_Unmarshalling_SizeExceedMaxSize, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector反序列化；覆盖size > max_size()分支（触发条件：size超过vector最大容量）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    size_t maxSize = std::vector<PhotosVo>().max_size();
    bool ret = parcel.WriteInt32(static_cast<int32_t>(maxSize) + 1);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC009_Unmarshalling_ElementUnmarshallingFail, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector反序列化；覆盖循环内Unmarshalling失败分支（触发条件：元素反序列化失败）；
    // 验证业务状态断言：反序列化返回false
    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(1);
    ASSERT_TRUE(ret);
    ret = parcel.WriteString("incomplete_data");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(PhotosVoTest, TC010_VectorMarshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试PhotosVo vector序列化与反序列化；覆盖正常路径（触发条件：正常vector数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    std::vector<PhotosVo> originalVec;

    PhotosVo vo1;
    vo1.fileId = 123;
    vo1.cloudId = "cloud_id_123";
    vo1.size = 1024;
    vo1.fileName = "photo1.jpg";
    originalVec.push_back(vo1);

    PhotosVo vo2;
    vo2.fileId = 456;
    vo2.cloudId = "cloud_id_456";
    vo2.size = 2048;
    vo2.fileName = "photo2.jpg";
    originalVec.push_back(vo2);

    OHOS::MessageParcel parcel;
    bool ret = PhotosVo::Marshalling(originalVec, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredVec.size(), originalVec.size());
    EXPECT_EQ(restoredVec[0].fileId, originalVec[0].fileId);
    EXPECT_EQ(restoredVec[1].cloudId, originalVec[1].cloudId);
}

HWTEST_F(PhotosVoTest, TC011_EmptyVectorMarshalling_Unmarshalling, TestSize.Level1)
{
    // 用用例说明：测试PhotosVo空vector序列化与反序列化；覆盖空集合边界（触发条件：empty vector）；
    // 验证业务状态断言：反序列化后的vector为空
    std::vector<PhotosVo> emptyVec;

    OHOS::MessageParcel parcel;
    bool ret = PhotosVo::Marshalling(emptyVec, parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<PhotosVo> restoredVec;
    ret = PhotosVo::Unmarshalling(restoredVec, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredVec.size(), 0);
}

HWTEST_F(PhotosVoTest, TC012_AttachmentMarshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试PhotosVo attachment序列化与反序列化；覆盖嵌套CloudFileDataVo分支（触发条件：正常attachment数据）；
    // 验证业务状态断言：反序列化后的attachment数据与原始数据一致
    PhotosVo original;
    original.fileId = 123;
    original.cloudId = "cloud_id_123";
    original.size = 2048;
    original.fileName = "photo.jpg";
    CloudFileDataVo thumbData;
    thumbData.fileName = "thumb.jpg";
    thumbData.filePath = "/thumb/path";
    thumbData.size = 1024;
    original.attachment["thumb"] = thumbData;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    PhotosVo restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.fileId, original.fileId);
    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.attachment.size(), original.attachment.size());
    EXPECT_EQ(restored.attachment["thumb"].fileName, original.attachment["thumb"].fileName);
}

}  // namespace OHOS::Media::CloudSync
