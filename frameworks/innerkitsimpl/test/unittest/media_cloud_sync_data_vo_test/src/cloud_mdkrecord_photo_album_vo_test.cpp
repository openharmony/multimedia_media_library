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

#include "cloud_mdkrecord_photo_album_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class CloudMdkRecordPhotoAlbumVoTest : public testing::Test {};

HWTEST_F(CloudMdkRecordPhotoAlbumVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    CloudMdkRecordPhotoAlbumVo original;
    original.cloudId = "album_cloud_123";
    original.albumName = "Test Album";
    original.albumType = 1;
    original.lpath = "DCIM/Album";

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudMdkRecordPhotoAlbumVo restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.albumName, original.albumName);
    EXPECT_EQ(restored.albumType, original.albumType);
}

HWTEST_F(CloudMdkRecordPhotoAlbumVoTest, TC002_Unmarshalling_ReadStringAlbumCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotoAlbumVo反序列化失败路径；
    // 覆盖albumCloudId字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("album_cloud_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    CloudMdkRecordPhotoAlbumVo vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudMdkRecordPhotoAlbumVoTest, TC003_Unmarshalling_ReadInt32AlbumType_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("album_cloud_123");
    parcel.WriteString("Test Album");

    parcel.RewindRead(0);
    CloudMdkRecordPhotoAlbumVo vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
