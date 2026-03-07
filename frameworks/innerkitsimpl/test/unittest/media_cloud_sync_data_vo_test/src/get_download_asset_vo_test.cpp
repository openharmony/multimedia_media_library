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

#include "get_download_asset_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class GetDownloadAssetVoTest : public testing::Test {};

HWTEST_F(GetDownloadAssetVoTest, TC001_ReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    GetDownloadAssetReqBody original;
    ASSERT_EQ(original.pathList.size(), 0);
    ASSERT_EQ(original.fileKeyList.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 0);
    EXPECT_EQ(restored.fileKeyList.size(), 0);
}

HWTEST_F(GetDownloadAssetVoTest, TC002_ReqBody_Marshalling_Unmarshalling_SinglePath, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadAssetReqBody original;
    original.pathList.push_back("/path/to/file1.jpg");
    original.fileKeyList.push_back("key1");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 1);
    EXPECT_EQ(restored.pathList[0], "/path/to/file1.jpg");
}

HWTEST_F(GetDownloadAssetVoTest, TC003_ReqBody_Marshalling_Unmarshalling_MultiplePaths, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadAssetReqBody original;
    original.pathList.push_back("/path/to/file1.jpg");
    original.pathList.push_back("/path/to/file2.jpg");
    original.fileKeyList.push_back("key1");
    original.fileKeyList.push_back("key2");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 2);
}

HWTEST_F(GetDownloadAssetVoTest, TC004_ReqBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    GetDownloadAssetReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetDownloadAssetVoTest, TC005_ReqBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    GetDownloadAssetReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetDownloadAssetVoTest, TC006_RespBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    GetDownloadAssetRespBody original;
    ASSERT_EQ(original.photos.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadAssetRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 0);
}

HWTEST_F(GetDownloadAssetVoTest, TC007_RespBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadAssetRespBody original;
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
    GetDownloadAssetRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 1);
    EXPECT_EQ(restored.photos[0].fileId, 123);
}

HWTEST_F(GetDownloadAssetVoTest, TC008_RespBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadAssetRespBody original;
    PhotosVo photo1;
    photo1.fileId = 1231;
    photo1.cloudId = "cloud_id_1231";
    photo1.size = 1024;
    photo1.fileName = "photo1.jpg";
    original.photos.push_back(photo1);

    PhotosVo photo2;
    photo2.fileId = 1232;
    photo2.cloudId = "cloud_id_1232";
    photo2.size = 2048;
    photo2.fileName = "photo2.jpg";
    original.photos.push_back(photo2);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadAssetRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 2);
}

}  // namespace OHOS::Media::CloudSync
