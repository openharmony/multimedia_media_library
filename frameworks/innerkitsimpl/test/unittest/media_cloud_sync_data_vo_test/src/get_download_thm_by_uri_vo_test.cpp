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

#include "get_download_thm_by_uri_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class GetDownloadThmByUriVoTest : public testing::Test {};

HWTEST_F(GetDownloadThmByUriVoTest, TC001_ReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    GetDownloadThmsByUriReqBody original;
    original.thmType = 0;
    ASSERT_EQ(original.pathList.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 0);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC002_ReqBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadThmsByUriReqBody original;
    original.thmType = 1;
    original.pathList.push_back("/storage/path1");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 1);
    EXPECT_EQ(restored.pathList[0], "/storage/path1");
}

HWTEST_F(GetDownloadThmByUriVoTest, TC003_ReqBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadThmsByUriReqBody original;
    original.thmType = 2;
    original.pathList.push_back("/storage/path1");
    original.pathList.push_back("/storage/path2");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.pathList.size(), 2);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC004_ReqBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    GetDownloadThmsByUriReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC005_ReqBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    GetDownloadThmsByUriReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC007_RespBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    GetDownloadThmsByUriRespBody original;
    ASSERT_EQ(original.photos.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 0);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC008_RespBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadThmsByUriRespBody original;
    PhotosVo photo;
    photo.cloudId = "cloud_id_123";
    original.photos.push_back(photo);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 1);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC009_RespBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    GetDownloadThmsByUriRespBody original;
    PhotosVo photo1;
    photo1.cloudId = "cloud_id_123";
    original.photos.push_back(photo1);
    PhotosVo photo2;
    photo2.cloudId = "cloud_id_456";
    original.photos.push_back(photo2);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmsByUriRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 2);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC010_RespBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    GetDownloadThmsByUriRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(GetDownloadThmByUriVoTest, TC011_RespBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    GetDownloadThmsByUriRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
