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

#include "on_delete_albums_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnDeleteAlbumsVoTest : public testing::Test {};

HWTEST_F(OnDeleteAlbumsVoTest, TC001_RespBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    OnDeleteAlbumsRespBody original;
    ASSERT_EQ(original.failedAlbumIds.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteAlbumsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failedAlbumIds.size(), 0);
}

HWTEST_F(OnDeleteAlbumsVoTest, TC002_RespBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnDeleteAlbumsRespBody original;
    original.failedAlbumIds.push_back("album_cloud_123");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteAlbumsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failedAlbumIds.size(), 1);
    EXPECT_EQ(restored.failedAlbumIds[0], "album_cloud_123");
}

HWTEST_F(OnDeleteAlbumsVoTest, TC003_RespBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnDeleteAlbumsRespBody original;
    original.failedAlbumIds.push_back("album_cloud_1");
    original.failedAlbumIds.push_back("album_cloud_2");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteAlbumsRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failedAlbumIds.size(), 2);
}

HWTEST_F(OnDeleteAlbumsVoTest, TC004_RespBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    OnDeleteAlbumsRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnDeleteAlbumsVoTest, TC005_RespBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    OnDeleteAlbumsRespBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
