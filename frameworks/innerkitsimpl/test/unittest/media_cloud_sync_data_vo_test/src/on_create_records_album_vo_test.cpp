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

#include "on_create_records_album_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnCreateRecordsAlbumVoTest : public testing::Test {};

HWTEST_F(OnCreateRecordsAlbumVoTest, TC001_AlbumData_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCreateRecordsAlbumReqBodyAlbumData original;
    original.cloudId = "cloud_id_123";
    original.newCloudId = "new_cloud_id_456";
    original.localPath = "/local/photo.jpg";
    original.isSuccess = true;
    original.serverErrorCode = 0;
    original.errorType = static_cast<ErrorType>(0);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.newCloudId, original.newCloudId);
    EXPECT_EQ(restored.isSuccess, original.isSuccess);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC002_AlbumData_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC003_AlbumData_Unmarshalling_ReadStringNewCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC004_AlbumData_Unmarshalling_ReadStringLocalPath_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC005_AlbumData_Unmarshalling_ReadBoolIsSuccess_Fail, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(true);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC006_AlbumData_Unmarshalling_ReadInt32ServerErrorCode_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(true);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC007_AlbumData_Unmarshalling_ReadInt32ErrorType_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(true);
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC008_AlbumData_Unmarshalling_ErrorDetailsEmpty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(true);
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC009_AlbumData_Unmarshalling_ErrorDetailsSingle, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnCreateRecordsAlbumReqBodyAlbumData original;
    original.cloudId = "cloud_id_123";
    original.newCloudId = "new_cloud_id_456";
    original.localPath = "/local/photo.jpg";
    original.isSuccess = true;
    original.serverErrorCode = 0;
    original.errorType = static_cast<ErrorType>(0);
    CloudErrorDetail errorDetail;
    errorDetail.domain = "test_domain";
    errorDetail.reason = "test_reason";
    errorDetail.errorCode = "ERR_001";
    errorDetail.description = "test description";
    errorDetail.errorPos = "position_1";
    errorDetail.errorParam = "param_1";
    errorDetail.detailCode = 100;
    original.errorDetails.push_back(errorDetail);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.errorDetails.size(), 1);
    EXPECT_EQ(restored.errorDetails[0].domain, "test_domain");
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC010_AlbumData_Unmarshalling_ErrorDetailsMultiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnCreateRecordsAlbumReqBodyAlbumData original;
    original.cloudId = "cloud_id_123";
    original.newCloudId = "new_cloud_id_456";
    original.localPath = "/local/photo.jpg";
    original.isSuccess = true;
    original.serverErrorCode = 0;
    original.errorType = static_cast<ErrorType>(0);

    CloudErrorDetail errorDetail1;
    errorDetail1.domain = "test_domain_1";
    errorDetail1.reason = "test_reason_1";
    errorDetail1.errorCode = "ERR_001";
    errorDetail1.description = "test description 1";
    errorDetail1.errorPos = "position_1";
    errorDetail1.errorParam = "param_1";
    errorDetail1.detailCode = 100;
    original.errorDetails.push_back(errorDetail1);

    CloudErrorDetail errorDetail2;
    errorDetail2.domain = "test_domain_2";
    errorDetail2.reason = "test_reason_2";
    errorDetail2.errorCode = "ERR_002";
    errorDetail2.description = "test description 2";
    errorDetail2.errorPos = "position_2";
    errorDetail2.errorParam = "param_2";
    errorDetail2.detailCode = 200;
    original.errorDetails.push_back(errorDetail2);

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBodyAlbumData restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.errorDetails.size(), 2);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC011_ReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败
    OnCreateRecordsAlbumReqBody reqBody;
    ASSERT_EQ(reqBody.albums.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.albums.size(), 0);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC012_ReqBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnCreateRecordsAlbumReqBody reqBody;
    OnCreateRecordsAlbumReqBodyAlbumData albumData;
    albumData.cloudId = "cloud_id_123";
    albumData.newCloudId = "new_cloud_id_456";
    albumData.localPath = "/local/photo.jpg";
    albumData.isSuccess = true;
    albumData.serverErrorCode = 0;
    albumData.errorType = static_cast<ErrorType>(0);
    reqBody.albums.push_back(albumData);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.albums.size(), 1);
    EXPECT_EQ(restored.albums[0].cloudId, "cloud_id_123");
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC013_ReqBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常
    OnCreateRecordsAlbumReqBody reqBody;

    OnCreateRecordsAlbumReqBodyAlbumData albumData1;
    albumData1.cloudId = "cloud_id_1";
    albumData1.newCloudId = "new_cloud_id_1";
    albumData1.localPath = "/local/photo1.jpg";
    albumData1.isSuccess = true;
    albumData1.serverErrorCode = 0;
    albumData1.errorType = static_cast<ErrorType>(0);
    reqBody.albums.push_back(albumData1);

    OnCreateRecordsAlbumReqBodyAlbumData albumData2;
    albumData2.cloudId = "cloud_id_2";
    albumData2.newCloudId = "new_cloud_id_2";
    albumData2.localPath = "/local/photo2.jpg";
    albumData2.isSuccess = false;
    albumData2.serverErrorCode = 500;
    albumData2.errorType = static_cast<ErrorType>(1);
    reqBody.albums.push_back(albumData2);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.albums.size(), 2);
    EXPECT_EQ(restored.albums[0].isSuccess, true);
    EXPECT_EQ(restored.albums[1].isSuccess, false);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC014_ReqBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnCreateRecordsAlbumVoTest, TC015_ReqBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试反序列化溢出错误；覆盖错误路径（触发条件：输入为INT32_MAX）；验证业务状态断言：反序列化失败
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    OnCreateRecordsAlbumReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync
