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

#include <gtest/gtest.h>
#include <message_parcel.h>
#include "on_modify_records_photos_vo.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

class OnModifyRecordsPhotosVoTest : public testing::Test {};

HWTEST_F(OnModifyRecordsPhotosVoTest, TC001_PhotoData_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    OnModifyRecordsPhotosReqBodyPhotoData original;
    original.cloudId = "cloud_id_123";
    original.newCloudId = "new_cloud_id_456";
    original.localPath = "/local/photo.jpg";
    original.recycled = false;
    original.fileSize = 1024000;
    original.fileType = 1;
    original.serverErrorCode = 0;
    original.errorType = 0;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.newCloudId, original.newCloudId);
    EXPECT_EQ(restored.recycled, original.recycled);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC002_PhotoData_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC003_PhotoData_Unmarshalling_ReadStringNewCloudId_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC004_PhotoData_Unmarshalling_ReadStringLocalPath_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC005_PhotoData_Unmarshalling_ReadBoolRecycled_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(false);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC006_PhotoData_Unmarshalling_ReadInt64FileSize_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(false);
    parcel.WriteInt64(1024000);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC007_PhotoData_Unmarshalling_ReadInt32FileType_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(false);
    parcel.WriteInt64(1024000);
    parcel.WriteInt32(1);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC008_PhotoData_Unmarshalling_ReadInt32ServerErrorCode_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(false);
    parcel.WriteInt64(1024000);
    parcel.WriteInt32(1);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC009_PhotoData_Unmarshalling_ReadInt32ErrorType_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("new_cloud_id_456");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteBool(false);
    parcel.WriteInt64(1024000);
    parcel.WriteInt32(1);
    parcel.WriteInt32(0);
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC010_ReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    OnModifyRecordsPhotosReqBody reqBody;
    ASSERT_EQ(reqBody.photos.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 0);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC011_ReqBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    OnModifyRecordsPhotosReqBody reqBody;
    OnModifyRecordsPhotosPhotosReqBodyPhotoData photoData;
    photoData.cloudId = "cloud_id_123";
    photoData.newCloudId = "new_cloud_id_456";
    photoData.localPath = "/local/photo.jpg";
    photoData.recycled = false;
    photoData.fileSize = 1024000;
    photoData.fileType = 1;
    photoData.serverErrorCode = 0;
    photoData.errorType = 0;
    reqBody.photos.push_back(photoData);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 1);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC012_ReqBody_Marshalling_Unmarshalling_Multiple, TestSizeKeySize.Level1)
{
    OnModifyRecordsPhotosReqBody reqBody;
    
    OnModifyRecordsPhotosReqBodyPhotoData photoData1;
    photoData1.cloudId = "cloud_id_1";
    photoData1.newCloudId = "new_cloud_id_1";
    photoData1.localPath = "/local/photo1.jpg";
    photoData1.recycled = false;
    photoData1.fileSize = 1024000;
    photoData1.fileType = 1;
    photoData1.serverErrorCode = 0;
    photoData1.errorType = 0;
    reqBody.photos.push_back(photoData1);
    
    OnModifyRecordsPhotosReqBodyPhotoData photoData2;
    photoData2.cloudId = "cloud_id_2";
    photoData2.newCloudId = "new_cloud_id_2";
    photoData2.localPath = "/local/photo2.jpg";
    photoData2.recycled = true;
    photoData2.fileSize = 2048000;
    photoData2.fileType = 2;
    photoData2.serverErrorCode = 500;
    photoData2.errorType = 1;
    reqBody.photos.push_back(photoData2);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 2);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC013_ReqBody_Unmarshalling_ReadInt32Size_Fail, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC014_ReqBody_Unmarshalling_SizeOverflow, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    OnModifyRecordsPhotosReqBody vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC015_PhotoData_ToString, TestSize.Level1)
{
    OnModifyRecordsPhotosReqBodyPhotoData vo;
    vo.cloudId = "cloud_id_123";
    vo.newCloudId = "new_cloud_id_456";
    vo.localPath = "/local/photo.jpg";
    vo.recycled = false;
    vo.fileSize = 1024000;
    vo.fileType = 1;

    std::string str = vo.ToString();
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.find("cloud_id_123"), std::string::npos);
}

HWTEST_F(OnModifyRecordsPhotosVoTest, TC016_ReqBody_ToString, TestSize.Level1)
{
    OnModifyRecordsPhotosReqBody vo;
    OnModifyRecordsPhotosReqBodyPhotoData photoData;
    photoData.cloudId = "cloud_id_123";
    photoData.newCloudId = "new_cloud_id_456";
    photoData.localPath = "/local/photo.jpg";
    photoData.recycled = false;
    photoData.fileSize = 1024000;
    photoData.fileType = 1;
    photoData.serverErrorCode = 0;
    photoData.errorType = 0;
    vo.photos.push_back(photoData);

    std::string str = vo.ToString();
    EXPECT_FALSE(str.empty());
}
