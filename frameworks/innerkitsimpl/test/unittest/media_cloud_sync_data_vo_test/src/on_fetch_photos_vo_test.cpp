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

#include "on_fetch_photos_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnFetchPhotosVoTest : public testing::Test {};

HWTEST_F(OnFetchPhotosVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试OnFetchPhotosVo序列化/反序列化成功路径；覆盖所有字段正常读写（触发条件：所有字段有效）；验证业务状态断言：反序列化后关键字段值与原值一致

    OnFetchPhotosVo original;
    original.cloudId = "cloud_id_123";
    original.fileName = "photo.jpg";
    original.fileSourcePath = "/source/photo.jpg";
    original.mimeType = "image/jpeg";
    original.firstVisitTime = "2024-01-01";
    original.detailTime = "2024-01-01 12:00:00";
    original.frontCamera = "front";
    original.editDataCamera = "edit";
    original.title = "Test Photo";
    original.relativePath = "DCIM/Camera";
    original.virtualPath = "storage:/DCIM/Camera";
    original.dateYear = "2024";
    original.dateMonth = "01";
    original.dateDay = "01";
    original.shootingMode = "normal";
    original.shootingModeTag = "tag_1";
    original.burstKey = "burst_001";
    original.localPath = "/local/photo.jpg";
    original.latitude = 39.9;
    original.longitude = 116.4;
    original.description = "test photo";
    original.source = "camera";
    original.fileId = 123;
    original.mediaType = 1;
    original.fileType = 1;
    original.rotation = 0;
    original.photoHeight = 1080;
    original.photoWidth = 1920;
    original.duration = 0;
    original.hidden = 0;
    original.burstCoverLevel = 0;
    original.subtype = 1;
    original.originalSubtype = 1;
    original.dynamicRangeType = 0;
    original.hdrMode = 0;
    original.videoMode = 0;
    original.movingPhotoEffectMode = 0;
    original.supportedWatermarkType = 0;
    original.strongAssociation = 0;
    original.fixVersion = 1;
    original.version = 1;
    original.size = 1024000;
    original.lcdSize = 51200;
    original.thmSize = 25600;
    original.createTime = 1704067200;
    original.metaDateModified = 1704067200;
    original.dualEditTime = 0;
    original.editTime = 0;
    original.editedTimeMs = 0;
    original.recycledTime = 0;
    original.hiddenTime = 0;
    original.coverPosition = 0;
    original.isRectificationCover = 0;
    original.exifRotate = 0;
    original.isDelete = false;
    original.fileSourceType = 0;
    original.storagePath = "/storage";
    original.photoRiskStatus = 0;
    original.isCritical = 0;
    original.hasAttributes = true;
    original.hasproperties = true;
    original.isFavorite = true;
    original.isRecycle = false;
    original.sourceAlbumIds.push_back("album_1");
    original.sourceAlbumIds.push_back("album_2");

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFetchPhotosVo restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.fileName, original.fileName);
    EXPECT_EQ(restored.fileId, original.fileId);
    EXPECT_EQ(restored.size, original.size);
}

HWTEST_F(OnFetchPhotosVoTest, TC002_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试OnFetchPhotosVo反序列化失败路径；覆盖cloudId字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("cloud_id_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFetchPhotosVo vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnFetchPhotosVoTest, TC003_Unmarshalling_ReadInt32FileId_Fail, TestSize.Level1)
{
    // 用例说明：测试OnFetchPhotosVo反序列化失败路径；覆盖fileId字段读取失败（触发条件：MessageParcel.ReadInt32失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    parcel.WriteString("cloud_id_123");
    parcel.WriteString("photo.jpg");
    parcel.WriteString("/source/photo.jpg");
    parcel.WriteString("image/jpeg");
    parcel.WriteString("2024-01-01");
    parcel.WriteString("2024-01-01 12:00:00");
    parcel.WriteString("front");
    parcel.WriteString("edit");
    parcel.WriteString("Test Photo");
    parcel.WriteString("DCIM/Camera");
    parcel.WriteString("storage:/DCIM/Camera");
    parcel.WriteString("2024");
    parcel.WriteString("01");
    parcel.WriteString("01");
    parcel.WriteString("normal");
    parcel.WriteString("tag_1");
    parcel.WriteString("burst_001");
    parcel.WriteString("/local/photo.jpg");
    parcel.WriteDouble(39.9);
    parcel.WriteDouble(116.4);
    parcel.WriteString("test photo");
    parcel.WriteString("camera");

    parcel.RewindRead(0);
    OnFetchPhotosVo vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync

HWTEST_F(OnFetchPhotosVoTest, TC004_Unmarshalling_ReadBoolHasAttributes_Fail, TestSize.Level1)
{
    // 用例说明：测试OnFetchPhotosVo反序列化失败路径；覆盖hasAttributes字段读取失败（触发条件：MessageParcel.ReadBool失败）；验证业务状态断言：反序列化返回false

    OnFetchPhotosVo original;
    original.cloudId = "cloud_id_123";
    original.fileName = "photo.jpg";
    original.fileSourcePath = "/source/photo.jpg";
    original.mimeType = "image/jpeg";
    original.firstVisitTime = "2024-01-01";
    original.detailTime = "2024-01-01 12:00:00";
    original.frontCamera = "front";
    original.editDataCamera = "edit";
    original.title = "Test Photo";
    original.relativePath = "DCIM/Camera";
    original.virtualPath = "storage:/DCIM/Camera";
    original.dateYear = "2024";
    original.dateMonth = "01";
    original.dateDay = "01";
    original.shootingMode = "normal";
    original.shootingModeTag = "tag_1";
    original.burstKey = "burst_001";
    original.localPath = "/local/photo.jpg";
    original.latitude = 39.9;
    original.longitude = 116.4;
    original.description = "test photo";
    original.source = "camera";
    original.fileId = 123;
    original.mediaType = 1;
    original.fileType = 1;
    original.rotation = 0;
    original.photoHeight = 1080;
    original.photoWidth = 1920;
    original.duration = 0;
    original.hidden = 0;
    original.burstCoverLevel = 0;
    original.subtype = 1;
    original.originalSubtype = 1;
    original.dynamicRangeType = 0;
    original.hdrMode = 0;
    original.videoMode = 0;
    original.movingPhotoEffectMode = 0;
    original.supportedWatermarkType = 0;
    original.strongAssociation = 0;
    original.fixVersion = 1;
    original.version = 1;
    original.size = 1024000;
    original.lcdSize = 51200;
    original.thmSize = 25600;
    original.createTime = 1704067200;
    original.metaDateModified = 1704067200;
    original.dualEditTime = 0;
    original.editTime = 0;
    original.editedTimeMs = 0;
    original.recycledTime = 0;
    original.hiddenTime = 0;
    original.coverPosition = 0;
    original.isRectificationCover = 0;
    original.exifRotate = 0;
    original.isDelete = false;
    original.fileSourceType = 0;
    original.storagePath = "/storage";
    original.photoRiskStatus = 0;
    original.isCritical = 0;
    original.hasAttributes = true;
    original.hasproperties = true;
    original.isFavorite = true;
    original.isRecycle = false;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFetchPhotosVo vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}
