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

#include "photos_po_test.h"
#include "photos_po.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace ORM {

void PhotosPoTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("PhotosPoTest SetUpTestCase");
}

void PhotosPoTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("PhotosPoTest TearDownTestCase");
}

void PhotosPoTest::SetUp(void)
{
    MEDIA_INFO_LOG("PhotosPoTest SetUp");
}

void PhotosPoTest::TearDown(void)
{
    MEDIA_INFO_LOG("PhotosPoTest TearDown");
}

HWTEST_F(PhotosPoTest, GetAlbumInfo_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAlbumInfo_Test_001");
    PhotosPo photosPo;
    photosPo.albumCloudId = "test_album_cloud_id";
    photosPo.albumLPath = "/test/album/lpath";
    
    std::stringstream ss;
    photosPo.GetAlbumInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("albumCloudId") != std::string::npos);
    EXPECT_TRUE(result.find("albumLPath") != std::string::npos);
    MEDIA_INFO_LOG("End GetAlbumInfo_Test_001");
}

HWTEST_F(PhotosPoTest, GetAlbumInfo_Empty_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAlbumInfo_Empty_Test_002");
    PhotosPo photosPo;
    
    std::stringstream ss;
    photosPo.GetAlbumInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("albumCloudId") != std::string::npos);
    EXPECT_TRUE(result.find("albumLPath") != std::string::npos);
    MEDIA_INFO_LOG("End GetAlbumInfo_Empty_Test_002");
}

HWTEST_F(PhotosPoTest, GetBasicInfo_Test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetBasicInfo_Test_003");
    PhotosPo photosPo;
    photosPo.fileId = 12345;
    photosPo.cloudId = "test_cloud_id";
    photosPo.size = 1024000;
    photosPo.displayName = "test_display_name";
    photosPo.isFavorite = 1;
    photosPo.hidden = 0;
    photosPo.hiddenTime = 1234567890;
    photosPo.dateTrashed = 0;
    photosPo.orientation = 90;
    photosPo.sourcePath = "/test/source/path";
    
    std::stringstream ss;
    photosPo.GetBasicInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("fileId") != std::string::npos);
    EXPECT_TRUE(result.find("cloudId") != std::string::npos);
    EXPECT_TRUE(result.find("size") != std::string::npos);
    EXPECT_TRUE(result.find("displayName") != std::string::npos);
    EXPECT_TRUE(result.find("isFavorite") != std::string::npos);
    EXPECT_TRUE(result.find("hidden") != std::string::npos);
    EXPECT_TRUE(result.find("hiddenTime") != std::string::npos);
    EXPECT_TRUE(result.find("dateTrashed") != std::string::npos);
    EXPECT_TRUE(result.find("orientation") != std::string::npos);
    EXPECT_TRUE(result.find("sourcePath") != std::string::npos);
    MEDIA_INFO_LOG("End GetBasicInfo_Test_003");
}

HWTEST_F(PhotosPoTest, GetBasicInfo_ZeroValues_Test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetBasicInfo_ZeroValues_Test_004");
    PhotosPo photosPo;
    photosPo.fileId = 0;
    photosPo.cloudId = "";
    photosPo.size = 0;
    photosPo.displayName = "";
    photosPo.isFavorite = 0;
    photosPo.hidden = 0;
    photosPo.hiddenTime = 0;
    photosPo.dateTrashed = 0;
    photosPo.orientation = 0;
    photosPo.sourcePath = "";
    
    std::stringstream ss;
    photosPo.GetBasicInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("fileId") != std::string::npos);
    EXPECT_TRUE(result.find("cloudId") != std::string::npos);
    EXPECT_TRUE(result.find("size") != std::string::npos);
    EXPECT_TRUE(result.find("displayName") != std::string::npos);
    MEDIA_INFO_LOG("End GetBasicInfo_ZeroValues_Test_004");
}

HWTEST_F(PhotosPoTest, GetPropertiesInfo_Test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetPropertiesInfo_Test_005");
    PhotosPo photosPo;
    photosPo.deviceName = "test_device";
    photosPo.dateAdded = 1234567890;
    photosPo.dateModified = 1234567891;
    photosPo.dateTaken = 1234567892;
    photosPo.duration = 30000;
    photosPo.dateYear = "2025";
    photosPo.dateMonth = "03";
    photosPo.dateDay = "06";
    photosPo.detailTime = "1234567893";
    photosPo.editTime = 1234567894;
    
    std::stringstream ss;
    photosPo.GetPropertiesInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("deviceName") != std::string::npos);
    EXPECT_TRUE(result.find("dateAdded") != std::string::npos);
    EXPECT_TRUE(result.find("dateModified") != std::string::npos);
    EXPECT_TRUE(result.find("dateTaken") != std::string::npos);
    EXPECT_TRUE(result.find("duration") != std::string::npos);
    EXPECT_TRUE(result.find("dateYear") != std::string::npos);
    EXPECT_TRUE(result.find("dateMonth") != std::string::npos);
    EXPECT_TRUE(result.find("dateDay") != std::string::npos);
    EXPECT_TRUE(result.find("detailTime") != std::string::npos);
    EXPECT_TRUE(result.find("editTime") != std::string::npos);
    MEDIA_INFO_LOG("End GetPropertiesInfo_Test_005");
}

HWTEST_F(PhotosPoTest, GetAttributesInfo_Test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAttributesInfo_Test_006");
    PhotosPo photosPo;
    photosPo.ownerAlbumId = 100;
    photosPo.data = "/test/data/path";
    photosPo.title = "test_title";
    photosPo.mediaType = 1;
    photosPo.mimeType = "image/jpeg";
    photosPo.relativePath = "/test/relative/path";
    photosPo.virtualPath = "/test/virtual/path";
    photosPo.latitude = 39.9042;
    photosPo.longitude = 116.3912;
    photosPo.height = 1920;
    photosPo.width = 1080;
    photosPo.subtype = 1;
    photosPo.burstCoverLevel = 0;
    photosPo.burstKey = "test_burst_key";
    photosPo.userComment = "test comment";
    photosPo.thumbStatus = 1;
    photosPo.syncStatus = 1;
    photosPo.shootingMode = "normal";
    photosPo.shootingModeTag = "tag";
    photosPo.dynamicRangeType = 1;
    photosPo.frontCamera = "0";
    photosPo.coverPosition = 0;
    photosPo.isRectificationCover = 0;
    photosPo.movingPhotoEffectMode = 0;
    photosPo.supportedWatermarkType = 1;
    photosPo.isStylePhoto = 0;
    photosPo.strongAssociation = 0;
    photosPo.southDeviceType = 1;
    
    std::stringstream ss;
    photosPo.GetAttributesInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("ownerAlbumId") != std::string::npos);
    EXPECT_TRUE(result.find("data") != std::string::npos);
    EXPECT_TRUE(result.find("title") != std::string::npos);
    EXPECT_TRUE(result.find("mediaType") != std::string::npos);
    EXPECT_TRUE(result.find("mimeType") != std::string::npos);
    EXPECT_TRUE(result.find("relativePath") != std::string::npos);
    EXPECT_TRUE(result.find("virtualPath") != std::string::npos);
    EXPECT_TRUE(result.find("latitude") != std::string::npos);
    EXPECT_TRUE(result.find("longitude") != std::string::npos);
    EXPECT_TRUE(result.find("height") != std::string::npos);
    EXPECT_TRUE(result.find("width") != std::string::npos);
    MEDIA_INFO_LOG("End GetAttributesInfo_Test_006");
}

HWTEST_F(PhotosPoTest, GetAttributesInfo_Test_006_V2, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAttributesInfo_Test_006");
    PhotosPo photosPo;
    photosPo.ownerAlbumId = 100;
    photosPo.data = "/test/data/path";
    photosPo.title = "test_title";
    photosPo.mediaType = 1;
    photosPo.mimeType = "image/jpeg";
    photosPo.relativePath = "/test/relative/path";
    photosPo.virtualPath = "/test/virtual/path";
    photosPo.latitude = 39.9042;
    photosPo.longitude = 116.3912;
    photosPo.height = 1920;
    photosPo.width = 1080;
    photosPo.subtype = 1;
    photosPo.burstCoverLevel = 0;
    photosPo.burstKey = "test_burst_key";
    photosPo.userComment = "test comment";
    photosPo.thumbStatus = 1;
    photosPo.syncStatus = 1;
    photosPo.shootingMode = "normal";
    photosPo.shootingModeTag = "tag";
    photosPo.dynamicRangeType = 1;
    photosPo.frontCamera = "0";
    photosPo.coverPosition = 0;
    photosPo.isRectificationCover = 0;
    photosPo.movingPhotoEffectMode = 0;
    photosPo.supportedWatermarkType = 1;
    photosPo.isStylePhoto = 0;
    photosPo.strongAssociation = 0;
    photosPo.southDeviceType = 1;
    
    std::stringstream ss;
    photosPo.GetAttributesInfo(ss);
    std::string result = ss.str();

    EXPECT_TRUE(result.find("subtype") != std::string::npos);
    EXPECT_TRUE(result.find("burstCoverLevel") != std::string::npos);
    EXPECT_TRUE(result.find("burstKey") != std::string::npos);
    EXPECT_TRUE(result.find("userComment") != std::string::npos);
    EXPECT_TRUE(result.find("thumbStatus") != std::string::npos);
    EXPECT_TRUE(result.find("syncStatus") != std::string::npos);
    EXPECT_TRUE(result.find("shootingMode") != std::string::npos);
    EXPECT_TRUE(result.find("shootingModeTag") != std::string::npos);
    EXPECT_TRUE(result.find("dynamicRangeType") != std::string::npos);
    EXPECT_TRUE(result.find("frontCamera") != std::string::npos);
    EXPECT_TRUE(result.find("coverPosition") != std::string::npos);
    EXPECT_TRUE(result.find("isRectificationCover") != std::string::npos);
    MEDIA_INFO_LOG("End GetAttributesInfo_Test_006");
}

HWTEST_F(PhotosPoTest, GetCloudInfo_Test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetCloudInfo_Test_007");
    PhotosPo photosPo;
    photosPo.position = 1;
    photosPo.metaDateModified = 1234567890;
    photosPo.originalSubtype = 0;
    photosPo.dirty = 1;
    photosPo.baseVersion = 1;
    photosPo.cloudVersion = 2;
    photosPo.originalAssetCloudId = "original_cloud_id";
    
    std::stringstream ss;
    photosPo.GetCloudInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("position") != std::string::npos);
    EXPECT_TRUE(result.find("metaDateModified") != std::string::npos);
    EXPECT_TRUE(result.find("originalSubtype") != std::string::npos);
    EXPECT_TRUE(result.find("dirty") != std::string::npos);
    EXPECT_TRUE(result.find("baseVersion") != std::string::npos);
    EXPECT_TRUE(result.find("cloudVersion") != std::string::npos);
    EXPECT_TRUE(result.find("originalAssetCloudId") != std::string::npos);
    MEDIA_INFO_LOG("End GetCloudInfo_Test_007");
}

HWTEST_F(PhotosPoTest, GetRemoveAlbumCloudInfo_Test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetRemoveAlbumCloudInfo_Test_008");
    PhotosPo photosPo;
    photosPo.removeAlbumCloudId = {"id1", "id2", "id3"};
    
    std::stringstream ss;
    photosPo.GetRemoveAlbumCloudInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("removeAlbumCloudId") != std::string::npos);
    EXPECT_TRUE(result.find("id1") != std::string::npos);
    EXPECT_TRUE(result.find("id2") != std::string::npos);
    EXPECT_TRUE(result.find("id3") != std::string::npos);
    MEDIA_INFO_LOG("End GetRemoveAlbumCloudInfo_Test_008");
}

HWTEST_F(PhotosPoTest, GetRemoveAlbumCloudInfo_Empty_Test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetRemoveAlbumCloudInfo_Empty_Test_009");
    PhotosPo photosPo;
    photosPo.removeAlbumCloudId = {};
    
    std::stringstream ss;
    photosPo.GetRemoveAlbumCloudInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("removeAlbumCloudId") != std::string::npos);
    EXPECT_TRUE(result.find("[]") != std::string::npos);
    MEDIA_INFO_LOG("End GetRemoveAlbumCloudInfo_Empty_Test_009");
}

HWTEST_F(PhotosPoTest, ToString_Test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ToString_Test_010");
    PhotosPo photosPo;
    photosPo.fileId = 12345;
    photosPo.cloudId = "test_cloud_id";
    photosPo.albumCloudId = "test_album_id";
    
    std::string result = photosPo.ToString();
    
    EXPECT_TRUE(result.find("fileId") != std::string::npos);
    EXPECT_TRUE(result.find("cloudId") != std::string::npos);
    EXPECT_TRUE(result.find("albumCloudId") != std::string::npos);
    MEDIA_INFO_LOG("End ToString_Test_010");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_NewWithoutCloudId_Test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_NewWithoutCloudId_Test_012");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosPo.cloudId = "";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    bool result = photosPo.IsCloudAsset();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End IsCloudAsset_NewWithoutCloudId_Test_012");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_NewLocalPosition_Test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_NewLocalPosition_Test_013");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosPo.cloudId = "test_cloud_id";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    
    bool result = photosPo.IsCloudAsset();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End IsCloudAsset_NewLocalPosition_Test_013");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_SyncedWithoutCloudId_Test_015, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_SyncedWithoutCloudId_Test_015");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_SYNCED);
    photosPo.cloudId = "";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    bool result = photosPo.IsCloudAsset();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End IsCloudAsset_SyncedWithoutCloudId_Test_015");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_SdirtytyWithoutCloudId_Test_018, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_SdirtytyWithoutCloudId_Test_018");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_SDIRTY);
    photosPo.cloudId = "";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    bool result = photosPo.IsCloudAsset();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End IsCloudAsset_SdirtytyWithoutCloudId_Test_018");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_TdirtytyWithoutCloudId_Test_020, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_TdirtytyWithoutCloudId_Test_020");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_TDIRTY);
    photosPo.cloudId = "";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    bool result = photosPo.IsCloudAsset();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End IsCloudAsset_TdirtytyWithoutCloudId_Test_020");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsMediaFile_MEDIA_Test_026, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsMediaFile_MEDIA_Test_026");
    PhotosPo photosPo;
    photosPo.fileSourceType = static_cast<int32_t>(FileSourceType::MEDIA);
    
    bool result = photosPo.ShouldHandleAsMediaFile();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End ShouldHandleAFileSourceType::CLOUD)sMediaFile_MEDIA_Test_026");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsMediaFile_Invalid_Test_028, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsMediaFile_Invalid_Test_028");
    PhotosPo photosPo;
    photosPo.fileSourceType = 999;
    
    bool result = photosPo.ShouldHandleAsMediaFile();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End ShouldHandleAsMediaFile_Invalid_Test_028");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsLakeFile_WithStoragePath_Test_029, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsLakeFile_WithStoragePath_Test_029");
    PhotosPo photosPo;
    photosPo.storagePath = "/test/storage/path";
    
    bool result = photosPo.ShouldHandleAsLakeFile();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End ShouldHandleAsLakeFile_WithStoragePath_Test_029");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsLakeFile_WithoutStoragePath_Test_030, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsLakeFile_WithoutStoragePath_Test_030");
    PhotosPo photosPo;
    photosPo.storagePath = "";
    
    bool result = photosPo.ShouldHandleAsLakeFile();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End ShouldHandleAsLakeFile_WithoutStoragePath_Test_030");
}

HWTEST_F(PhotosPoTest, GetAlbumInfo_MultipleCalls_Test_038, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAlbumInfo_MultipleCalls_Test_038");
    PhotosPo photosPo;
    photosPo.albumCloudId = "test_id";
    
    std::stringstream ss1, ss2;
    photosPo.GetAlbumInfo(ss1);
    photosPo.GetAlbumInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetAlbumInfo_MultipleCalls_Test_038");
}

HWTEST_F(PhotosPoTest, GetBasicInfo_MultipleCalls_Test_039, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetBasicInfo_MultipleCalls_Test_039");
    PhotosPo photosPo;
    photosPo.fileId = 12345;
    
    std::stringstream ss1, ss2;
    photosPo.GetBasicInfo(ss1);
    photosPo.GetBasicInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetBasicInfo_MultipleCalls_Test_039");
}

HWTEST_F(PhotosPoTest, GetPropertiesInfo_MultipleCalls_Test_040, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetPropertiesInfo_MultipleCalls_Test_040");
    PhotosPo photosPo;
    photosPo.dateAdded = 1234567890;
    
    std::stringstream ss1, ss2;
    photosPo.GetPropertiesInfo(ss1);
    photosPo.GetPropertiesInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetPropertiesInfo_MultipleCalls_Test_040");
}

HWTEST_F(PhotosPoTest, GetAttributesInfo_MultipleCalls_Test_041, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAttributesInfo_MultipleCalls_Test_041");
    PhotosPo photosPo;
    photosPo.mediaType = 1;
    
    std::stringstream ss1, ss2;
    photosPo.GetAttributesInfo(ss1);
    photosPo.GetAttributesInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetAttributesInfo_MultipleCalls_Test_041");
}

HWTEST_F(PhotosPoTest, GetCloudInfo_MultipleCalls_Test_042, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetCloudInfo_MultipleCalls_Test_042");
    PhotosPo photosPo;
    photosPo.dirty = 1;
    
    std::stringstream ss1, ss2;
    photosPo.GetCloudInfo(ss1);
    photosPo.GetCloudInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetCloudInfo_MultipleCalls_Test_042");
}

HWTEST_F(PhotosPoTest, GetRemoveAlbumCloudInfo_MultipleCalls_Test_043, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetRemoveAlbumCloudInfo_MultipleCalls_Test_043");
    PhotosPo photosPo;
    photosPo.removeAlbumCloudId = {"id1", "id2"};
    
    std::stringstream ss1, ss2;
    photosPo.GetRemoveAlbumCloudInfo(ss1);
    photosPo.GetRemoveAlbumCloudInfo(ss2);
    
    std::string result1 = ss1.str();
    std::string result2 = ss2.str();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End GetRemoveAlbumCloudInfo_MultipleCalls_Test_043");
}

HWTEST_F(PhotosPoTest, ToString_MultipleCalls_Test_044, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ToString_MultipleCalls_Test_044");
    PhotosPo photosPo;
    photosPo.fileId = 12345;
    
    std::string result1 = photosPo.ToString();
    std::string result2 = photosPo.ToString();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End ToString_MultipleCalls_Test_044");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_MultipleCalls_Test_ari, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_MultipleCalls_Test_044");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosPo.cloudId = "test_id";
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    bool result1 = photosPo.IsCloudAsset();
    bool result2 = photosPo.IsCloudAsset();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End IsCloudAsset_MultipleCalls_Test_044");
}

HWTEST_F(PhotosPoTest, TryGetMdirty_MultipleCalls_Test_045, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start TryGetMdirty_MultipleCalls_Test_045");
    PhotosPo photosPo;
    photosPo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    
    int32_t result1 = photosPo.TryGetMdirty();
    int32_t result2 = photosPo.TryGetMdirty();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End TryGetMdirty_MultipleCalls_Test_045");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsMediaFile_MultipleCalls_Test_046, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsMediaFile_MultipleCalls_Test_046");
    PhotosPo photosPo;
    photosPo.fileSourceType = static_cast<int32_t>(FileSourceType::MEDIA);
    
    bool result1 = photosPo.ShouldHandleAsMediaFile();
    bool result2 = photosPo.ShouldHandleAsMediaFile();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End ShouldHandleAsMediaFile_MultipleCalls_Test_046");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsLakeFile_MultipleCalls_Test_047, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsLakeFile_MultipleCalls_Test_047");
    PhotosPo photosPo;
    photosPo.storagePath = "/test/path";
    
    bool result1 = photosPo.ShouldHandleAsLakeFile();
    bool result2 = photosPo.ShouldHandleAsLakeFile();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End ShouldHandleAsLakeFile_MultipleCalls_Test_047");
}

HWTEST_F(PhotosPoTest, BuildFileUri_MultipleCalls_Test_048, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start BuildFileUri_MultipleCalls_Test_048");
    PhotosPo photosPo;
    photosPo.fileId = 12345;
    photosPo.data = "/test/path/test.jpg";
    photosPo.displayName = "test_name";
    
    std::string result1 = photosPo.BuildFileUri();
    std::string result2 = photosPo.BuildFileUri();
    
    EXPECT_EQ(result1, result2);
    MEDIA_INFO_LOG("End BuildFileUri_MultipleCalls_Test_048");
}

HWTEST_F(PhotosPoTest, GetAlbumInfo_LongStrings_Test_049, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAlbumInfo_LongStrings_Test_049");
    PhotosPo photosPo;
    photosPo.albumCloudId = "very_long_album_cloud_id_string_that_exceeds_normal_length_for_testing_purposes";
    photosPo.albumLPath = "/very/long/album/lpath/string/that/exceeds/normal/length/for/testing/purposes";
    
    std::stringstream ss;
    photosPo.GetAlbumInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("albumCloudId") != std::string::npos);
    EXPECT_TRUE(result.find("albumLPath") != std::string::npos);
    MEDIA_INFO_LOG("End GetAlbumInfo_LongStrings_Test_049");
}

HWTEST_F(PhotosPoTest, GetBasicInfo_LongStrings_Test_050, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetBasicInfo_LongStrings_Test_050");
    PhotosPo photosPo;
    photosPo.displayName = "very_long_display_name_string_that_exceeds_normal_length_for_testing_purposes";
    photosPo.sourcePath = "/very/long/source/path/string/that/exceeds/normal/length/for/testing/purposes";
    
    std::stringstream ss;
    photosPo.GetBasicInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("displayName") != std::string::npos);
    EXPECT_TRUE(result.find("sourcePath") != std::string::npos);
    MEDIA_INFO_LOG("End GetarBasicInfo_LongStrings_Test_050");
}

HWTEST_F(PhotosPoTest, GetAttributesInfo_LongStrings_Test_052, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetAttributesInfo_LongStrings_Test_052");
    PhotosPo photosPo;
    photosPo.mimeType = "very_long_mime_type_string_that_exceeds_normal_length_for_testing_purposes";
    photosPo.burstKey = "very_long_burst_key_string_that_exceeds_normal_length_for_testing_purposes";
    photosPo.userComment = "very_long_user_comment_string_that_exceeds_normal_length_for_testing_purposes";
    
    std::stringstream ss;
    photosPo.GetAttributesInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("mimeType") != std::string::npos);
    EXPECT_TRUE(result.find("burstKey") != std::string::npos);
    EXPECT_TRUE(result.find("userComment") != std::string::npos);
    MEDIA_INFO_LOG("End GetAttributesInfo_LongStrings_Test_052");
}

HWTEST_F(PhotosPoTest, GetRemoveAlbumCloudInfo_ManyIds_Test_054, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start GetRemoveAlbumCloudInfo_ManyIds_Test_054");
    PhotosPo photosPo;
    photosPo.removeAlbumCloudId = {"id1", "id2", "id3", "id4", "id5", "id6", "id7", "id8", "id9", "id10"};
    
    std::stringstream ss;
    photosPo.GetRemoveAlbumCloudInfo(ss);
    std::string result = ss.str();
    
    EXPECT_TRUE(result.find("id1") != std::string::npos);
    EXPECT_TRUE(result.find("id5") != std::string::npos);
    EXPECT_TRUE(result.find("id10") != std::string::npos);
    MEDIA_INFO_LOG("End GetRemoveAlbumCloudInfo_ManyIds_Test_054");
}

HWTEST_F(PhotosPoTest, IsCloudAsset_EdgeCases_Test_058, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start IsCloudAsset_EdgeCases_Test_058");
    PhotosPo photosPo1;
    photosPo1.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosPo1.cloudId = "";
    photosPo1.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    
    PhotosPo photosPo2;
    photosPo2.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosPo2.cloudId = "test_id";
    photosPo2.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    
    bool result1 = photosPo1.IsCloudAsset();
    bool result2 = photosPo2.IsCloudAsset();
    
    EXPECT_FALSE(result1);
    EXPECT_FALSE(result2);
    MEDIA_INFO_LOG("End IsCloudAsset_EdgeCases_Test_058");
}

HWTEST_F(PhotosPoTest, TryGetMdirty_EdgeCases_Test_059, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start TryGetMdirty_EdgeCases_Test_059");
    PhotosPo photosPo1;
    photosPo1.dirty = static_cast<int32_t>(DirtyType::TYPE_SYNCED);
    
    PhotosPo photosPo2;
    photosPo2.dirty = static_cast<int32_t>(DirtyType::TYPE_SDIRTY);
    
    int32_t result1 = photosPo1.TryGetMdirty();
    int32_t result2 = photosPo2.TryGetMdirty();
    
    EXPECT_EQ(result1, static_cast<int32_t>(DirtyType::TYPE_MDIRTY));
    EXPECT_EQ(result2, static_cast<int32_t>(DirtyType::TYPE_MDIRTY));
    MEDIA_INFO_LOG("End TryGetMdirty_EdgeCases_Test_059");
}

HWTEST_F(PhotosPoTest, ShouldHandleAsLakeFile_EdgeCases_Test_061, TestSize.Level1)
{
    MEDIA_INFO_LOG("Start ShouldHandleAsLakeFile_EdgeCases_Test_061");
    PhotosPo photosPo1;
    photosPo1.storagePath = "";
    
    PhotosPo photosPo2;
    photosPo2.storagePath = "/test/path";
    
    bool result1 = photosPo1.ShouldHandleAsLakeFile();
    bool result2 = photosPo2.ShouldHandleAsLakeFile();
    
    EXPECT_FALSE(result1);
    EXPECT_TRUE(result2);
    MEDIA_INFO_LOG("End ShouldHandleAsLakeFile_EdgeCases_Test_061");
}
}  // namespace ORM
}  // namespace Media
}  // namespace OHOS