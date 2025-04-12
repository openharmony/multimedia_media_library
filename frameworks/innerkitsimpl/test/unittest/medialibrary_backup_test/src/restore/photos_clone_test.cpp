/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "PhotosCloneTest"

#include "photos_clone_test.h"

#include <string>

#define private public
#include "photos_clone.h"
#undef private

#include "photo_album_dao.h"
#include "backup_const.h"
#include "userfile_manager_types.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media {

void PhotosCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotosCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

// SetUp:Execute before each test case
void PhotosCloneTest::SetUp()
{}

void PhotosCloneTest::TearDown(void)
{}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_1_lPath_Empty_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.sourcePath = "/storage/emulated/0/Pictures/Screenshots/SVID_20240805_113052_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/Pictures/Screenrecords");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_1_lPath_Not_Empty_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/Screenshots";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.sourcePath = "/storage/emulated/0/Pictures/Screenshots/SVID_20240805_113052_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/Pictures/Screenrecords");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_2_lPath_Empty_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/DCIM/Camera");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_3_Hidden_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.hidden = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/DCIM/Camera");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_3_Hidden_LPATH_EMPTY_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.hidden = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/DCIM/Camera");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_3_Hidden_Screenshots_Video_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.hidden = 1;
    fileInfo.sourcePath = "/storage/emulated/0/Pictures/Screenshots/SVID_20240805_113052_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/Pictures/Screenrecords");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_3_TRASHED_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/DCIM/Camera");
}

HWTEST_F(PhotosCloneTest, FindAlbumInfo_Scenario_3_TRASHED_LPATH_EMPTY_Test, TestSize.Level0)
{
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = PhotosClone().FindAlbumInfo(fileInfo);
    EXPECT_EQ(albumRowData.albumId, 0);
    EXPECT_EQ(albumRowData.lPath, "/DCIM/Camera");
}

HWTEST_F(PhotosCloneTest, GetPhotosRowCountInPhotoMap_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotosRowCountInPhotoMap_Test start");
    auto count = PhotosClone().GetPhotosRowCountInPhotoMap();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotosRowCountInPhotoMap_Test end");
}

HWTEST_F(PhotosCloneTest, GetCloudPhotosRowCountInPhotoMap_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetCloudPhotosRowCountInPhotoMap_Test start");
    auto count = PhotosClone().GetCloudPhotosRowCountInPhotoMap();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetCloudPhotosRowCountInPhotoMap_Test end");
}

HWTEST_F(PhotosCloneTest, GetPhotosRowCountNotInPhotoMap_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotosRowCountNotInPhotoMap_Test start");
    auto count = PhotosClone().GetPhotosRowCountNotInPhotoMap();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotosRowCountNotInPhotoMap_Test end");
}

HWTEST_F(PhotosCloneTest, GetCloudPhotosRowCountNotInPhotoMap_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetCloudPhotosRowCountNotInPhotoMap_Test start");
    auto count = PhotosClone().GetCloudPhotosRowCountNotInPhotoMap();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetCloudPhotosRowCountNotInPhotoMap_Test end");
}

HWTEST_F(PhotosCloneTest, FindlPath_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindlPath_Test start");
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    std::string lPath = PhotosClone().FindlPath(fileInfo);
    EXPECT_FALSE(lPath.empty());
    EXPECT_EQ(lPath, "/DCIM/Camera");
    MEDIA_INFO_LOG("FindlPath_Test end");
}

HWTEST_F(PhotosCloneTest, FindAlbumId_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindAlbumId_Test start");
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    auto albumId = PhotosClone().FindAlbumId(fileInfo);
    EXPECT_EQ(albumId, 0);
    MEDIA_INFO_LOG("FindAlbumId_Test end");
}

HWTEST_F(PhotosCloneTest, FindPackageName_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindPackageName_Test start");
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    std::string albumName = PhotosClone().FindPackageName(fileInfo);
    EXPECT_FALSE(albumName.empty());
    EXPECT_EQ(albumName, "Camera");
    MEDIA_INFO_LOG("FindPackageName_Test end");
}

HWTEST_F(PhotosCloneTest, FindBundleName_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindBundleName_Test start");
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/其它";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.sourcePath = "/storage/emulated/0/DCIM/Camera/SVID_20241029_225550_1.mp4";
    std::string bundleName = PhotosClone().FindBundleName(fileInfo);
    EXPECT_TRUE(bundleName.empty());
    MEDIA_INFO_LOG("FindBundleName_Test end");
}

HWTEST_F(PhotosCloneTest, GenerateUuid_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GenerateUuid_Test start");
    std::string uuid = PhotosClone().GenerateUuid();
    EXPECT_FALSE(uuid.empty());
    MEDIA_INFO_LOG("GenerateUuid_Test end");
}

HWTEST_F(PhotosCloneTest, FindSourcePath_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSourcePath_Test start");
    FileInfo fileInfo;
    fileInfo.lPath = "/Pictures/SourceTemp";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.recycledTime = 1;
    fileInfo.displayName = "Sp.jpg";
    std::string sourcePath = PhotosClone().FindSourcePath(fileInfo);
    EXPECT_FALSE(sourcePath.empty());
    EXPECT_EQ(sourcePath, "/storage/emulated/0/Pictures/SourceTemp/Sp.jpg");
    MEDIA_INFO_LOG("FindSourcePath_Test end");
}

HWTEST_F(PhotosCloneTest, GetNoNeedMigrateCount_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetNoNeedMigrateCount_Test start");
    auto count = PhotosClone().GetNoNeedMigrateCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetNoNeedMigrateCount_Test end");
}
}  // namespace OHOS::Media