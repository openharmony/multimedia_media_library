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

#define private public
#include "database_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_log.h"
#include "photos_clone.h"
#include "userfile_manager_types.h"
#undef private

using namespace testing::ext;

namespace OHOS::Media {
const int32_t TEST_FILE_ID = 1;
const int32_t TEST_ALBUM_ID = 10;
const int64_t TEST_FILE_SIZE = 1024;
const std::string TEST_ALBUM_NAME = "Camera";
const std::string TEST_ALBUM_LPATH = "/DCIM/Camera";
const std::string TEST_DATA = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string TEST_DISPLAY_NAME = "test.jpg";
const std::string TEST_CLOUD_ID = "cloudid";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void PhotosCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
}

void PhotosCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    PhotosCloneTestUtils::ClearAllData();
}

// SetUp:Execute before each test case
void PhotosCloneTest::SetUp()
{
    PhotosCloneTestUtils::ClearAllData();
}

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

HWTEST_F(PhotosCloneTest, FindDuplicateBurstKey_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_Test start");
    std::vector<PhotosDao::PhotosRowData> duplicateBurstKeyList = PhotosClone().FindDuplicateBurstKey();
    uint64_t number = static_cast<uint64_t>(duplicateBurstKeyList.size());
    EXPECT_EQ(number, 0);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_Test end");
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

HWTEST_F(PhotosCloneTest, FindSameFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSameFile_Test_001 start");
    PhotosClone photosClone;
    photosClone.OnStart(g_rdbStore->GetRaw(), nullptr);

    FileInfo fileInfo;
    PhotosDao::PhotosRowData rowData = photosClone.FindSameFile(fileInfo);
    EXPECT_EQ(rowData.IsValid(), false); // no data in target db
    MEDIA_INFO_LOG("FindSameFile_Test_001 end");
}

HWTEST_F(PhotosCloneTest, FindSameFile_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSameFile_Test_002 start");
    PhotosCloneTestUtils::InsertAlbum();
    PhotosCloneTestUtils::InsertPhoto();
    PhotosClone photosClone;
    photosClone.OnStart(g_rdbStore->GetRaw(), nullptr);

    FileInfo fileInfo;
    fileInfo.fileSize = TEST_FILE_SIZE;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = TEST_DISPLAY_NAME;
    fileInfo.lPath = TEST_ALBUM_LPATH;

    PhotosDao::PhotosRowData rowData = photosClone.FindSameFile(fileInfo);
    EXPECT_EQ(rowData.IsValid(), true); // source: without cloud_id - dst: without cloud_id
    MEDIA_INFO_LOG("FindSameFile_Test_002 end");
}

HWTEST_F(PhotosCloneTest, FindSameFile_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSameFile_Test_003 start");
    PhotosCloneTestUtils::InsertAlbum();
    PhotosCloneTestUtils::InsertPhoto(TEST_CLOUD_ID);
    PhotosClone photosClone;
    photosClone.OnStart(g_rdbStore->GetRaw(), nullptr);

    FileInfo fileInfo;
    fileInfo.fileSize = TEST_FILE_SIZE;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = TEST_DISPLAY_NAME;
    fileInfo.uniqueId = TEST_CLOUD_ID;

    PhotosDao::PhotosRowData rowData = photosClone.FindSameFile(fileInfo);
    EXPECT_EQ(rowData.IsValid(), true); // source: with cloud_id - dst: with cloud_id
    MEDIA_INFO_LOG("FindSameFile_Test_003 end");
}

HWTEST_F(PhotosCloneTest, FindSameFile_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSameFile_Test_004 start");
    PhotosCloneTestUtils::InsertAlbum();
    PhotosCloneTestUtils::InsertPhoto();
    PhotosClone photosClone;
    photosClone.OnStart(g_rdbStore->GetRaw(), nullptr);

    FileInfo fileInfo;
    fileInfo.fileSize = TEST_FILE_SIZE;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = TEST_DISPLAY_NAME;
    fileInfo.uniqueId = TEST_CLOUD_ID;
    fileInfo.lPath = TEST_ALBUM_LPATH;

    PhotosDao::PhotosRowData rowData = photosClone.FindSameFile(fileInfo);
    EXPECT_EQ(rowData.IsValid(), true); // source: with cloud_id - dst: without cloud_id
    MEDIA_INFO_LOG("FindSameFile_Test_004 end");
}

HWTEST_F(PhotosCloneTest, FindSameFile_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSameFile_Test_005 start");
    PhotosCloneTestUtils::InsertAlbum();
    PhotosCloneTestUtils::InsertPhoto();
    PhotosClone photosClone;
    photosClone.OnStart(g_rdbStore->GetRaw(), nullptr);

    FileInfo fileInfo;
    fileInfo.fileSize = TEST_FILE_SIZE;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = TEST_DISPLAY_NAME;
    fileInfo.uniqueId = TEST_CLOUD_ID;

    PhotosDao::PhotosRowData rowData = photosClone.FindSameFile(fileInfo);
    EXPECT_EQ(rowData.IsValid(), false); // source: with cloud_id, no lpath - dst: not found
    MEDIA_INFO_LOG("FindSameFile_Test_005 end");
}

void PhotosCloneTestUtils::ClearAllData()
{
    ClearPhotosData();
    ClearPhotoAlbumData();
}

void PhotosCloneTestUtils::ClearPhotosData()
{
    const std::string CLEAR_PHOTOS_SQL = "DELETE FROM Photos";
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), CLEAR_PHOTOS_SQL);
}

void PhotosCloneTestUtils::ClearPhotoAlbumData()
{
    const std::string CLEAR_PHOTO_ALBUM_SQL = "DELETE FROM PhotoAlbum WHERE album_type <> ?";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { static_cast<int32_t>(PhotoAlbumType::SYSTEM) };
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), CLEAR_PHOTO_ALBUM_SQL, BIND_ARGS);
}

void PhotosCloneTestUtils::InsertPhoto(const std::string &cloudId)
{
    const std::string INSERT_SQL = "INSERT INTO Photos (file_id, data, size, display_name, owner_album_id, cloud_id) "
        " VALUES (?, ?, ?, ?, ?, ?)";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { TEST_FILE_ID, TEST_DATA, TEST_FILE_SIZE, TEST_DISPLAY_NAME,
        TEST_ALBUM_ID, cloudId };
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), INSERT_SQL, BIND_ARGS);
}

void PhotosCloneTestUtils::InsertAlbum()
{
    const std::string INSERT_SQL = "INSERT INTO PhotoAlbum (album_id, album_name, lpath, album_type, album_subtype) "
        " VALUES (?, ?, ?, ?, ?)";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { TEST_ALBUM_ID, TEST_ALBUM_NAME, TEST_ALBUM_LPATH,
        static_cast<int32_t>(PhotoAlbumType::SOURCE), static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC) };
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), INSERT_SQL, BIND_ARGS);
}
}  // namespace OHOS::Media