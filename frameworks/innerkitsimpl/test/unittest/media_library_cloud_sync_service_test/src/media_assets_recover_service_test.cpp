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

#define MLOG_TAG "MediaAssetsRecoverServiceTest"

#include "media_assets_recover_service_test.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "media_file_utils.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "cloud_media_define.h"
#include "photos_po.h"
#include "media_assets_recover_service.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::Common;
namespace OHOS::Media {

static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static std::vector<std::string> createTableSqlLists = {
    PhotoAlbumColumns::CREATE_TABLE,
};

static std::vector<std::string> testTables = {
    PhotoAlbumColumns::TABLE,
};

void MediaAssetsRecoverServiceTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    bool ret = MediaLibraryUnitTestUtils::CreateTestTables(g_rdbStore, createTableSqlLists);
    ASSERT_TRUE(ret);
}

void MediaAssetsRecoverServiceTest::TearDownTestCase(void)
{
    system("rm -rf /storage/cloud/files/*");
    bool ret = MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables, true);
    ASSERT_TRUE(ret);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    MEDIA_INFO_LOG("MediaAssetsRecoverServiceTest is finish");
}

void MediaAssetsRecoverServiceTest::SetUp(void)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    system("rm -rf /storage/cloud/files/.cache");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    bool ret = MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables);
    ASSERT_TRUE(ret);
}

void MediaAssetsRecoverServiceTest::TearDown(void) {}

HWTEST_F(MediaAssetsRecoverServiceTest, MediaAssetsRecoverService_RecoverPackageName_Empty_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.packageName = "";
    PhotosPo targetPhotoInfo;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->RecoverPackageName(sourcePhotoInfo, targetPhotoInfo, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest, MediaAssetsRecoverService_RecoverPackageName_TargetEmpty_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.packageName = "test_package";
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.packageName = "";
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->RecoverPackageName(sourcePhotoInfo, targetPhotoInfo, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest, MediaAssetsRecoverService_MergeAssetFile_SourceCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);

    int32_t ret = service->MergeAssetFile(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_MergeAssetFile_SourceLocalAndCloud_TargetLocalAndCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);

    int32_t ret = service->MergeAssetFile(photoInfo, targetPhotoInfo);
    EXPECT_NE(ret, E_FAIL);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_MergeAssetFileFromMediaToLake_SourceCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);

    int32_t ret = service->MergeAssetFileFromMediaToLake(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_MergeAssetFileFromMediaToLake_TargetCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);

    int32_t ret = service->MergeAssetFileFromMediaToLake(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_MoveAssetFileFromMediaToLake_NotLakeFile_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    PhotosPo targetPhotoInfo;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    targetPhotoInfo.storagePath = "";

    int32_t ret = service->MoveAssetFileFromMediaToLake(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_StoreThumbnailAndEditSize_Valid_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "/storage/cloud/100/files/Photo/test.jpg";

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_StoreThumbnailAndEditSize_InvalidFileId_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 0;
    photoInfo.data = "/storage/cloud/100/files/Photo/test.jpg";

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_StoreThumbnailAndEditSize_InvalidData_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "";

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_StoreThumbnailAndEditSize_BothInvalid_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 0;
    photoInfo.data = "";

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsRecoverServiceTest,
    MediaAssetsRecoverService_RecoverPhotoAsset_Valid_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsRecoverService>();
    ASSERT_NE(service, nullptr);

    std::string fileUri = "datashare:///media/Photo/123/IMG_1748424853_004/IMG_20250528_171337.jpg";

    int32_t ret = service->RecoverPhotoAsset(fileUri);
    EXPECT_EQ(ret, E_OK);
}
} // namespace OHOS::Media
