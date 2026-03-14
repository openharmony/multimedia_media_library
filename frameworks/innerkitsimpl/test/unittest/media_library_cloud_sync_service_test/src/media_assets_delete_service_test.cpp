/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaCloudSync"

#include "media_assets_delete_service_test.h"

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

#include "media_albums_controller_service.h"
#include "create_album_vo.h"

#define private public
#define protected public
#include "media_assets_delete_service.h"
#undef private

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::Common;
namespace OHOS::Media::CloudSync {

static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static std::vector<std::string> createTableSqlLists = {
    PhotoAlbumColumns::CREATE_TABLE,
    // add more phots ,audios if necessary
};

static std::vector<std::string> testTables = {
    PhotoAlbumColumns::TABLE,
};

static int32_t CreateAlbum(const std::string &albumName)
{
    CreateAlbumReqBody reqBody;
    reqBody.albumName = albumName;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->CreatePhotoAlbum(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    return respVo.GetErrCode();
}

void CloudMediaAssetsDeleteTest::SetUpTestCase()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    bool ret = MediaLibraryUnitTestUtils::CreateTestTables(g_rdbStore, createTableSqlLists);
    ASSERT_TRUE(ret);
}

void CloudMediaAssetsDeleteTest::TearDownTestCase()
{
    system("rm -rf /storage/cloud/files/*");
    // drop table
    bool ret = MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables, true);
    ASSERT_TRUE(ret);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    MEDIA_INFO_LOG("CloudMediaPhotoDeleteTest is finish");
}

void CloudMediaAssetsDeleteTest::SetUp()
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

void CloudMediaAssetsDeleteTest::TearDown() {}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("start CloudMediaAssetsDeleteLocalAssets_Test");
    std::vector<std::string> fileIds;
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteLocalAssets(fileIds);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
    int32_t albumId = CreateAlbum("summer");
    ASSERT_GT(albumId, 0);

    int32_t albumId1 = CreateAlbum("winter");
    ASSERT_GT(albumId1, 0);
    MEDIA_INFO_LOG("end CloudMediaAssetsDeleteLocalAssets_Test");
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_002, TestSize.Level1)
{
    // 用例说明：测试 DeleteLocalAssets 方法，文件ID列表为空场景
    std::vector<std::string> file;
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteLocalAssets(fileIds);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_003, TestSize.Level1)
{
    // 用例说明：测试 DeleteLocalAssets 方法，查询资产失败场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteLocalAssets(fileIds);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_004, TestSize.Level1)
{
    // 用例说明：测试 DeleteLocalAssets 方法，全云端资源场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteLocalAssets(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_005, TestSize.Level1)
{
    // 用例说明：测试 DeleteCloudAssets 方法，文件ID列表为空场景
    std::vector<std::string> fileIds;
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteCloudAssets(fileIds);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_006, TestSize.Level1)
{
    // 用例说明：测试 DeleteCloudAssets 方法，查询资产失败场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteCloudAssets(fileIds);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssets_Test_007, TestSize.Level1)
{
    // 用例说明：测试 DeleteCloudAssets 方法，全本地资源场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    int32_t ret = service->DeleteCloudAssets(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssetSingle_Test_001, TestSize.Level1)
{
    // 用例说明：测试 DeleteLocalAssetSingle 方法，非 LOCAL_AND_CLOUD 位置场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<in32_t>(PhotoPositionType::LOCAL);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteLocalAssetSingle(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssetSingle_Test_002, TestSize.Level1)
{
    // 用例说明：测试 DeleteLocalAssetSingle 方法，LOCAL_AND_CLOUD 位置场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteLocalAssetSingle(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssetSingle_Test_003, TestSize.Level1)
{
    // 用例说明：测试 DeleteCloudAssetSingle 方法，非 LOCAL_AND_CLOUD 位置场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteCloudAssetSingle(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsDeleteLocalAssetSingle_Test_004, TestSize.Level1)
{
    // 用例说明：测试 DeleteCloudAssetSingle 方法，LOCAL_AND_CLOUD 位置场景
    std::vector<std::string> fileIds = {"1"};
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteCloudAssetSingle(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsEraseCloudInfo_Test, TestSize.Level1)
{
    // 用例说明：测试 EraseCloudInfo 方法，擦除云端信息
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudVersion = "v1";

    int32_t ret = service->EraseCloudInfo(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.cloudId.has_value());
    EXPECT_EQ(photoInfo.dirty.value_or(-1), static_cast<int32_t>(DirtyType::TYPE_NEW));
    EXPECT_EQ(photoInfo.position.value_or(-1), static_cast<int32_t>(PhotoPositionType::LOCAL));
    EXPECT_FALSE(photoInfo.cloudVersion.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetFileId_Test, TestSize.Level1)
{
    // 用例说明：测试 ResetFileId 方法，重置文件ID
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;

    int32_t ret = service->ResetFileId(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.fileId.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetVirtualPath_Test, TestSize.Level1)
{
    // 用例说明：测试 ResetVirtualPath 方法，重置虚拟路径
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.virtualPath = "/test/path";

    int32_t ret = service->ResetVirtualPath(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.virtualPath.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsSetDateTrashed_Test, TestSize.Level1)
{
    // 用例说明：测试 SetDateTrashed 方法，设置删除时间
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    int64_t dateTrashed = 1234567890;

    int32_t ret = service->SetDateTrashed(photoInfo, dateTrashed);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfo.dateTrashed.value_or(-1), dateTrashed);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsSetPosition_Test, TestSize.Level1)
{
    // 用例说明：测试 SetPosition 方法，设置位置类型
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    int32_t position = static_cast<int32_t>(PhotoPositionType::CLOUD);

    int32_t ret = service->SetPosition(photoInfo, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfo.position.value_or(-1), position);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsSetFilePath_Test, TestSize.Level1)
{
    // 用例说明：测试 SetFilePath 方法，设置文件路径
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    std::string filePath = "/test/path/file.jpg";

    int32_t ret = service->SetFilePath(photoInfo, filePath);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfo.data.value_or(""), filePath);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsSetFileId_Test, TestSize.Level1)
{
    // 用例说明：测试 SetFileId 方法，设置文件ID
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    int32_t fileId = 456;

    int32_t ret = service->SetFileId(photoInfo, fileId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfo.fileId.value_or(-1), fileId);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsClearCloudInfo_Test, TestSize.Level1)
{
    // 用例说明：测试 ClearCloudInfo 方法，清除云端信息
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudVersion = "v1";

    int32_t ret = service->ClearCloudInfo(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.cloudId.has_value());
    EXPECT_EQ(photoInfo.dirty.value_or(-1), static_cast<int32_t>(DirtyType::TYPE_NEW));
    EXPECT_EQ(photoInfo.position.value_or(-1), static_cast<int32_t>(PhotoPositionType::LOCAL));
    EXPECT_FALSE(photoInfo.cloudVersion.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetNullableFields_Test_001, TestSize.Level1)
{
    // 用例说明：测试 ResetNullableFields 方法，burstKey 为空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.burstKey = "";

    int32_t ret = service->ResetNullableFields(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.burstKey.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetNullableFields_Test_002, TestSize.Level1)
{
    // 用例说明：测试 ResetNullableFields 方法，originalAssetCloudId 为空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.originalAssetCloudId = "";

    int32_t ret = service->ResetNullableFields(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.originalAssetCloudId.has_value());
    MEDIA_INFO_LOG("end Cloud)MediaAssetsResetNullableFields_OriginalAssetCloudIdEmpty_Test");
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetNullableFields_Test_003, TestSize.Level1)
{
    // 用例说明：测试 ResetNullableFields 方法，relativePath 为空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.relativePath = "";

    int32_t ret = service->ResetNullableFields(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.relativePath.has_value());
}

HWTEST_F
(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetNullableFields_Test_004, TestSize.Level1)
{
    // 用例说明：测试 ResetNullableFields 方法，latitude 和 longitude 为零场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.latitude = 0.0;
    photoInfo.longitude = 0.0;

    int32_t ret = service->ResetNullableFields(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.latitude.has_value());
    EXPECT_FALSE(photoInfo.longitude.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetNullableFields_Test_005, TestSize.Level1)
{
    // 用例说明：测试 ResetNullableFields 方法，userComment 为空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.userComment = "";

    int32_t ret = service->ResetNullableFields(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.userComment.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetFileSourceType_Test, asTestSize.Level1)
{
    // 用例说明：测试 ResetFileSourceType 方法，重置文件源类型
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileSourceType = static_cast<int32_t>(FileSourceType::CLOUD);

    int32_t ret = service->ResetFileSourceType(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfo.fileSourceType.value_or(-1), static_cast<int32_t>(FileSourceType::MEDIA));
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsResetSouthDeviceType_Test, TestSize.Level1)
{
    // 用例例说明：测试 ResetSouthDeviceType 方法，重置南向设备类型
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.southDeviceType = static_cast<int32_t>(SouthDeviceType::SOUTH_DEVICE_HUAWEI);

    int32_t ret = service->ResetSouthDeviceType(photoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(photoInfo.southDeviceType.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsSetMdirty_Test, TestSize.Level1)
{
    // 用例说明：测试 SetMdirty 方法，设置 Mdirty 标志
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);

    int32_t ret = service->SetMdirty(photoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsStoreThumbnailAndEditSize_Test_001, TestSize.Level1)
{
    // 用例说明：测试 StoreThumbnailAndEditSize 方法，有效参数场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "/test/path/file.jpg";

    std::optional<PhotosPo> targetPhotoInfoOp;
    targetPhotoInfoOp = photoInfo;

    int32_t ret = service->StoreThumbnailAndariEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsStoreThumbnailAndEditSize_Test_002, TestSize.Level1)
{
    // 用例说明：测试 StoreThumbnailAndEditSize 方法，无目标场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "/test/path/file.jpg";

    std::optional<PhotosPo> targetPhotoInfoOp;

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsStoreThumbnailAndEditSize_Test_003, TestSize.Level1)
{
    // 用例说明：测试 StoreThumbnailAndEditSize 方法，无效参数场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 0;
    photoInfo.data = "";

    std::optional<PhotosPo> targetPhotoInfoOp;
    targetPhotoInfoOp = {fileId: 456, data: "/test/path/file.jpg"};

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_INVALID_VALUES);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCopyAndMoveLocalAssetToTrash_Test_001, TestSize.Level1)
{
    // 用例说明：测试 CopyAndMoveLocalAssetToTrash 方法，非 LOCAL_AND_CLOUD 位置场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->CopyAndMoveLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCopyAndMoveLocalAssetToTrash_Test_002, TestSize.Level1)
{
    // 用例说明：测试 CopyAndMoveLocalAssetToTrash 方法，Fdirty 场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->CopyAndMoveLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCopyAndMoveLocalAssetToTrash_Test_003, TestSize.Level1)
{
    // 用例说明：测试 CopyAndMoveLocalAssetToTrash 方法，非 LOCAL_AND_CLOUD 位置场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->CopyAndMoveLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCopyAndMoveLocalAssetToTrash_Test_004, TestSize.Level1)
{
    // 用例说明：测试 CopyAndMoveLocalAssetToTrash 方法，Fdirty 场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->CopyAndMoveLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsBuildTargetFilePath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 BuildTargetFilePath 方法，storagePath 非空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.storagePath = "/storage/cloud/100/files/.lake";
    std::string targetPath;

    int32_t ret = service->BuildTargetFilePath(photoInfo, targetPath);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetPath.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsBuildTargetFilePath_Test_002, TestSize.Level1)
{
    //用例说明：测试方法，storagePath 为空场景
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.storagePath = "";
    std::string targetPath;

    int32_t ret = service->BuildTargetFilePath(photoInfo, targetPath);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetPath.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsStoreThumbnailAndEditSize_Valid_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "/test/path/file.jpg";

    std::optional<PhotosPo> targetPhotoInfoOp;
    targetPhotoInfoOp = photoInfo;

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsStoreThumbnailAndEditSize_NoTarget_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.data = "/test/path/file.jpg";

    std::optional<PhotosPo> targetPhotoInfoOp;

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsStoreThumbnailAndEditSize_Invalid_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 0;
    photoInfo.data = "";

    std::optional<PhotosPo> targetPhotoInfoOp;
    targetPhotoInfoOp = {fileId: 456, data: "/test/path/file.jpg"};

    int32_t ret = service->StoreThumbnailAndEditSize(photoInfo, targetPhotoInfoOp);
    EXPECT_EQ(ret, E_INVALID_VALUES);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsCopyAndMoveLocalAssetToTrash_Fdirty_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->CopyAndMoveLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest, CloudMediaAssetsBuildTargetFilePath_NoStoragePath_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.storagePath = "";
    std::string targetPath;

    int32_t ret = service->BuildTargetFilePath(photoInfo, targetPath);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetPath.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBatchCopyAndMoveLocalAssetToTrash_Fdirty_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    std::vector<PhotosPo> photosList;
    PhotosPo photoInfo;
    photoInfo.burstCoverLevel = 1;
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_FDIRTY);
    photosList.push_back(photoInfo);

    std::vector<std::string> targetFileIds;

    int32_t ret = service->BatchCopyAndMoveLocalAssetToTrash(photosList, targetFileIds);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetFileIds.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBatchCopyAndMoveLocalAssetToTrash_NotLocal_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    std::vector<PhotosPo> photosList;
    PhotosPo photoInfo;
    photoInfo.burstCoverLevel = 1;
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosList.push_back(photoInfo);

    std::vector<std::string> targetFileIds;

    int32_t ret = service->BatchCopyAndMoveLocalAssetToTrash(photosList, targetFileIds);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetFileIds.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBatchCopyAndMoveCloudAssetToTrash_BurstCoverLevelNot1_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    std::vector<PhotosPo> photosList;
    PhotosPo photoInfo;
    photoInfo.burstCoverLevel = 2;
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photosList.push_back(photoInfo);

    std::vector<std::string> targetFileIds;

    int32_t ret = service->BatchCopyAndMoveCloudAssetToTrash(photosList, targetFileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBatchCopyAndMoveCloudAssetToTrash_Fdirty_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    std::vector<PhotosPo> photosList;
    PhotosPo photoInfo;
    photoInfo.burstCoverLevel = 1;
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_FDIRTY);
    photosList.push_back(photoInfo);

    std::vector<std::string> targetFileIds;

    int32_t ret = service->BatchCopyAndMoveCloudAssetToTrash(photosList, targetFileIds);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetFileIds.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBatchCopyAndMoveCloudAssetToTrash_NotCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    std::vector<PhotosPo> photosList;
    PhotosPo photoInfo;
    photoInfo.burstCoverLevel = 1;
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_NEW);
    photosList.push_back(photoInfo);

    std::vector<std::string> targetFileIds;

    int32_t ret = service->BatchCopyAndMoveCloudAssetToTrash(photosList, targetFileIds);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(targetFileIds.empty());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsDeleteLocalBurstAssets_NotBurst_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dateTrashed = 0;
    photoInfo.burstKey = "";
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";

    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteLocalBurstAssets(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_INVALID_MODE);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsDeleteLocalBurstAssets_CoverNotLocalAndCloud_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dateTrashed = 0;
    photoInfo.burstKey = "test_burst_key";
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.burstCoverLevel = static_cast<int32_t>(BurstCoverLevelType::COVER);

    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteLocalBurstAssets(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsDeleteCloudBurstAssets_NotBurst_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dateTrashed = 0;
    photoInfo.burstKey = "";
    photoInfo.fileId = 123;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";

    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->DeleteCloudBurstAssets(photoInfo, targetPhotoInfoOp, photoRefresh);
    EXPECT_EQ(ret, E_INVALID_MODE);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCheckAndFindBurstAssets_DateTrashed_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dateTrashed = 1234567890;
    photoInfo.burstKey = "test_burst_key";
    photoInfo.fileId = 123;

    std::optional<PhotosPo> coverAssetOp;
    std::vector<PhotosPo> burstAssets;

    int32_t ret = service->CheckAndFindBurstAssets(photoInfo, coverAssetOp, burstAssets);
    EXPECT_EQ(ret, E_INVALID_MODE);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCheckAndFindBurstAssets_EmptyBurstKey_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.dateTrashed = 0;
    photoInfo.burstKey = "";
    photoInfo.fileId = 123;

    std::optional<PhotosPo> coverAssetOp;
    std::vector<PhotosPo> burstAssets;

    int32_t ret = service->CheckAndFindBurstAssets(photoInfo, coverAssetOp, burstAssets);
    EXPECT_EQ(ret, E_INVALID_MODE);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsCreateCloudTrashedPhotosPo_CloudPullData_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>(true);
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = 0;
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoInfo.cloudId = "test_cloud_id";
    photoInfo.dirty = static_cast<int32_t>(DirtyType::TYPE_MDIRTY);

    PhotosPo targetPhotoInfo;

    int32_t ret = service->CreateCloudTrashedPhotosPo(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(targetPhotoInfo.dateTrashed.has_value());
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBuildMediaFilePath_EmptyDisplayName_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.displayName = "";
    photoInfo.mediaType = 0;
    std::string targetPath;

    int32_t ret = service->BuildMediaFilePath(photoInfo, targetPath);
    EXPECT_EQ(ret, E_FILE_NAME_INVALID);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsBuildLakeFilePath_EmptyDisplayName_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.displayName = "";
    photoInfo.mediaType = 0;
    std::string targetPath;

    int32_t ret = service->BuildLakeFilePath(photoInfo, targetPath);
    EXPECT_EQ(ret, E_FILE_NAME_INVALID);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsMoveOrGenerateLocalThumbnail_CopySuccess_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo photoInfo;
    photoInfo.fileId = 123;
    photoInfo.displayName = "test.jpg";

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.fileId = 456;
    targetPhotoInfo.displayName = "target.jpg";
    targetPhotoInfo.dateTaken = 1234567890;
    targetPhotoInfo.dateModified = 1234567890;

    int32_t ret = service->MoveOrGenerateLocalThumbnail(photoInfo, targetPhotoInfo);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaAssetsDeleteTest,
    CloudMediaAssetsGenerateThumbnail_NoFileId_Test, TestSize.Level1)
{
    auto service = make_shared<MediaAssetsDeleteService>();
    ASSERT_NE(service, nullptr);

    PhotosPo targetPhotosPo;
    targetPhotosPo.fileId.reset();
    targetPhotosPo.displayName = "test.jpg";
    targetPhotosPo.data = "/test/path/file.jpg";

    int32_t ret = service->GenerateThumbnail(targetPhotosPo);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}
}