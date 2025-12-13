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

#include "cloud_media_photos_delete_test.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "media_file_utils.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "media_albums_controller_service.h"
#include "photos_po.h"
#include "create_album_vo.h"
#include "asset_accurate_refresh.h"

#define private public
#define protected public
#include "photos_po_writer.h"
#include "photo_file_operation.h"
#include "cloud_media_photos_service.h"
#include "cloud_media_photos_delete_service.h"
#undef private

using namespace std;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
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

void CloudMediaPhotoDeleteTest::SetUpTestCase()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    bool ret = MediaLibraryUnitTestUtils::CreateTestTables(g_rdbStore, createTableSqlLists);
    ASSERT_TRUE(ret);
}

void CloudMediaPhotoDeleteTest::TearDownTestCase()
{
    system("rm -rf /storage/cloud/files/*");
    bool ret = MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables, true);
    ASSERT_TRUE(ret);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();

    MEDIA_INFO_LOG("CloudMediaPhotoDeleteTest is finish");
}

void CloudMediaPhotoDeleteTest::SetUp()
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

void CloudMediaPhotoDeleteTest::TearDown() {}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoFindAlbumUploadStatus, TestSize.Level1)
{
    MEDIA_INFO_LOG("start CloudMediaPhotoFindAlbumStatus");
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);

    CloudMediaPullDataDto pullData;
    EXPECT_EQ(service->FindAlbumUploadStatus(pullData), false);

    PhotosPo photoPo;
    PhotoAlbumPo albumInfoOp;
    photoPo.hidden = 0;
    pullData.localPhotosPoOp = photoPo;
    EXPECT_EQ(service->FindAlbumUploadStatus(pullData), false);

    albumInfoOp.uploadStatus = 1;
    pullData.albumInfoOp = albumInfoOp;
    EXPECT_EQ(service->FindAlbumUploadStatus(pullData), true);
    MEDIA_INFO_LOG("end CloudMediaPhotoFindAlbumStatus");
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoIsClearCloudInfo, TestSize.Level1)
{
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);

    CloudMediaPullDataDto pullData;
    EXPECT_EQ(service->IsClearCloudInfoOnly(pullData), false);

    PhotosPo photosPo;
    photosPo.hidden = 1;
    pullData.basicIsDelete = true;
    photosPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    pullData.localPhotosPoOp = photosPo;
    EXPECT_EQ(service->IsClearCloudInfoOnly(pullData), true);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoFindPhotoAlbum, TestSize.Level1)
{
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);
    CloudMediaPullDataDto pullData;
    int32_t ret = service->FindPhotoAlbum(pullData);
    EXPECT_EQ(ret, E_ERR);

    PhotosPo photoOp;
    pullData.localPhotosPoOp = photoOp;
    int32_t albumId = CreateAlbum("summer");
    ASSERT_GT(albumId, 0);
    pullData.localOwnerAlbumId = albumId;
    ret = service->FindPhotoAlbum(pullData);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoPullClearCloudInfo, TestSize.Level1)
{
    MEDIA_INFO_LOG("start CloudMediaPhotoPullClearCloudInfo");
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);
    CloudMediaPullDataDto pullData;
    pullData.cloudId = -1;
    std::set<std::string> refreshAlbums;
    std::vector<int32_t> stats = {0, 0, 0, 0, 0};
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service->PullClearCloudInfo(pullData, refreshAlbums, stats, photoRefresh);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(stats[StatsIndex::DELETE_RECORDS_COUNT], 1);

    int32_t albumId = CreateAlbum("winter");
    ASSERT_GT(albumId, 0);
    pullData.cloudId = albumId;
    ret = service->PullClearCloudInfo(pullData, refreshAlbums, stats, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoIsMoveOnlyCloudAssetIntoTrash, TestSize.Level1)
{
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);

    CloudMediaPullDataDto pullData;
    bool ret = service->IsMoveOnlyCloudAssetIntoTrash(pullData);
    EXPECT_EQ(ret, false);

    PhotosPo photoPo;
    photoPo.dateTrashed = 0;
    photoPo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    photoPo.hidden = 1;
    pullData.localPhotosPoOp = photoPo;
    pullData.basicRecycledTime = 1;
    pullData.basicIsDelete = false;

    ret = service->IsMoveOnlyCloudAssetIntoTrash(pullData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoIsMoveOutFromTrash, TestSize.Level1)
{
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);
    CloudMediaPullDataDto pullData;
    bool ret = service->IsMoveOutFromTrash(pullData);
    EXPECT_EQ(ret, false);

    PhotosPo photoPo;
    photoPo.dateTrashed = 1;
    pullData.basicRecycledTime = 0;
    pullData.localPhotosPoOp = photoPo;
    ret = service->IsMoveOutFromTrash(pullData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoCopyAndMoveCloudAssetToTrash, TestSize.Level1)
{
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();
    auto service = make_shared<CloudMediaPhotosDeleteService>();
    ASSERT_NE(service, nullptr);

    CloudMediaPullDataDto pullData;
    int32_t ret = service->CopyAndMoveCloudAssetToTrash(pullData, photoRefresh);
    EXPECT_EQ(ret, E_CLOUDSYNC_INVAL_ARG);

    PhotosPo photoPo;
    pullData.localPhotosPoOp = photoPo;
    ret = service->CopyAndMoveCloudAssetToTrash(pullData, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaCopyThumbnail, TestSize.Level1)
{
    auto photoOperation = make_shared<PhotoFileOperation>();
    ASSERT_NE(photoOperation, nullptr);
    PhotosPo sourcePhotosPo;
    PhotosPo targetPhotosPo;
    int32_t ret = photoOperation->CopyThumbnail(sourcePhotosPo, targetPhotosPo);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);

    sourcePhotosPo.data = "10001";
    sourcePhotosPo.dateTaken = 10001l;
    sourcePhotosPo.fileId = 1;
    targetPhotosPo.fileId = 2;
    targetPhotosPo.data = "10002";
    ret = photoOperation->CopyThumbnail(sourcePhotosPo, targetPhotosPo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotosPoWriterTest, TestSize.Level1)
{
    PhotosPo photosPo;
    auto writer = make_shared<PhotosPoWriter>(photosPo);
    ASSERT_NE(writer, nullptr);
    std::variant<int32_t, int64_t, double, std::string> valueInt = 12;
    std::variant<int32_t, int64_t, double, std::string> valueLong = 12LL;
    std::variant<int32_t, int64_t, double, std::string> valueDouble = 12.0;
    std::variant<int32_t, int64_t, double, std::string> valueStr = "test";

    for (const auto &handler : writer->HANDLERS) {
        writer->SetMemberVariable(handler.first, valueInt);
        writer->SetMemberVariable(handler.first, valueLong);
        writer->SetMemberVariable(handler.first, valueDouble);
        writer->SetMemberVariable(handler.first, valueStr);
    }
    EXPECT_EQ(writer->SetMemberVariable("invalidKey", valueStr), E_ERR);
    writer->SetMemberVariable(PhotoColumn::MEDIA_FILE_PATH, valueStr);
    EXPECT_EQ(writer->photosPo_.data, "test");
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotosPoTest, TestSize.Level1)
{
    PhotosPo photoPo;
    string result = photoPo.ToString();
    std::regex pattern("\\{.*?\\}");
    EXPECT_EQ(std::regex_search(result, pattern), true);
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMediaPhotoServicesHandleRecordTest, TestSize.Level1)
{
    MEDIA_INFO_LOG("start CloudMediaPhotoServicesHandleRecordTest");
    CloudMediaPhotosService services;
    std::vector<int32_t> stats = {0, 0, 0, 0, 0};
    std::vector<PhotosDto> newData;
    std::vector<std::string> cloudIds;
    std::vector<PhotosDto> fdirtyData;
    std::vector<std::string> failedRecords;
    std::map<std::string, CloudMediaPullDataDto> cloudIdRelativeMap;
    int32_t ret = services.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);
    EXPECT_EQ(ret, E_OK);

    cloudIds.emplace_back("001");
    CloudMediaPullDataDto dataDto;
    dataDto.basicIsDelete = false;
    cloudIdRelativeMap["001"] = dataDto;
    services.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);
    EXPECT_EQ(stats[0], 1);

    cloudIds.emplace_back("002");
    CloudMediaPullDataDto dataDto1;
    dataDto1.localPath = "/test";
    dataDto1.basicIsDelete = true;
    cloudIdRelativeMap["002"] = dataDto1;
    services.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);
    EXPECT_EQ(stats[4], 1);
    MEDIA_INFO_LOG("end CloudMediaPhotoServicesHandleRecordTest");
}

HWTEST_F(CloudMediaPhotoDeleteTest, CloudMedia_PhotosPo_BuildFileUri_Test, TestSize.Level1)
{
    PhotosPo photoPo;
    photoPo.data = "/storage/cloud/files/Photo/8/IMG_1761641838_408.jpg";
    photoPo.displayName = "IMG_20250912_225900.jpg";
    photoPo.fileId = 409;
    std::string fileUri = photoPo.BuildFileUri();
    // file://media/Photo/${file_id}/${data_prefix}/%{display_name}
    const std::string expectFileUri = "file://media/Photo/409/IMG_1761641838_408/IMG_20250912_225900.jpg";
    EXPECT_EQ(fileUri, expectFileUri);
}
}
