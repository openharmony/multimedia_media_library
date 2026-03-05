/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under Apache License, Version 2.0 (the "License");
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

#define MLOG_TAG "MediaAssetsServiceTest"

#include "media_assets_service_test.h"

#include <string>
#include <vector>
#include <chrono>
#include <thread>

#define private public
#define protected public
#include "datashare_result_set.h"
#include "media_assets_controller_service.h"
#include "media_assets_service.h"
#include "rdb_utils.h"
#undef private
#undef protected

#include "create_asset_vo.h"
#include "submit_cache_vo.h"
#include "asset_change_create_asset_vo.h"
#include "add_image_vo.h"
#include "save_camera_photo_vo.h"
#include "set_location_dto.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "media_column.h"
#include "photo_column.h"
#include "media_file_utils.h"
#include "multistages_capture_manager.h"
#include "multistages_video_capture_manager.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRats;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;
static constexpr int32_t TEST_FILE_ID = 1001;
static constexpr int32_t TEST_ALBUM_ID = 2001;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void MediaAssetsServiceTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaAssetsServiceTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoAlbumColumns::TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void MediaAssetsServiceTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoAlbumColumns::TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void MediaAssetsServiceTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void MediaAssetsServiceTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static int32_t InsertAssetIntoPhotosTable(int32_t fileId, const std::string &filePath, int32_t mediaType = 0)
{
    const std::string sqlInsertPhoto = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
        MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
        MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
        PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ", " +
        PhotoColumn::PHOTO_LATITUDE + ", " + PhotoColumn::PHOTO_LONGITUDE + ", " +
        PhotoColumn::PHOTO_IS_TEMP + ", " + PhotoColumn::PHOTO_DIRTY + ") VALUES (" +
        "'" + filePath + "', 1024, 'test_title', 'test.jpg', " + to_string(mediaType) + ", " +
        "'com.example.test', 'com.example.test', 1000000, 1000000, 1000000, 0, 1, 0, 0, 0, 0, 0.0, 0, 0";
    return g_rdbStore->ExecuteSql(sqlInsertPhoto);
}

static int32_t InsertAlbumIntoTable(int32_t albumId, const std::string &albumName)
{
    int64_t now = MediaFileUtils::UTCTimeMilliSeconds();
    const std::string sqlInsertAlbum = "INSERT INTO " + PhotoAlbumColumns::TABLE + "(" +
        PhotoAlbumColumns::ALBUM_NAME + ", " + PhotoAlbumColumns::ALBUM_TYPE + ", " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + ", " + PhotoAlbumColumns::ALBUM_DATE_MODIFIED + ", " +
        PhotoAlbumColumns::ALBUM_DATE_ADDED + ", " + PhotoAlbumColumns::ALBUM_LPATH + ", " +
        PhotoAlbumColumns::CONTAINS_HIDDEN + ", " + PhotoAlbumColumns::ALBUM_IS_LOCAL + ", " +
        PhotoAlbumColumns::ALBUM_PRIORITY + ") VALUES (" +
        "'" + albumName + "', 1, 0, " + to_string(now) + ", " + to_string(now) + ", " +
        "'/Pictures/" + albumName + "', 0, 1, 1";
    return g_rdbStore->ExecuteSql(sqlInsertAlbum);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_TrashPhotos_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::vector<std::string> uris = {"datashare:///media/Photo/" + std::to_string(fileId)};
    int32_t ret = instance.TrashPhotos(uris);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_TrashPhotos_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::vector<std::string> uris = {"datashare:///media/Photo/" + std::to_string(fileId)};
    int32_t ret = instance.TrashPhotos(uris);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {MediaColumn::MEDIA_DATE_TRASHED};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int64_t dateTrashed = 0;
    resultSet->GetLong(0, dateTrashed);
    EXPECT_GT(dateTrashed, 0);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_TrashPhotos_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<std::string> uris;
    int32_t ret = instance.TrashPhotos(uris);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_TrashPhotos_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> uris = {
        "datashare:///media/Photo/" + std::to_string(fileId1),
        "datashare:///media/Photo/" + std::to_string(fileId2)
    };
    int32_t ret = instance.TrashPhotos(uris);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_UpdateExistedTasksTitle_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t ret = instance.UpdateExistedTasksTitle(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_UpdateExistedTasksTitle_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    int32_t ret = instance.UpdateExistedTasksTitle(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_UpdateExistedTasksTitle_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t ret = instance.UpdateExistedTasksTitle(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_UpdateExistedTasksTitle_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = -1;
    int32_t ret = instance.UpdateExistedTasksTitle(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_UpdateExistedTasksTitle_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateTitle = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        MediaColumn::MEDIA_TITLE + " = 'updated_title' WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateTitle);

    int32_t ret = instance.UpdateExistedTasksTitle(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSubmitCache_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    SubmitCacheDto dto;
    dto.isWriteGpsAdvanced = false;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 0);

    int32_t ret = instance.AssetChangeSubmitCache(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
    EXPECT_FALSE(dto.outUri.empty());
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSubmitCache_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    SubmitCacheDto dto;
    dto.isWriteGpsAdvanced = true;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 0);
    dto.values.PutDouble(PhotoColumn::PHOTO_LATITUDE, 39.9);
    dto.values.PutDouble(PhotoColumn::PHOTO_LONGITUDE, 116.4);

    int32_t ret = instance.AssetChangeSubmitCache(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSubmitCache_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    SubmitCacheDto dto;
    dto.isWriteGpsAdvanced = false;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 1);

    int32_t ret = instance.AssetChangeSubmitCache(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSubmitCache_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    SubmitCacheDto dto;
    dto.isWriteGpsAdvanced = false;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 0);

    int32_t ret = instance.AssetChangeSubmitCache(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeCreateAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AssetChangeCreateAssetDto dto;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 0);

    int32_t ret = instance.AssetChangeCreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
    EXPECT_FALSE(dto.outUri.empty());
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeCreateAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AssetChangeCreateAssetDto dto;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 1);

    int32_t ret = instance.AssetChangeCreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeCreateAsset_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AssetChangeCreateAssetDto dto;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/media/local/files/Pictures/test.jpg");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 2);

    int32_t ret = instance.AssetChangeCreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeCreateAsset_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AssetChangeCreateAssetDto dto;
    dto.values.PutInt(PhotoColumn::MEDIA_ID, TEST_FILE_ID);
    dto.values.PutString(PhotoColumn::MEDIA_FILE_PATH, "");
    dto.values.PutString(MediaColumn::MEDIA_NAME, "test.jpg");
    dto.values.PutInt(MediaColumn::MEDIA_TYPE, 0);

    int32_t ret = instance.AssetChangeCreateAsset(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeAddImage_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    AddImageDto dto;
    dto.fileId = fileId;
    dto.photoId = "photo_001";
    dto.deferredProcType = 0;

    int32_t ret = instance.AssetChangeAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeAddImage_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    AddImageDto dto;
    dto.fileId = fileId;
    dto.photoId = "photo_002";
    dto.deferredProcType = 1;

    int32_t ret = instance.AssetChangeAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeAddImage_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    AddImageDto dto;
    dto.fileId = fileId;
    dto.photoId = "";
    dto.deferredProcType = 0;

    int32_t ret = instance.AssetChangeAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeAddImage_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AddImageDto dto;
    dto.fileId = 0;
    dto.photoId = "photo_001";
    dto.deferredProcType = 0;

    int32_t ret = instance.AssetChangeAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CameraInnerAddImage_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    AddImageDto dto;
    dto.fileId = fileId;
    dto.photoId = "photo_001";
    dto.deferredProcType = 0;

    int32_t ret = instance.CameraInnerAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CameraInnerAddImage_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    AddImageDto dto;
    dto.fileId = fileId;
    dto.photoId = "photo_002";
    dto.deferredProcType = 1;

    int32_t ret = instance.CameraInnerAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CameraInnerAddImage_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    AddImageDto dto;
    dto.fileId = 0;
    dto.photoId = "photo_001";
    dto.deferredProcType = 0;

    int32_t ret = instance.CameraInnerAddImage(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFusionAssetsInfo_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = TEST_ALBUM_ID;
    InsertAlbumIntoTable(albumId, "test_album");

    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateOwner = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " + std::to_string(albumId) + ", " +
        PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " = 3, " +
        PhotoColumn::PHOTO_STORAGE_PATH + " = '/storage/path' WHERE " +
        PhotoColumn::MEDIA_ID + " = " + std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateOwner);

    GetFussionAssetsRespBody respBody;
    int32_t ret = instance.GetFusionAssetsInfo(albumId, respBody);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(respBody.queryResult.size(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFusionAssetsInfo_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = TEST_ALBUM_ID;
    InsertAlbumIntoTable(albumId, "test_album");

    GetFussionAssetsRespBody respBody;
    int32_t ret = instance.GetFusionAssetsInfo(albumId, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFusionAssetsInfo_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = 0;

    GetFussionAssetsRespBody respBody;
    int32_t ret = instance.GetFusionAssetsInfo(albumId, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFusionAssetsInfo_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = -1;

    GetFussionAssetsRespBody respBody;
    int32_t ret = instance.GetFusionAssetsInfo(albumId, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFusionAssetsInfo_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = TEST_ALBUM_ID;
    InsertAlbumIntoTable(albumId, "test_album");

    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateOwner = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " + std::to_string(albumId) + ", " +
        PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " = 3, " +
        PhotoColumn::PHOTO_STORAGE_PATH + " = '/storage/path', " +
        PhotoColumn::MEDIA_DATE_TRASHED + " = 1 WHERE " +
        PhotoColumn::MEDIA_ID + " = " + std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateOwner);

    GetFussionAssetsRespBody respBody;
    int32_t ret = instance.GetFusionAssetsInfo(albumId, respBody);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(respBody.queryResult.size(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DiscardCameraPhoto_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateTemp = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        PhotoColumn::PHOTO_IS_TEMP + " = 1 WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateTemp);

    int32_t ret = instance.DiscardCameraPhoto(fileId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DiscardCameraPhoto_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t ret = instance.DiscardCameraPhoto(fileId);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DiscardCameraPhoto_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;

    int32_t ret = instance.DiscardCameraPhoto(fileId);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DiscardCameraPhoto_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateTemp = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        PhotoColumn::PHOTO_IS_TEMP + " = 1 WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateTemp);

    int32_t ret = instance.DiscardCameraPhoto(fileId);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::PHOTO_IS_TEMP};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t isTemp = 0;
    resultSet->GetInt(0, isTemp);
    EXPECT_EQ(isTemp, 1);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetEffectMode_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t effectMode = 1;
    int32_t ret = instance.SetEffectMode(fileId, effectMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetEffectMode_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t effectMode = 0;
    int32_t ret = instance.SetEffectMode(fileId, effectMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetEffectMode_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t effectMode = 299;
    int32_t ret = instance.SetEffectMode(fileId, effectMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetEffectMode_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t effectMode = 1;
    int32_t ret = instance.SetEffectMode(fileId, effectMode);
    EXPECT_NE(ret, EOK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetEffectMode_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t effectMode = 1;
    int32_t ret = instance.SetEffectMode(fileId, effectMode);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::MOVING_PHOTO_EFFECT_MODE};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedEffectMode = 0;
    resultSet->GetInt(0, savedEffectMode);
    EXPECT_EQ(savedEffectMode, effectMode);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetOrientation_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t orientation = 90;
    int32_t ret = instance.SetOrientation(fileId, orientation);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetOrientation_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t orientation = 0;
    int32_t ret = instance.SetOrientation(fileId, orientation);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetOrientation_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t orientation = 270;
    int32_t ret = instance.SetOrientation(fileId, orientation);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetOrientation_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t orientation = 90;
    int32_t ret = instance.SetOrientation(fileId, orientation);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetOrientation_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t orientation = 180;
    int32_t ret = instance.SetOrientation(fileId, orientation);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::PHOTO_ORIENTATION};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedOrientation = 0;
    resultSet->GetInt(0, savedOrientation);
    EXPECT_EQ(savedOrientation, orientation);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetVideoEnhancementAttr_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "photo_001";
    std::string path = "/storage/media/local/files/Videos/test.mp4";

    int32_t ret = instance.SetVideoEnhancementAttr(fileId, photoId, path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetVideoEnhancementAttr_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "photo_002";
    std::string path = "/storage/media/local/files/Videos/test2.mp4";

    int32_t ret = instance.SetVideoEnhancementAttr(fileId, photoId, path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetVideoEnhancementAttr_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "";
    std::string path = "/storage/media/local/files/Videos/test.mp4";

    int32_t ret = instance.SetVideoEnhancementAttr(fileId, photoId, path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetVideoEnhancementAttr_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "photo_001";
    std::string path = "";

    int32_t ret = instance.SetVideoEnhancementAttr(fileId, photoId, path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetVideoEnhancementAttr_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string photoId = "photo_001";
    std::string path = "/storage/media/local/files/Videos/test.mp4";

    int32_t ret = instance.SetVideoEnhancementAttr(fileId, photoId, path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetHasAppLink_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t hasAppLink = 1;
    int32_t ret = instance.SetHasAppLink(fileId, hasAppLink);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetHasAppLink_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t hasAppLink = 0;
    int32_t ret = instance.SetHasAppLink(fileId, hasAppLink);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetHasAppLink_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t hasAppLink = 1;
    int32_t ret = instance.SetHasAppLink(fileId, hasAppLink);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetHasAppLink_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t hasAppLink = 1;
    int32_t ret = instance.SetHasAppLink(fileId, hasAppLink);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::PHOTO_HAS_APPLINK};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedHasAppLink = 0;
    resultSet->GetInt(0, savedHasAppLink);
    EXPECT_EQ(savedHasAppLink, hasAppLink);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLinkState_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t appLinkState = 1;
    int32_t ret = instance.SetAppLinkState(fileId, appLinkState);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLinkState_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t appLinkState = 0;
    int32_t ret = instance.SetAppLinkState(fileId, appLinkState);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLinkState_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t appLinkState = 1;
    int32_t ret = instance.SetAppLinkState(fileId, appLinkState);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLinkState_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t appLinkState = 2;
    int32_t ret = instance.SetAppLinkState(fileId, appLinkState);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::PHOTO_HAS_APPLINK};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedAppLinkState = 0;
    resultSet->GetInt(0, savedAppLinkState);
    EXPECT_EQ(savedAppLinkState, appLinkState);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLink_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string appLink = "app://com.example.app";
    int32_t ret = instance.SetAppLink(fileId, appLink);
    EXPECT_EQ(ret, EOK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLink_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string appLink = "";
    int32_t ret = instance.SetAppLink(fileId, appLink);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLink_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string appLink = "app://com.example.app";
    int32_t ret = instance.SetAppLink(fileId, appLink);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAppLink_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string appLink = "app://com.example.test.app/123";
    int32_t ret = instance.SetAppLink(fileId, appLink);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::PHOTO_APPLINK};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    std::string savedAppLink = "";
    resultSet->GetString(0, savedAppLink);
    EXPECT_EQ(savedAppLink, appLink);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetSupportedWatermarkType_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t watermarkType = 1;
    int32_t ret = instance.SetSupportedWatermarkType(fileId, watermarkType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetSupportedWatermarkType_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t watermarkType = 0;
    int32_t ret = instance.SetSupportedWatermarkType(fileId, watermarkType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetSupportedWatermarkType_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t watermarkType = 1;
    int32_t ret = instance.SetSupportedWatermarkType(fileId, watermarkType);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetSupportedWatermarkType_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t watermarkType = 2;
    int32_t ret = instance.SetSupportedWatermarkType(fileId, watermarkType);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {PhotoColumn::SUPPORTED_WATERMARK_TYPE};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedWatermarkType = 0;
    resultSet->GetInt(0, savedWatermarkType);
    EXPECT_EQ(savedWatermarkType, watermarkType);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    bool ret = instance.CheckMimeType(fileId);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    bool ret = instance.CheckMimeType(fileId);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = -1;
    bool ret = instance.CheckMimeType(fileId);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.heif";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateMimeType = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        MediaColumn::MEDIA_MIME_TYPE + " = 'image/heif' WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateMimeType);

    bool ret = instance.CheckMimeType(fileId);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.heic";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateMimeType = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        MediaColumn::MEDIA_MIME_TYPE + " = 'image/heic' WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateMimeType);

    bool ret = instance.CheckMimeType(fileId);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckMimeType_test_006, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string sqlUpdateMimeType = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        MediaColumn::MEDIA_MIME_TYPE + " = 'image/jpeg' WHERE " + PhotoColumn::MEDIA_ID + " = " +
        std::to_string(fileId);
    g_rdbStore->ExecuteSql(sqlUpdateMimeType);

    bool ret = instance.CheckMimeType(fileId);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetTitle_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "new_test_title";
    int32_t ret = instance.SetAssetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetTitle_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "";
    int32_t ret = instance.SetAssetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetTitle_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "very_long_title_that_exceeds_normal_length_for_testing_purposes";
    int32_t ret = instance.SetAssetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetTitle_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string title = "test_title";
    int32_t ret = instance.SetAssetTitle(fileId, title);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetTitle_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "updated_title";
    int32_t ret = instance.SetAssetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);

    vector<string> columns = {MediaColumn::MEDIA_TITLE};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    std::string savedTitle = "";
    resultSet->GetString(0, savedTitle);
    EXPECT_EQ(savedTitle, title);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetPending_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t pending = 1;
    int32_t ret = instance.SetAssetPending(fileId, pending);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetPending_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t pending = 0;
    int32_t ret = instance.SetAssetPending(fileId, pending);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetPending_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t pending = 1;
    int32_t ret = instance.SetAssetPending(fileId, pending);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetPending_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t pending = 1;
    int32_t ret = instance.SetAssetPending(fileId, pending);
    EXPECT EXPECT_EQ(ret, E_OK);

    vector<string> columns = {MediaColumn::MEDIA_TIME_PENDING};
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t savedPending = 0;
    resultSet->GetInt(0, savedPending);
    EXPECT_EQ(savedPending, pending);
    resultSet->Close();
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsFavorite_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t favorite = 1;
    int32_t ret = instance.SetAssetsFavorite(fileIds, favorite);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsFavorite_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t favorite = 0;
    int32_t ret = instance.SetAssetsFavorite(fileIds, favorite);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsFavorite_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<int32_t> fileIds;
    int32_t favorite = 1;
    int32_t ret = instance.SetAssetsFavorite(fileIds, favorite);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsFavorite_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    int32_t fileId3 = TEST_FILE_ID + 2;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    std::string filePath3 = "/storage/media/local/files/Pictures/test3.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);
    InsertAssetIntoPhotosTable(fileId3, filePath3);

    std::vector<int32_t> fileIds = {fileId1, fileId2, fileId3};
    int32_t favorite = 1;
    int32_t ret = instance.SetAssetsFavorite(fileIds, favorite);
    EXPECT_EQ(ret, E_OK);

    for (int32_t fileId : fileIds) {
        vector<string> columns = {MediaColumn::MEDIA_IS_FAV};
        NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
        rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);
        auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
        ASSERT_NE(resultSet, nullptr);
        EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
        int32_t savedFavorite = 0;
        resultSet->GetInt(0, savedFavorite);
        EXPECT_EQ(savedFavorite, favorite);
        resultSet->Close();
    }
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsHiddenStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t hiddenStatus = 1;
    int32_t ret = instance.SetAssetsHiddenStatus(fileIds, hiddenStatus);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsHiddenStatus_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t hiddenStatus = 0;
    int32_t ret = instance.SetAssetsHiddenStatus(fileIds, hiddenStatus);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsHiddenStatus_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<int32_t> fileIds;
    int32_t hiddenStatus = 1;
    int32_t ret = instance.SetAssetsHiddenStatus(fileIds, hiddenStatus);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsRecentShowStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t recentShowStatus = 1;
    int32_t ret = instance.SetAssetsRecentShowStatus(fileIds, recentShowStatus);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsRecentShowStatus_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t recentShowStatus = 0;
    int32_t ret = instance.SetAssetsRecentShowStatus(fileIds, recentShowStatus);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsUserComment_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    std::string userComment = "test_user_comment";
    int32_t ret = instance.SetAssetsUserComment(fileIds, userComment);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsUserComment_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    std::string userComment = "";
    int32_t ret = instance.SetAssetsUserComment(fileIds, userComment);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetAssetsUserComment_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<int32_t> fileIds = {fileId1, fileId2};
    std::string userComment = "very_long_user_comment_that_exceeds_normal_length_for_testing";
    int32_t ret = instance.SetAssetsUserComment(fileIds, userComment);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AddAssetVisitCount_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    int32_t visitType = 1;
    int32_t ret = instance.AddAssetVisitCount(fileId, visitType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AddAssetVisitCount_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    int32_t visitType = 0;
    int32_t ret = instance.AddAssetVisitCount(fileId, visitType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AddAssetVisitCount_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    int32_t visitType = 5;
    int32_t ret = instance.AddAssetVisitCount(fileId, visitType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AddAssetVisitCount_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t visitType = 1;
    int32_t ret = instance.AddAssetVisitCount(fileId, visitType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloneAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloneAssetDto dto;
    dto.fileId = fileId;
    dto.title = "cloned_title";
    int32_t ret = instance.CloneAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloneAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloneAssetDto dto;
    dto.fileId = fileId;
    dto.title = "";
    int32_t ret = instance.CloneAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloneAsset_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string title = "cloned_title";
    CloneAssetDto dto;
    dto.fileId = fileId;
    dto.title = title;
    int32_t ret = instance.CloneAsset(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloneAsset_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloneAssetDto dto;
    dto.fileId = fileId;
    dto.title = "very_long_title_that_exceeds_normal_length_for_testing_purposes";
    int32_t ret = instance.CloneAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RevertToOriginal_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RevertToOriginalDto dto;
    dto.fileId = fileId;
    dto.fileUri = "datashare:///media/Photo/" + std::to_string(fileId);
    int32_t ret = instance.RevertToOriginal(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RevertToOriginal_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string fileUri = "datashare:///media/Photo/1";
    RevertToOriginalDto dto;
    dto.fileId = fileId;
    dto.fileUri = fileUri;
    int32_t ret = instance.RevertToOriginal(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RevertToOriginal_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RevertToOriginalDto dto;
    dto.fileId = fileId;
    dto.fileUri = "";
    int32_t ret = instance.RevertToOriginal(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.cameraShotKey = "test_key";
    int32_t ret = instance.CreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
    EXPECT_FALSE(dto.outUri.empty());
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".mp4";
    dto.mediaType = 1;
    dto.photoSubtype = 0;
    dto.title = "test_video";
    dto.displayName = "test.mp4";
    int32_t ret = instance.CreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAsset_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "";
    dto.displayName = "test.jpg";
    int32_t ret = instance.CreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAsset_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "";
    int32_t ret = instance.CreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAsset_test_005, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.cameraShotKey = "";
    int32_t ret = instance.CreateAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForApp_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    int32_t ret = instance.CreateAssetForApp(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForApp_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".mp4";
    dto.mediaType = 1;
    dto.photoSubtype = 0;
    dto.title = "test_video";
    dto.displayName = "test.mp4";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    int32_t ret = instance.CreateAssetForApp(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForApp_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "";
    dto.displayName = "test.jpg";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    int32_t ret = instance.CreateAssetForApp(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForApp_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.appId = "";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    int32_t ret = instance.CreateAssetForApp(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForAppWithAlbum_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = TEST_ALBUM_ID;
    InsertAlbumIntoTable(albumId, "test_album");

    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    dto.ownerAlbumId = std::to_string(albumId);
    int32_t ret = instance.CreateAssetForAppWithAlbum(dto);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(dto.fileId, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForAppWithAlbum_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t albumId = TEST_ALBUM_ID;
    InsertAlbumIntoTable(albumId, "test_album");

    CreateAssetDto dto;
    dto.extension = ".mp4";
    dto.mediaType = 1;
    dto.photoSubtype = 0;
    dto.title = "test_video";
    dto.displayName = "test.mp4";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    dto.ownerAlbumId = std::to_string(albumId);
    int32_t ret = instance.CreateAssetForAppWithAlbum(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForAppWithAlbum_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "test_asset";
    dto.displayName = "test.jpg";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    dto.ownerAlbumId = "999999";
    int32_t ret = instance.CreateAssetForAppWithAlbum(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateAssetForAppWithAlbum_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CreateAssetDto dto;
    dto.extension = ".jpg";
    dto.mediaType = 0;
    dto.photoSubtype = 0;
    dto.title = "";
    dto.displayName = "test.jpg";
    dto.appId = "com.example.test";
    dto.packageName = "com.example.test";
    dto.bundleName = "com.example.test";
    dto.ownerAlbumId = "1001";
    int32_t ret = instance.CreateAssetForAppWithAlbum(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DeletePhotos_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> uris = {
        "datashare:///media/Photo/" + std::to_string(fileId1),
        "datashare:///media/Photo/" + std::to_string(fileId2)
    };
    int32_t ret = instance.DeletePhotos(uris);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DeletePhotos_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<std::string> uris;
    int32_t ret = instance.DeletePhotos(uris);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DeletePhotosCompleted_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> fileIds = {
        std::to_string(fileId1),
        std::to_string(fileId2)
    };
    int32_t ret = instance.DeletePhotosCompleted(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(F(MediaAssetsServiceTest, MediaAssetsService_DeletePhotosCompleted_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<std::string> fileIds;
    int32_t ret = instance.DeletePhotosCompleted(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DeleteAssetsPermanentlyWithUri_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> fileIds = {
        std::to_string(fileId1),
        std::to_string(fileId2)
    };
    int32_t ret = instance.DeleteAssetsPermanentlyWithUri(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_DeleteAssetsPermanentlyWithUri_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<std::string> fileIds;
    int32_t ret = instance.DeleteAssetsPermanentlyWithUri(fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveFormInfo_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    FormInfoDto dto;
    dto.formIds = {"form_id_001"};
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(TEST_FILE_ID)};
    int32_t ret = instance.SaveFormInfo(dto);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveFormInfo_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    FormInfoDto dto;
    dto.formIds = {"form_id_002"};
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(TEST_FILE_ID + 1)};
    int32_t ret = instance.SaveFormInfo(dto);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveFormInfo_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    FormInfoDto dto;
    dto.formIds = {};
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(TEST_FILE_ID)};
    int32_t ret = instance.SaveFormInfo(dto);
    EXPECT_NE(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RemoveFormInfo_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string formId = "form_id_001";
    int32_t ret = instance.RemoveFormInfo(formId);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RemoveFormInfo_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string formId = "form_id_002";
    int32_t ret = instance.RemoveFormInfo(formId);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RemoveFormInfo_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string formId = "";
    int32_t ret = instance.RemoveFormInfo(formId);
    EXPECT_NE(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveGalleryFormInfo_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    FormInfoDto dto;
    dto.formIds = {"form_id_001", "form_id_002"};
    dto.fileUris = {
        "datashare:///media/Photo/" + std::to_string(TEST_FILE_ID),
        "datashare:///media/Photo/" + std::to_string(TEST_FILE_ID + 1)
    };
    int32_t ret = instance.SaveGalleryFormInfo(dto);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveGalleryFormInfo_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    FormInfoDto dto;
    dto.formIds = {"form_id_003"};
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(TEST_FILE_ID)};
    int32_t ret = instance.SaveGalleryFormInfo(dto);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RemoveGalleryFormInfo_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string formId = "form_id_001";
    int32_t ret = instance.RemoveGalleryFormInfo(formId);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RemoveGalleryFormInfo_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string formId = "form_id_002";
    int32_t ret = instance.RemoveGalleryFormInfo(formId);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CommitEditedAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CommitEditedAssetDto dto;
    dto.fileId = fileId;
    dto.editData.PutInt(PhotoColumn::MEDIA_ID, fileId);
    dto.editData.PutString(PhotoColumn::MEDIA_TITLE, "edited_title");
    int32_t ret = instance.CommitEditedAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CommitEditedAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CommitEditedAssetDto dto;
    dto.fileId = fileId;
    dto.editData.PutInt(PhotoColumn::MEDIA_ID, fileId);
    dto.editData.PutString(PhotoColumn::MEDIA_TITLE, "");
    int32_t ret = instance.CommitEditedAsset(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CommitEditedAsset_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    CommitEditedAssetDto dto;
    dto.fileId = fileId;
    dto.editData.PutInt(PhotoColumn::MEDIA_ID, fileId);
    dto.editData.PutString(PhotoColumn::MEDIA_TITLE, "edited_title");
    int32_t ret = instance.CommitEditedAsset(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCompositeDisplayMode_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t compositeDisplayMode = 1;
    int32_t ret = instance.SetCompositeDisplayMode(fileId, compositeDisplayMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCompositeDisplayMode_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t compositeDisplayMode = 0;
    int32_t ret = instance.SetCompositeDisplayMode(fileId, compositeDisplayMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCompositeDisplayMode_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t compositeDisplayMode = 1;
    int32_t ret = instance.SetCompositeDisplayMode(fileId, compositeDisplayMode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCameraShotKey_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string cameraShotKey = "camera_shot_key_001";
    int32_t ret = instance.SetCameraShotKey(fileId, cameraShotKey);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCameraShotKey_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string cameraShotKey = "";
    int32_t ret = instance.SetCameraShotKey(fileId, cameraShotKey);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCameraShotKey_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string cameraShotKey = "camera_shot_key_001";
    int32_t ret = instance.SetCameraShotKey(fileId, cameraShotKey);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetCameraShotKey_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string cameraShotKey = "very_long_camera_shot_key_that_exceeds_normal_length";
    int32_t ret = instance.SetCameraShotKey(fileId, cameraShotKey);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveCameraPhoto_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    SaveCameraPhotoDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.mediaType = 0;
    dto.photoSubType = 0;
    dto.needScan = true;
    dto.imageFileType = 0;
    dto.discardHighQualityPhoto = false;
    dto.cameraShotKey = "test_key";
    dto.supportedWatermarkType = 1;
    int32_t ret = instance.SaveCameraPhoto(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveCameraPhoto_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    SaveCameraPhotoDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.mediaType = 1;
    dto.photoSubType = 0;
    dto.needScan = false;
    dto.imageFileType = 0;
    dto.discardHighQualityPhoto = false;
    dto.cameraShotKey = "test_key";
    int32_t ret = instance.SaveCameraPhoto(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveCameraPhoto_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    SaveCameraPhotoDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.mediaType = 0;
    dto.photoSubType = 0;
    dto.needScan = true;
    dto.imageFileType = 0;
    dto.discardHighQualityPhoto = true;
    dto.cameraShotKey = "test_key";
    dto.supportedWatermarkType = 1;
    int32_t ret = instance.SaveCameraPhoto(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SaveCameraPhoto_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    SaveCameraPhotoDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.mediaType = 0;
    dto.photoSubType = 0;
    dto.needScan = true;
    dto.imageFileType = 0;
    dto.discardHighQualityPhoto = false;
    dto.cameraShotKey = "test_key";
    int32_t ret = instance.SaveCameraPhoto(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetFavorite_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    bool favorite = true;
    int32_t ret = instance.AssetChangeSetFavorite(fileId, favorite);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetFavorite_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    bool favorite = false;
    int32_t ret = instance.AssetChangeSetFavorite(fileId, favorite);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(ret, 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetFavorite_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    bool favorite = true;
    int32_t ret = instance.AssetChangeSetFavorite(fileId, favorite);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetHidden_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string uri = "datashare:///media/Photo/" + std::to_string(fileId);
    bool hidden = true;
    int32_t ret = instance.AssetChangeSetHidden(uri, hidden);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetHidden_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string uri = "datashare:///media/Photo/" + std::to_string(fileId);
    bool hidden = false;
    int32_t ret = instance.AssetChangeSetHidden(uri, hidden);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetHidden_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string uri = "datashare:///media/Photo/1";
    bool hidden = true;
    int32_t ret = instance.AssetChangeSetHidden(uri, hidden);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetUserComment_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string userComment = "test_user_comment";
    int32_t ret = instance.AssetChangeSetUserComment(fileId, userComment);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServicearianceService_AssetChangeSetUserComment_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string userComment = "";
    int32_t ret = instance.AssetChangeSetUserComment(fileId, userComment);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetUserComment_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string userComment = "test_user_comment";
    int32_t ret = instance.AssetChangeSetUserComment(fileId, userComment);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetLocation_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    SetLocationDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.latitude = 39.9;
    dto.longitude = 116.4;
    int32_t ret = instance.AssetChangeSetLocation(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetLocation_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    SetLocationDto dto;
    dto.fileId = fileId;
    dto.path = "";
    dto.latitude = 39.9;
    dto.longitude = 116.4;
    int32_t ret = instance.AssetChangeSetLocation(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetLocation_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    SetLocationDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/media/local/files/Pictures/test.jpg";
    dto.latitude = 39.9;
    dto.longitude = 116.4;
    int32_t ret = instance.AssetChangeSetLocation(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetTitle_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "new_title";
    int32_t ret = instance.AssetChangeSetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetTitle_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string title = "";
    int32_t ret = instance.AssetChangeSetTitle(fileId, title);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetTitle_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string title = "new_title";
    int32_t ret = instance.AssetChangeSetTitle(fileId, title);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetEditData_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    values.PutString(PhotoColumn::MEDIA_TITLE, "test_title");
    int32_t ret = instance.AssetChangeSetEditData(values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetEditData_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    values.PutString(PhotoColumn::MEDIA_TITLE, "");
    int32_t ret = instance.AssetChangeSetEditData(values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AssetChangeSetEditData_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, 0);
    values.PutString(PhotoColumn::MEDIA_TITLE, "test_title");
    int32_t ret = instance.AssetChangeSetEditData(values);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAssets_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE, MediaColumn::MEDIA_NAME};
    int32_t passCode = 0;
    auto resultSet = instance.GetAssets(dto, passCode);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_GT(resultSet->GetRowCount(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAssets_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    int32_t passCode = 0;
    auto resultSet = instance.GetAssets(dto, passCode);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GetRowCount(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAssets_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, std::to_string(fileId));
    dto.predicates = predicates;
    int32_t passCode = 0;
    auto resultSet = instance.GetAssets(dto, passCode);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GetRowCount(), 1);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAllDuplicateAssets_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    auto resultSet = instance.GetAllDuplicateAssets(dto);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAllDuplicateAssets_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    auto resultSet = instance.GetAllDuplicateAssets(dto);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GetRowCount(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetDuplicateAssetsToDelete_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    auto resultSet = instance.GetDuplicateAssetsToDelete(dto);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetDuplicateAssetsToDelete_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetAssetsDto dto;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    auto resultSet = instance.GetDuplicateAssetsToDelete(dto);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GetRowCount(), 0);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartAssetChangeScanInner_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    StartAssetChangeScanDto dto;
    dto.operation = "scan_operation";
    int32_t ret = instance.StartAssetChangeScanInner(dto);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartAssetChangeScanInner_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    StartAssetChangeScanDto dto;
    dto.operation = "";
    int32_t ret = instance.StartAssetChangeScanInner(dto);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_QueryMediaDataStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string dataKey = "test_data_key";
    bool result = false;
    int32_t ret = instance.QueryMediaDataStatus(dataKey, result);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_QueryMediaDataStatus_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string dataKey = "";
    bool result = false;
    int32_t ret = instance.QueryMediaDataStatus(dataKey, result);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudMediaAssetStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string status = "test_status";
    int32_t ret = instance.GetCloudMediaAssetStatus(status);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudMediaAssetStatus_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string status = "";
    int32_t ret = instance.GetCloudMediaAssetStatus(status);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartDownloadCloudMedia_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.StartDownloadCloudMedia(CloudMediaDownloadType::START_DOWNLOAD);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartDownloadCloudMedia_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.StartDownloadCloudMedia(CloudMediaDownloadType::PAUSE_DOWNLOAD);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartDownloadCloudMedia_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.StartDownloadCloudMedia(CloudMediaDownloadType::RESUME_DOWNLOAD);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_PauseDownloadCloudMedia_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.PauseDownloadCloudMedia();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelDownloadCloudMedia_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.CancelDownloadCloudMedia();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RetainCloudMediaAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.RetainCloudMediaAsset(CloudMediaRetainType::RETAIN_FORCE);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RetainCloudMediaAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.RetainCloudMediaAsset(CloudMediaRetainType::RETAIN_NORMAL);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_NotifyAssetSended_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string uri = "datashare:///media/Photo/" + std::to_string(TEST_FILE_ID);
    int32_t ret = instance.NotifyAssetSended(uri);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_NotifyAssetSended_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string uri = "";
    int32_t ret = instance.NotifyAssetSended(uri);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAssetCompressVersion_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t version = 1;
    int32_t ret = instance.GetAssetCompressVersion(version);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetAssetCompressVersion_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t version = 0;
    int32_t ret = instance.GetAssetCompressVersion(version);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCompressAssetSize_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> uris = {
        "datashare:///media/Photo/" + std::to_string(fileId1),
        "datashare:///media/Photo/" + std::to_string(fileId2)
    };
    GetCompressAssetSizeRespBody respBody;
    int32_t ret = instance.GetCompressAssetSize(uris, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCompressAssetSize_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::vector<std::string> uris;
    GetCompressAssetSizeRespBody respBody;
    int32_t ret = instance.GetCompressAssetSize(uris, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_OpenAssetCompress_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    OpenAssetCompressDto dto;
    dto.fileId = fileId;
    dto.compressVersion = 1;
    OpenAssetCompressRespBody respBody;
    int32_t ret = instance.OpenAssetCompress(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_OpenAssetCompress_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    OpenAssetCompressDto dto;
    dto.fileId = fileId;
    dto.compressVersion = 0;
    OpenAssetCompressRespBody respBody;
    int32_t ret = instance.OpenAssetCompress(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StopRestore_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string keyPath = "/storage/test/restore_key";
    int32_t ret = instance.StopRestore(keyPath);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StopRestore_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string keyPath = "";
    int32_t ret = instance.StopRestore(keyPath);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_Restore_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RestoreDto dto;
    dto.fileId = fileId;
    dto.restoreType = 1;
    int32_t ret = instance.Restore(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_Restore_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RestoreDto dto;
    dto.fileId = fileId;
    dto.restoreType = 0;
    int32_t ret = instance.Restore(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_Restore_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    RestoreDto dto;
    dto.fileId = 0;
    dto.restoreType = 1;
    int32_t ret = instance.Restore(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_IsEdited_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    IsEditedDto dto;
    dto.fileId = fileId;
    IsEditedRespBody respBody;
    int32_t ret = instance.IsEdited(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_IsEdited_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    IsEditedDto dto;
    dto.fileId = fileId;
    IsEditedRespBody respBody;
    int32_t ret = instance.IsEdited(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RequestEditData_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RequestEditDataDto dto;
    dto.fileId = fileId;
    dto.editType = 1;
    RequestEditDataRespBody respBody;
    int32_t ret = instance.RequestEditData(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RequestEditData_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    RequestEditDataDto dto;
    dto.fileId = fileId;
    dto.editType = 0;
    RequestEditDataRespBody respBody;
    int32_t ret = instance.RequestEditData(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetEditData_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GetEditDataDto dto;
    dto.fileId = fileId;
    dto.editType = 1;
    GetEditDataRespBody respBody;
    int32_t ret = instance.GetEditData(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetEditData_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GetEditDataDto dto;
    dto.fileId = fileId;
    dto.editType = 0;
    GetEditDataRespBody respBody;
    int32_t ret = instance.GetEditData(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string photoUri = "datashare:///media/Photo/" + std::to_string(fileId);
    auto resultSet = instance.GetCloudEnhancementPair(photoUri);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string photoUri = "";
    auto resultSet = instance.GetCloudEnhancementPair(photoUri);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string photoUri = "datashare:///media/Photo/999999";
    auto resultSet resultSet = instance.GetCloudEnhancementPair(photoUri);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_004, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string photoUri = "invalid_uri_format";
    auto resultSet = instance.GetCloudEnhancementPair(photoUri);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFilePathFromUri_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string virtualId = "photo_" + std::to_string(fileId);
    GetFilePathFromUriRespBody respBody;
    int32_t ret = instance.GetFilePathFromUri(virtualId, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetFilePathFromUri_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string virtualId = "";
    GetFilePathFromUriRespBody respBody;
    int32_t ret = instance.GetFilePathFromUri(virtualId, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetUriFromFilePath_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string tempPath = "/storage/temp/test.jpg";
    GetUriFromFilePathRespBody respBody;
    int32_t ret = instance.GetUriFromFilePath(tempPath, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetUriFromFilePath_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string tempPath = "";
    GetUriFromFilePathRespBody respBody;
    int32_t ret = instance.GetUriFromFilePath(tempPath, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetUriFromFilePath_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string tempPath = "invalid_path_format";
    GetUriFromFilePathRespBody respBody;
    int32_t ret = instance.GetUriFromFilePath(tempPath, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CanSupportedCompatibleDuplicate_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string bundleName = "com.example.test";
    HeifTranscodingCheckRespBody respBody;
    int32_t ret = instance.CanSupportedCompatibleDuplicate(bundleName, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CanSupportedCompatibleDuplicate_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string bundleName = "";
    HeifTranscodingCheckRespBody respBody;
    int32_t ret = instance.CanSupportedCompatibleDuplicate(bundleName, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateTmpCompatibleDup_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CreateTmpCompatibleDupDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/temp/test_dup.jpg";
    int32_t ret = instance.CreateTmpCompatibleDup(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateTmpCompatibleDup_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CreateTmpCompatibleDupDto dto;
    dto.fileId = fileId;
    dto.path = "";
    int32_t ret = instance.CreateTmpCompatibleDup(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CreateTmpCompatibleDup_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    CreateTmpCompatibleDupDto dto;
    dto.fileId = fileId;
    dto.path = "/storage/temp/test_dup.jpg";
    int32_t ret = instance.CreateTmpCompatibleDup(dto);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AcquireDebugDatabase_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string betaIssueId = "test_issue_001";
    std::string betaScenario = "test_scenario";
    AcquireDebugDatabaseRespBody respBody;
    int32_t ret = instance.AcquireDebugDatabase(betaIssueId, betaScenario, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AcquireDebugDatabase_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string betaIssueId = "";
    std::string betaScenario = "test_scenario";
    AcquireDebugDatabaseRespBody respBody;
    int32_t ret = instance.AcquireDebugDatabase(betaIssueId, betaScenario, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_AcquireDebugDatabase_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string betaIssueId = "test_issue_002";
    std::string betaScenario = "";
    AcquireDebugDatabaseRespBody respBody;
    int32_t ret = instance.AcquireDebugDatabase(betaIssueId, betaScenario, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_ReleaseDebugDatabase_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string betaIssueId = "test_issue_001";
    int32_t ret = instance.ReleaseDebugDatabase(betaIssueId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_ReleaseDebugDatabase_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string betaIssueId = "";
    int32_t ret = instance.ReleaseDebugDatabase(betaIssueId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetResultSetFromDb_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GetResultSetFromDbDto dto;
    dto.tableName = PhotoColumn::PHOTOS_TABLE;
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    GetResultSetFromDbRespBody respBody;
    int32_t ret = instance.GetResultSetFromDb(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetResultSetFromDb_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetResultSetFromDbDto dto;
    dto.tableName = "";
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    GetResultSetFromDbRespBody respBody;
    int32_t ret = instance.GetResultSetFromDb(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetResultSetFromPhotosExtend_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string value = "test_value";
    std::vector<std::string> columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    GetResultSetFromPhotosExtendRespBody respBody;
    int32_t ret = instance.GetResultSetFromPhotosExtend(value, columns, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetResultSetFromPhotosExtend_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string value = "";
    std::vector<std::string> columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    GetResultSetFromPhotosExtendRespBody respBody;
    int32_t ret = instance.GetResultSetFromPhotosExtend(value, columns, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetMovingPhotoDateModified_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string fileIdStr = std::to_string(fileId);
    GetMovingPhotoDateModifiedRespBody respBody;
    int32_t ret = instance.GetMovingPhotoDateModified(fileIdStr, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetMovingPhotoDateModified_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string fileIdStr = "";
    GetMovingPhotoDateModifiedRespBody respBody;
    int32_t ret = instance.GetMovingPhotoDateModified(fileIdStr, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetUrisByOldUrisInner_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    std::vector<std::string> oldUris = {
        "datashare:///media/Photo/" + std::to_string(fileId1),
        "datashare:///media/Photo/" + std::to_string(fileId2)
    };
    GetUrisByOldUrisInnerDto dto;
    dto.oldUris = oldUris;
    dto.tokenId = 1001;
    int32_t ret = instance.GetUrisByOldUrisInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetUrisByOldUrisInner_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetUrisByOldUrisInnerDto dto;
    dto.oldUris = {};
    dto.tokenId = 1001;
    int32_t ret = instance.GetUrisByOldUrisInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloseAsset_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloseAssetReqBody req;
    req.fileId = fileId;
    int32_t ret = instance.CloseAsset(req);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CloseAsset_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    CloseAssetReqBody req;
    req.fileId = fileId;
    int32_t ret = instance.CloseAsset(req);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelRequest_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "photo_001";
    int32_t mediaType = 0;
    int32_t ret = instance.CancelRequest(photoId, mediaType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelRequest_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string photoId = "photo_002";
    int32_t mediaType = 1;
    int32_t ret = instance.CancelRequest(photoId, mediaType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelRequest_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    std::string photoId = "photo_001";
    int32_t mediaType = 0;
    int32_t ret = instance.CancelRequest(photoId, mediaType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RequestContent_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t position = 0;
    int32_t ret = instance.RequestContent(std::to_string(fileId), position);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RequestContent_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    int32_t position = 1;
    int32_t ret = instance.RequestContent(std::to_string(fileId), position);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_RequestContent_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    int32_t position = 0;
    int32_t ret = instance.RequestContent(std::to_string(fileId), position);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartThumbnailCreationTask_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    StartThumbnailCreationTaskDto dto;
    dto.fileId = fileId;
    dto.width = 1920;
    dto.height = 1080;
    int32_t ret = instance.StartThumbnailCreationTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartThumbnailCreationTask_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    StartThumbnailCreationTaskDto dto;
    dto.fileId = fileId;
    dto.width = 3840;
    dto.height = 2160;
    int32_t ret = instance.StartThumbnailCreationTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StopThumbnailCreationTask_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    StopThumbnailCreationTaskDto dto;
    dto.fileId = fileId;
    int32_t ret = instance.StopThumbnailCreationTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StopThumbnailCreationTask_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    StopThumbnailCreationTaskDto dto;
    dto.fileId = fileId;
    int32_t ret = instance.StopThumbnailCreationTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUriPermission_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GrantUriPermissionDto dto;
    dto.fileId = fileId;
    dto.uriType = 1;
    dto.readPermission = 1;
    dto.writePermission = 1;
    int32_t ret = instance.GrantPhotoUriPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUriPermission_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GrantUriPermissionDto dto;
    dto.fileId = fileId;
    dto.uriType = 0;
    dto.readPermission = 0;
    dto.writePermission = 0;
    int32_t ret = instance.GrantPhotoUriPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUrisPermission_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GrantUrisPermissionDto dto;
    dto.fileIds = {fileId1, fileId2};
    dto.uriTypes = {1, 1};
    dto.readPermissions = {1, 1};
    dto.writePermissions = {1, 1};
    int32_t ret = instance.GrantPhotoUrisPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUrisPermission_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GrantUrisPermissionDto dto;
    dto.fileIds = {};
    dto.uriTypes = {1, 1};
    dto.readPermissions = {1, 1};
    dto.writePermissions = {1, 1};
    int32_t ret = instance.GrantPhotoUrisPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUriPermissionInner_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GrantUriPermissionInnerDto dto;
    dto.fileIds = {fileId1, fileId2};
    dto.uriTypes = {1, 1};
    dto.permissionTypes = {1, 1};
    dto.hideSensitiveType = 0;
    int32_t ret = instance.GrantPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GrantPhotoUriPermissionInner_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    GrantUriPermissionInnerDto dto;
    dto.fileIds = {fileId1, fileId2};
    dto.uriTypes = {1, 1};
    dto.permissionTypes = {0, 0};
    dto.hideSensitiveType = 1;
    int32_t ret = instance.GrantPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckPhotoUriPermissionInner_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    CheckUriPermissionInnerDto dto;
    dto.targetTokenId = 1001;
    dto.uriType = 1;
    dto.inFileIds = {fileId1, fileId2};
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    int32_t ret = instance.CheckPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CheckPhotoUriPermissionInner_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CheckUriPermissionInnerDto dto;
    dto.targetTokenId = 1001;
    dto.uriType = 1;
    dto.inFileIds = {};
    dto.columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE};
    int32_t ret = instance.CheckPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelPhotoUriPermissionInner_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    CancelUriPermissionInnerDto dto;
    dto.fileIds = {fileId1, fileId2};
    dto.uriTypes = {1, 1};
    dto.permissionTypes = {1, 1};
    dto.srcTokenId = 1001;
    dto.targetTokenId = 2001;
    int32_t ret = instance.CancelPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelPhotoUriPermissionInner_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CancelUriPermissionInnerDto dto;
    dto.fileIds = {};
    dto.uriTypes = {1, 1};
    dto.permissionTypes = {1, 1};
    dto.srcTokenId = 1001;
    dto.targetTokenId = 2001;
    int32_t ret = instance.CancelPhotoUriPermissionInner(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelPhotoUriPermission_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CancelUriPermissionDto dto;
    dto.fileId = fileId;
    dto.uriType = 1;
    dto.readPermission = 1;
    int32_t ret = instance.CancelPhotoUriPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelPhotoUriPermission_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CancelUriPermissionDto dto;
    dto.fileId = fileId;
    dto.uriType = 0;
    dto.readPermission = 0;
    int32_t ret = instance.CancelPhotoUriPermission(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SubmitCloudEnhancementTasks_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloudEnhancementDto dto;
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(fileId)};
    dto.hasCloudWatermark = false;
    dto.triggerMode = 1;
    int32_t ret = instance.SubmitCloudEnhancementTasks(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SubmitCloudEnhancementTasks_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CloudEnhancementDto dto;
    dto.fileUris = {};
    dto.hasCloudWatermark = true;
    dto.triggerMode = 0;
    int32_t ret = instance.SubmitCloudEnhancementTasks(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_PrioritizeCloudEnhancementTask_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    CloudEnhancementDto dto;
    dto.fileUris = {"datashare:///media/Photo/" + std::to_string(fileId)};
    dto.hasCloudWatermark = false;
    dto.triggerMode = 1;
    int32_t ret = instance.PrioritizeCloudEnhancementTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_PrioritizeCloudEnhancementTask_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CloudEnhancementDto dto;
    dto.fileUris = {};
    dto.hasCloudWatermark = true;
    dto.triggerMode = 0;
    int32_t ret = instance.PrioritizeCloudEnhancementTask(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelCloudEnhancementTasks_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId1 = TEST_FILE_ID;
    int32_t fileId2 = TEST_FILE_ID + 1;
    std::string filePath1 = "/storage/media/local/files/Pictures/test1.jpg";
    std::string filePath2 = "/storage/media/local/files/Pictures/test2.jpg";
    InsertAssetIntoPhotosTable(fileId1, filePath1);
    InsertAssetIntoPhotosTable(fileId2, filePath2);

    CloudEnhancementDto dto;
    dto.fileUris = {
        "datashare:///media/Photo/" + std::to_string(fileId1),
        "datashare:///media/Photo/" + std::to_string(fileId2)
    };
    dto.hasCloudWatermark = false;
    dto.triggerMode = 1;
    int32_t ret = instance.CancelCloudEnhancementTasks(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelCloudEnhancementTasks_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CloudEnhancementDto dto;
    dto.fileUris = {};
    dto.hasCloudWatermark = true;
    dto.triggerMode = 0;
    int32_t ret = instance.CancelCloudEnhancementTasks(dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelAllCloudEnhancementTasks_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.CancelAllCloudEnhancementTasks();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SyncCloudEnhancementTaskStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t ret = instance.SyncCloudEnhancementTaskStatus();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    GetCloudEnhancementPairDto dto;
    dto.photoUri = "datashare:///media/Photo/" + std::to_string(fileId);
    GetCloudEnhancementPairRespBody respBody;
    int32_t ret = instance.GetCloudEnhancementPair(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetCloudEnhancementPairDto dto;
    dto.photoUri = "";
    GetCloudEnhancementPairRespBody respBody;
    int32_t ret = instance.GetCloudEnhancementPair(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudEnhancementPair_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = 0;
    GetCloudEnhancementPairDto dto;
    dto.photoUri = "datashare:///media/Photo/" + std::to_string(fileId);
    GetCloudEnhancementPairRespBody respBody;
    int32_t ret = instance.GetCloudEnhancementPair(dto, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_QueryCloudEnhancementTaskState_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    int32_t fileId = TEST_FILE_ID;
    std::string filePath = "/storage/media/local/files/Pictures/test.jpg";
    InsertAssetIntoPhotosTable(fileId, filePath);

    std::string photoUri = "datashare:///media/Photo/" + std::to_string(fileId);
    QueryCloudEnhancementTaskStateDto dto;
    int32_t ret = instance.QueryCloudEnhancementTaskState(photoUri, dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_QueryCloudEnhancementTaskState_test_002, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string photoUri = "";
    QueryCloudEnhancementTaskStateDto dto;
    int32_t ret = instance.QueryCloudEnhancementTaskState(photoUri, dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_QueryCloudEnhancementTaskState_test_003, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    std::string photoUri = "datashare:///media/Photo/999999";
    QueryCloudEnhancementTaskStateDto dto;
    int32_t ret = instance.QueryCloudEnhancementTaskState(photoUri, dto);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_StartBatchDownloadCloudResources_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    StartBatchDownloadCloudResourcesReqBody reqBody;
    reqBody.downloadType = 1;
    StartBatchDownloadCloudResourcesRespBody respBody;
    int32_t ret = instance.StartBatchDownloadCloudResources(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_SetNetworkPolicyForBatchDownload_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    SetNetworkPolicyForBatchDownloadReqBody reqBody;
    reqBody.networkPolicy = 1;
    int32_t ret = instance.SetNetworkPolicyForBatchDownload(reqBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_ResumeBatchDownloadCloudResources_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    ResumeBatchDownloadCloudResourcesReqBody reqBody;
    reqBody.taskId = "test_task_001";
    ResumeBatchDownloadCloudResourcesRespBody respBody;
    int32_t ret = instance.ResumeBatchDownloadCloudResources(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_PauseBatchDownloadCloudResources_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    PauseBatchDownloadCloudResourcesReqBody reqBody;
    reqBody.taskId = "test_task_001";
    PauseBatchDownloadCloudResourcesRespBody respBody;
    int32_t ret = instance.PauseBatchDownloadCloudResources(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_CancelBatchDownloadCloudResources_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    CancelBatchDownloadCloudResourcesReqBody reqBody;
    reqBody.taskId = "test_task_001";
    CancelBatchDownloadCloudResourcesRespBody respBody;
    int32_t ret = instance.CancelBatchDownloadCloudResources(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudMediaBatchDownloadResourcesStatus_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetBatchDownloadCloudResourcesStatusReqBody reqBody;
    reqBody.taskId = "test_task_001";
    GetBatchDownloadCloudResourcesStatusRespBody respBody;
    int32_t ret = instance.GetCloudMediaBatchDownloadResourcesStatus(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudMediaBatchDownloadResourcesCount_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetBatchDownloadCloudResourcesCountReqBody reqBody;
    reqBody.taskId = "test_task_001";
    GetBatchDownloadCloudResourcesCountRespBody respBody;
    int32_t ret = instance.GetCloudMediaBatchDownloadResourcesCount(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsServiceTest, MediaAssetsService_GetCloudMediaBatchDownloadResourcesSize_test_001, TestSize.Level1)
{
    auto &instance = MediaAssetsService::GetInstance();
    GetBatchDownloadCloudResourcesSizeReqBody reqBody;
    reqBody.taskId = "test_task_001";
    GetBatchDownloadCloudResourcesSizeRespBody respBody;
    int32_t ret = instance.GetCloudMediaBatchDownloadResourcesSize(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
}

} // namespace OHOS::Media