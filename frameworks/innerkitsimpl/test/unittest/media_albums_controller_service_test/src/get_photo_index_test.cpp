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
 
#define MLOG_TAG "MediaAssetsControllerServiceTest"
 
#include "get_photo_index_test.h"
 
#include <string>
#include <vector>
 
#define private public
#define protected public
#include "datashare_result_set.h"
#include "media_albums_controller_service.h"
#include "media_assets_service.h"
#include "rdb_utils.h"
#undef private
#undef protected
 
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "get_photo_index_vo.h"
#include "query_result_vo.h"
 
namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
 
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;
 
static int32_t DeleteDatabaseData()
{
    if (g_rdbStore == nullptr) {
        std::cout << "g_rdbStore == nullptr" << std::endl;
        return E_ERR;
    }
    std::cout << "DeleteDatabaseData" << std::endl;
    // delete photo
    std::string deletePhotoData = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE;
    int32_t ret = g_rdbStore->ExecuteSql(deletePhotoData);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete Photos Data Failed:" << deletePhotoData;
        return E_ERR;
    }
    std::cout << "Delete Photos Data success." << std::endl;

    // tab_analysis_total
    std::string deleteAnalysisTotalSql = "DELETE FROM tab_analysis_total;";
    ret = g_rdbStore->ExecuteSql(deleteAnalysisTotalSql);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete tab_analysis_total Data Failed:" << deleteAnalysisTotalSql;
        return E_ERR;
    }
    std::cout << "Delete tab_analysis_total Data success." << std::endl;

    // tab_user_photography_info
    std::string deleteUserPhotographyInfo = "DELETE FROM tab_user_photography_info;";
    ret = g_rdbStore->ExecuteSql(deleteUserPhotographyInfo);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete tab_user_photography_info Data Failed:" << deleteAnalysisTotalSql;
        return E_ERR;
    }
    std::cout << "Delete tab_user_photography_info Data success." << std::endl;

    // tab_highlight_album
    std::string deleteHightlightAlbum = "DELETE FROM tab_highlight_album;";
    ret = g_rdbStore->ExecuteSql(deleteHightlightAlbum);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete tab_highlight_album Data Failed:" << deleteAnalysisTotalSql;
        return E_ERR;
    }
    std::cout << "Delete tab_highlight_album Data success." << std::endl;

    std::string deletePhotoAlbum = "DELETE FROM PhotoAlbum;";
    ret = g_rdbStore->ExecuteSql(deletePhotoAlbum);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete PhotoAlbum Data Failed:" << deletePhotoAlbum;
        return E_ERR;
    }
    std::cout << "Delete PhotoAlbum Data success." << std::endl;

    std::string deleteAnalysisPhotoMap = "DELETE FROM AnalysisPhotoMap;";
    ret = g_rdbStore->ExecuteSql(deleteAnalysisPhotoMap);
    if (ret != NativeRdb::E_OK) {
        std::cout << "Delete AnalysisPhotoMap Data Failed:" << deleteAnalysisPhotoMap;
        return E_ERR;
    }
    std::cout << "Delete AnalysisPhotoMap Data success." << std::endl;

    return E_OK;
}
 
 
void GetPhotoIndexTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start GetPhotoIndexTest failed, can not get g_rdbStore");
        exit(1);
    }
    DeleteDatabaseData();
    MEDIA_INFO_LOG("SetUpTestCase");
}
 
void GetPhotoIndexTest::TearDownTestCase(void)
{
    DeleteDatabaseData();
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}
 
void GetPhotoIndexTest::SetUp()
{
    DeleteDatabaseData();
    MEDIA_INFO_LOG("SetUp");
}
 
void GetPhotoIndexTest::TearDown(void)
{
    DeleteDatabaseData();
    MEDIA_INFO_LOG("TearDown");
}
 
static void InsertAssetIntoPhotosTable(const std::string &filePath, const std::string &photoId, int photoQuality)
{
    const std::string sqlInsertPhoto = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "("  +
        MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
        MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
        MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
        PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ", " + PhotoColumn::PHOTO_ID + ", " +
        PhotoColumn::PHOTO_QUALITY + ")";
    g_rdbStore->ExecuteSql(sqlInsertPhoto + "VALUES (" +
        "'" + filePath + "', 175258, 'cam_pic', 'cam_pic.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 0, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, '1', '" + photoId  + "', " + std::to_string(photoQuality) + ")"); // cam, pic, shootingmode = 1
}

// ANALYSIS_PHOTO_MAP_TABLE
static int InsertAnalysisPhotoMap(int mediaId)
{
    int ret = g_rdbStore->ExecuteSql(
        "insert into AnalysisPhotoMap(map_album, map_asset) values(" + std::to_string(mediaId) + ", 1000012)");
    return ret;
}

// PhotoAlbumColumns::TABLE
static int InsertPhotoAlbum()
{
    int ret = g_rdbStore->ExecuteSql(
        "insert into PhotoAlbum(album_id, album_type, album_subtype) values(1, 1024, 1025)");
    return ret;
}

HWTEST_F(GetPhotoIndexTest, GetPhotoIndexTest_Test_001, TestSize.Level0)
{
    bool createDirRes = MediaFileUtils::CreateDirectory("/data/local/tmp");
    EXPECT_EQ(createDirRes, true);
    std::string filePath = "/data/local/tmp/IMG_1501924305_001.jpg";
    if (!MediaFileUtils::IsFileExists(filePath)) {
        bool createFileRes = MediaFileUtils::CreateFile(filePath);
        EXPECT_EQ(createFileRes, true);
    }
    const std::string photoId = "photo_id_test";
    int photoQuality = 1;
    InsertAssetIntoPhotosTable(filePath, photoId, photoQuality);
 
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_FILE_PATH, filePath);
    std::vector<std::string> columns = { MediaColumn::MEDIA_ID, PhotoColumn::PHOTO_ID, PhotoColumn::PHOTO_QUALITY };
 
    shared_ptr<NativeRdb::ResultSet> resSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    EXPECT_NE(resSet, nullptr);
    EXPECT_EQ(resSet->GoToNextRow(), NativeRdb::E_OK);
    EXPECT_EQ(InsertAnalysisPhotoMap(GetInt32Val(MediaColumn::MEDIA_ID, resSet)), NativeRdb::E_OK) ;
    RdbPredicates analysisPhotoMapPredicates(ANALYSIS_PHOTO_MAP_TABLE);
    columns = { "map_album" };
    resSet = MediaLibraryRdbStore::Query(analysisPhotoMapPredicates, columns);
    int rowsCount = 0;
    while (resSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string val = "";
        resSet->GetString(0, val);
        std::cout << "map_album = " << val << std::endl;
        ++rowsCount;
    }
    std::cout << "analysisPhotoMap rowsCount = " << rowsCount << std::endl;

    EXPECT_EQ(InsertPhotoAlbum(), NativeRdb::E_OK);
    RdbPredicates photoAlbumPredicates(PhotoAlbumColumns::TABLE);
    columns = { "album_id", "album_type" };
    resSet = MediaLibraryRdbStore::Query(photoAlbumPredicates, columns);
    EXPECT_NE(resSet, nullptr);
    rowsCount = 0;
    std::string album_id = "";
    while (resSet->GoToNextRow() == NativeRdb::E_OK) {
        resSet->GetString(0, album_id);
        std::cout << "album_id = " << album_id << std::endl;
        ++rowsCount;
    }
    EXPECT_EQ(rowsCount, 1);
    std::cout << "photoAlbum rowsCount = " << rowsCount << std::endl;
    columns = { photoId, album_id };
    GetPhotoIndexReqBody reqBody;
    DataShare::DataSharePredicates dataSharePredicates;
    reqBody.predicates = dataSharePredicates;
    reqBody.photoId = photoId;
    reqBody.albumId = album_id;
    reqBody.isAnalysisAlbum = false;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    auto service = make_shared<MediaAlbumsControllerService>();
    service->GetPhotoIndex(data, reply);
    IPC::MediaRespVo<QueryResultRespBody> resp;
    bool isValid = resp.Unmarshalling(reply);
    ASSERT_EQ(isValid, true);
    EXPECT_NE(resp.GetErrCode(), E_SUCCESS);
}
 
}  // namespace OHOS::Media