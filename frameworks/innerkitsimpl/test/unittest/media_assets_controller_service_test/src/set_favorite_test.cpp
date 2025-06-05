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

#include "set_favorite_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "datashare_result_set.h"
#include "media_assets_controller_service.h"
#include "media_assets_service.h"
#include "rdb_utils.h"
#undef private
#undef protected

#include "create_asset_vo.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace IPC;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void SetFavoriteTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void SetFavoriteTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void SetFavoriteTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void SetFavoriteTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static void InsertAssetIntoPhotosTable(const std::string &filePath)
{
    const std::string sqlInsertPhoto = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "("  +
        MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
        MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
        MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
        PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ")";
    // file_id,
    // data, size, title, display_name, media_type,
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, date_trashed, hidden
    // height, width, edit_time, shooting_mode
    g_rdbStore->ExecuteSql(sqlInsertPhoto + "VALUES (" +
        "'" + filePath + "', 175258, 'cam_pic', 'cam_pic.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 0, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, '1' )"); // cam, pic, shootingmode = 1
}

static shared_ptr<NativeRdb::ResultSet> QueryAsset(const string& filePath, const vector<string>& columns)
{
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_FILE_PATH, filePath);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file asset");
        return nullptr;
    }
    return resultSet;
}

static int32_t SetFavorite(int32_t fileId, bool favorite)
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = fileId;
    reqBody.favorite = favorite;

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);

    auto service = make_shared<MediaAssetsControllerService>();
    service->AssetChangeSetFavorite(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> resp;
    if (resp.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("resp.Unmarshalling failed");
        return -1;
    }

    return resp.GetErrCode();
}

HWTEST_F(SetFavoriteTest, SetFavoriteTest_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetFavoriteTest_Test_001");
    // 1、前置条件准备，插入一张照片
    std::string filePath = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
    InsertAssetIntoPhotosTable(filePath);

    // 2、查询fileId
    vector<string> columns;
    auto resultSet = QueryAsset(filePath, columns);
    ASSERT_NE(resultSet, nullptr);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    EXPECT_GT(fileId, 0);

    // 3、设置收藏
    int32_t ret = SetFavorite(-1, true);
    EXPECT_EQ(ret, -EINVAL);

    int32_t changedRows = SetFavorite(fileId, true);
    EXPECT_GT(changedRows, 0);

    changedRows = SetFavorite(fileId, false);
    EXPECT_GT(changedRows, 0);
    MEDIA_INFO_LOG("end SetFavoriteTest_Test_001");
}

}  // namespace OHOS::Media