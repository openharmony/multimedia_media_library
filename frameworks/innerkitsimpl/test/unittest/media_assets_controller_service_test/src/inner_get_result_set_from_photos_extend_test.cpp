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

#include "inner_get_result_set_from_photos_extend_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "get_result_set_from_photos_extend_vo.h"
#include "get_result_set_from_db_vo.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "media_file_uri.h"

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

void GetResultSetFromPhotosExtendTest::SetUpTestCase(void)
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

void GetResultSetFromPhotosExtendTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void GetResultSetFromPhotosExtendTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void GetResultSetFromPhotosExtendTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static const string SQL_INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
    MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
    MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
    MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
    MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_HIDDEN +", " +
    PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " + PhotoColumn::PHOTO_EDIT_TIME + ", " +
    PhotoColumn::PHOTO_SUBTYPE + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ")";

static void InsertMovingAssetIntoPhotosTable(const string& data, const string& title)
{
    // data, size, title, display_name, media_type,
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, hidden
    // height, width, edit_time, subtype, shooting_mode
    g_rdbStore->ExecuteSql(SQL_INSERT_PHOTO + "VALUES ('" + data + "', 175258, '" + title + "', '" +
        title + ".jpg', 1, 'com.ohos.camera', '相机', 1748423617814, 1748424146785, 1748423617706, " +
        "0, 0, 0, 1280, 960, 0, 3, '1' )"); // cam, pic, subtype = 3(PhotoSubType::MOVING_PHOTO)
}

static shared_ptr<NativeRdb::ResultSet> QueryAsset(const string& displayName, const vector<string>& columns)
{
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file asset");
        return nullptr;
    }
    return resultSet;
}

static std::shared_ptr<DataShare::DataShareResultSet> GetResultSetFromPhotos(
    const string &value, vector<string> &columns)
{
    GetResultSetFromPhotosExtendReqBody reqBody;
    reqBody.value = value;
    reqBody.columns = columns;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return nullptr;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GetResultSetFromPhotosExtend(data, reply);

    IPC::MediaRespVo<GetResultSetFromDbRespBody> resp;
    if (resp.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("resp.Unmarshalling failed");
        return nullptr;
    }

    auto resultSet = resp.GetBody().resultSet;
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file asset");
        return nullptr;
    }
    return resultSet;
}

HWTEST_F(GetResultSetFromPhotosExtendTest, GetResultSetFromPhotosExtendTest_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetResultSetFromPhotosExtendTest_Test_001");
    // 1、前置条件准备，插入一张动态照片到数据库
    string data = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
    string title = "cam_pic";
    InsertMovingAssetIntoPhotosTable(data, title);

    // 2、查询数据是否插入成功
    vector<string> columns;
    auto resultSet = QueryAsset(title + ".jpg", columns);
    ASSERT_NE(resultSet, nullptr);
    string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    EXPECT_GT(displayName.size(), 0);

    int32_t fileId = GetInt32Val(PhotoColumn::MEDIA_ID, resultSet);
    string path = GetStringVal(PhotoColumn::MEDIA_FILE_PATH, resultSet);
    string uri = MediaFileUri::GetPhotoUri(to_string(fileId), path, displayName);

    // 3、查询照片
    std::shared_ptr<DataShare::DataShareResultSet> ptr = GetResultSetFromPhotos("1", columns);
    EXPECT_EQ(ptr, nullptr);

    ptr = GetResultSetFromPhotos(uri, columns);
    EXPECT_NE(ptr, nullptr);
    MEDIA_INFO_LOG("end GetResultSetFromPhotosExtendTest_Test_001");
}

HWTEST_F(GetResultSetFromPhotosExtendTest, GetResultSetFromPhotosExtendTest_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetResultSetFromPhotosExtendTest_Test_002");
    MessageParcel data;
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GetResultSetFromPhotosExtend(data, reply);

    IPC::MediaRespVo<GetResultSetFromDbRespBody> resp;
    ASSERT_EQ(resp.Unmarshalling(reply), true);
    ASSERT_LT(resp.GetErrCode(), 0);
    MEDIA_INFO_LOG("end GetResultSetFromPhotosExtendTest_Test_002");
}
}  // namespace OHOS::Media