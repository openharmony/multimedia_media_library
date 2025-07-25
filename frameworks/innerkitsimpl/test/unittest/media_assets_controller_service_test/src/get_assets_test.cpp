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

#include "get_assets_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "get_assets_vo.h"

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
using OHOS::DataShare::DataSharePredicates;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;
static const string SQL_INSERT_PHOTO =
    "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE +
    ", " + MediaColumn::MEDIA_TITLE + ", " + MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " +
    MediaColumn::MEDIA_OWNER_PACKAGE + ", " + MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED +
    ", " + MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
    MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ", " + PhotoColumn::PHOTO_BURST_KEY + ")";
static const string VALUES_END = ") ";

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear photos table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void GetAssetsTest::SetUpTestCase(void)
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

void GetAssetsTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void GetAssetsTest::SetUp()
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("SetUp");
}

void GetAssetsTest::TearDown(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("TearDown");
}

static int32_t GetBurstAssets(string burstKey, std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    GetAssetsReqBody reqBody;
    reqBody.burstKey = burstKey;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    OHOS::Media::IPC::IPCContext context(MessageOption(), 0);
    auto service = make_shared<MediaAssetsControllerService>();
    service->GetBurstAssets(data, reply, context);

    IPC::MediaRespVo<GetAssetsRespBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }
    resultSet = respVo.GetBody().resultSet;
    return 0;
}

static int32_t GetAssets(std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    GetAssetsReqBody reqBody;
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    OHOS::Media::IPC::IPCContext context(MessageOption(), 0);
    auto service = make_shared<MediaAssetsControllerService>();
    service->GetAssets(data, reply, context);

    IPC::MediaRespVo<GetAssetsRespBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }
    resultSet = respVo.GetBody().resultSet;
    return 0;
}

using ServiceMethod = std::function<void(MessageParcel &, MessageParcel &)>;
static int32_t GetDupAssets(std::shared_ptr<DataShare::DataShareResultSet> &resultSet, ServiceMethod serviceMethod)
{
    GetAssetsReqBody reqBody;
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    serviceMethod(data, reply);

    IPC::MediaRespVo<GetAssetsRespBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }
    resultSet = respVo.GetBody().resultSet;
    return 0;
}

static void InsertAsset(string displayName, string title, string burstKey)
{
    // data, size,
    // title, display_name, media_type,
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, date_trashed, hidden
    // height, width, edit_time, shooting_mode
    std::string insertSql = SQL_INSERT_PHOTO + " VALUES (" + "'/storage/cloud/files/Photo/16/" + displayName +
                            ".jpg', 175258, '" + title + "', '" + displayName + ".jpg', 1, " +
                            "'com.ohos.camera', '相机', 1501924205218, 0, 1501924205, 0, 0, 0, 0, " +
                            "1280, 960, 0, '1', '" + burstKey + "'" + VALUES_END;
    int32_t ret = g_rdbStore->ExecuteSql(insertSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", insertSql.c_str());
    }
}

static int32_t QueryPhotoIdByDisplayName(const string &displayName)
{
    vector<string> columns;
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get fileId");
        return -1;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    return fileId;
}

HWTEST_F(GetAssetsTest, GetAssets_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_001 for GetBurstAssets Begin");
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    int32_t result = GetBurstAssets("invalid", resultSet);
    ASSERT_EQ(result, 0);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_NE(resultSet->GoToFirstRow(), E_OK);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_002 for GetBurstAssets Begin");
    string pic1 = "cam_pic1";
    string burstKey = "burst_test";
    InsertAsset(pic1, pic1, burstKey);
    int32_t fileId = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    ASSERT_GT(fileId, 0);

    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    int32_t result = GetBurstAssets(burstKey, resultSet);
    ASSERT_EQ(result, 0);

    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    ASSERT_EQ(GetInt32Val(MediaColumn::MEDIA_ID, resultSet), fileId);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_003 for public Begin");
    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    int32_t result = GetAssets(resultSet);
    ASSERT_EQ(result, 0);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_NE(resultSet->GoToFirstRow(), E_OK);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_004 for public Begin");
    string pic1 = "cam_pic1";
    InsertAsset(pic1, pic1, "");
    int32_t fileId = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    ASSERT_GT(fileId, 0);

    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    int32_t result = GetAssets(resultSet);
    ASSERT_EQ(result, 0);

    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    ASSERT_EQ(GetInt32Val(MediaColumn::MEDIA_ID, resultSet), fileId);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_005 for system duplicate Begin");
    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    ServiceMethod serviceMethod = [service](MessageParcel &data, MessageParcel &reply) {
        service->GetAllDuplicateAssets(data, reply);
    };
    int32_t result = GetDupAssets(resultSet, serviceMethod);
    ASSERT_EQ(result, 0);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_NE(resultSet->GoToFirstRow(), E_OK);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_006 for system duplicate Begin");
    string pic1 = "cam_pic1";
    string title = "same";
    InsertAsset(pic1, title, "");
    int32_t fileId1 = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    ASSERT_GT(fileId1, 0);

    string pic2 = "cam_pic2";
    InsertAsset(pic2, title, "");
    int32_t fileId2 = QueryPhotoIdByDisplayName(pic2 + ".jpg");
    ASSERT_GT(fileId2, 0);

    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    ServiceMethod serviceMethod = [service](MessageParcel &data, MessageParcel &reply) {
        service->GetAllDuplicateAssets(data, reply);
    };
    int32_t result = GetDupAssets(resultSet, serviceMethod);
    ASSERT_EQ(result, 0);

    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    int32_t mediaId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    ASSERT_TRUE(mediaId == fileId1 || mediaId == fileId2);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_007 for system duplicateToDelete Begin");
    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    ServiceMethod serviceMethod = [service](MessageParcel &data, MessageParcel &reply) {
        service->GetDuplicateAssetsToDelete(data, reply);
    };
    int32_t result = GetDupAssets(resultSet, serviceMethod);
    ASSERT_EQ(result, 0);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_NE(resultSet->GoToFirstRow(), E_OK);
}

HWTEST_F(GetAssetsTest, GetAssets_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAssets_Test_008 for system duplicateToDelete Begin");
    string pic1 = "cam_pic1";
    string title = "same";
    InsertAsset(pic1, title, "");
    int32_t fileId1 = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    ASSERT_GT(fileId1, 0);

    string pic2 = "cam_pic2";
    InsertAsset(pic2, title, "");
    int32_t fileId2 = QueryPhotoIdByDisplayName(pic2 + ".jpg");
    ASSERT_GT(fileId2, 0);

    auto service = make_shared<MediaAssetsControllerService>();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    ServiceMethod serviceMethod = [service](MessageParcel &data, MessageParcel &reply) {
        service->GetDuplicateAssetsToDelete(data, reply);
    };
    int32_t result = GetDupAssets(resultSet, serviceMethod);
    ASSERT_EQ(result, 0);

    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    int32_t mediaId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    ASSERT_TRUE(mediaId == fileId1 || mediaId == fileId2);
}

}  // namespace OHOS::Media