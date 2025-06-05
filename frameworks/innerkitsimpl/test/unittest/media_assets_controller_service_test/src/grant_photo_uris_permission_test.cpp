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

#include "grant_photo_uris_permission_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "grant_photo_uris_permission_vo.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "ipc_skeleton.h"

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
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ")";
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

void GrantUrisPermissionTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    ClearTable(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void GrantUrisPermissionTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    ClearTable(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void GrantUrisPermissionTest::SetUp()
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    ClearTable(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("SetUp");
}

void GrantUrisPermissionTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

int32_t GrantUrisPermission(std::vector<int32_t>& fileIds)
{
    GrantUrisPermissionReqBody reqBody;
    reqBody.tokenId = IPCSkeleton::GetCallingTokenID();
    reqBody.srcTokenId = IPCSkeleton::GetCallingTokenID();
    reqBody.fileIds = fileIds;
    reqBody.permissionType = AppUriPermissionColumn::PERMISSION_TEMPORARY_READ_WRITE;
    reqBody.hideSensitiveType = AppUriSensitiveColumn::SENSITIVE_SHOOTING_PARAM_DESENSITIZE;
    reqBody.uriType = AppUriPermissionColumn::URI_PHOTO;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GrantPhotoUrisPermission(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    MEDIA_INFO_LOG("Grant ErrCode:%{public}d", respVo.GetErrCode());
    return respVo.GetErrCode();
}

static void InsertAsset(string displayName)
{
    // data, size,
    // title, display_name, media_type,
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, date_trashed, hidden
    // height, width, edit_time, shooting_mode
    std::string insertSql =
        SQL_INSERT_PHOTO + " VALUES (" + "'/storage/cloud/files/Photo/16/" + displayName + ".jpg', 175258, '" +
        displayName + "', '" + displayName + ".jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 0, 1501924205, 0, 0, 0, 0, " + "1280, 960, 0, '1'" + VALUES_END;
    int32_t ret = g_rdbStore->ExecuteSql(insertSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", insertSql.c_str());
    }
}

static void InsertAssetSystem()
{
    std::string insertSql =
        SQL_INSERT_PHOTO + " VALUES (" +
        "'/storage/cloud/files/Photo/20/IMG_1501924306_222.jpg', 175259, 'system_cam_pic', 'system_cam_pic.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205219, 0, 1501924206, 0, 0, 0, 0, " + "1280, 960, 0, '1'" + VALUES_END;
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

static int32_t QueryUriPermissionTableByFileId(int32_t fileId)
{
    vector<string> columns;
    RdbPredicates rdbPredicates(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    rdbPredicates.EqualTo(AppUriPermissionColumn::FILE_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get fileId");
        return -1;
    }
    int32_t uriType = GetInt32Val(AppUriPermissionColumn::URI_TYPE, resultSet);
    int32_t permType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, resultSet);
    int64_t srcToken = GetInt64Val(AppUriPermissionColumn::SOURCE_TOKENID, resultSet);
    int64_t targetToken = GetInt64Val(AppUriPermissionColumn::TARGET_TOKENID, resultSet);
    return 0;
}

static int32_t QueryUriSensitiveTableByFileId(int32_t fileId)
{
    vector<string> columns;
    RdbPredicates rdbPredicates(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    rdbPredicates.EqualTo(AppUriSensitiveColumn::FILE_ID, fileId);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get fileId");
        return -1;
    }
    int32_t uriType = GetInt32Val(AppUriSensitiveColumn::URI_TYPE, resultSet);
    int32_t sensitiveType = GetInt32Val(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, resultSet);
    int64_t srcToken = GetInt64Val(AppUriSensitiveColumn::SOURCE_TOKENID, resultSet);
    int64_t targetToken = GetInt64Val(AppUriSensitiveColumn::TARGET_TOKENID, resultSet);
    return 0;
}

HWTEST_F(GrantUrisPermissionTest, GrantUrisPermission_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GrantUrisPermission_Test_001 Begin");
    std::vector<int32_t> fileIds = {10000000, 10000001, 10000002};
    int32_t result = GrantUrisPermission(fileIds);
    ASSERT_LT(result, 0);
}

HWTEST_F(GrantUrisPermissionTest, GrantUrisPermission_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("GrantUrisPermission_Test_002 Begin");
    string pic1 = "cam_pic1";
    InsertAsset(pic1);
    int32_t fileId = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    MEDIA_INFO_LOG("GrantUrisPermission_Test_002 fileId = %{public}d", fileId);
    ASSERT_GT(fileId, 0);

    std::vector<int32_t> fileIds = {fileId, 10000000};
    int32_t result = GrantUrisPermission(fileIds);
    ASSERT_LT(result, 0);
}

HWTEST_F(GrantUrisPermissionTest, GrantUrisPermission_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("GrantUrisPermission_Test_003 Begin");
    string pic1 = "cam_pic1";
    InsertAsset(pic1);
    string pic2 = "cam_pic2";
    InsertAsset(pic2);
    int32_t fileId1 = QueryPhotoIdByDisplayName(pic1 + ".jpg");
    int32_t fileId2 = QueryPhotoIdByDisplayName(pic2 + ".jpg");
    MEDIA_INFO_LOG("GrantUrisPermission_Test_003 fileId1 = %{public}d, fileId1 = %{public}d", fileId1, fileId2);
    ASSERT_GT(fileId1, 0);
    ASSERT_GT(fileId2, 0);
    std::vector<int32_t> fileIds = {fileId1, fileId2};
    int32_t result = GrantUrisPermission(fileIds);
    ASSERT_EQ(result, 0);
}

}  // namespace OHOS::Media