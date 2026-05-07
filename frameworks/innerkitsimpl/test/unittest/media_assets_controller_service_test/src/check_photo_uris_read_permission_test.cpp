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

#define MLOG_TAG "MediaAssetsControllerServiceTest"

#include "check_photo_uris_read_permission_test.h"

#include <memory>
#include <string>

#include <map>
#include <vector>
#include <gtest/gtest.h>

#include "media_assets_controller_service.h"

#include "check_photo_uris_read_permission_vo.h"
#include "accesstoken_kit.h"
#include "get_self_permissions.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "token_setproc.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static const string READ_IMAGEVIDEO_PERMISSION = "ohos.permission.READ_IMAGEVIDEO";
static constexpr int32_t URI_FORMAT_ERROR_STATE = 0;
static constexpr int32_t FILE_NOT_EXIST_STATE = 1;
static constexpr int32_t READ_PERMISSION_STATE = 2;
static constexpr int32_t NO_READ_PERMISSION_STATE = 3;

class SelfTokenRestorer {
public:
    SelfTokenRestorer() : tokenId_(IPCSkeleton::GetSelfTokenID()) {}

    ~SelfTokenRestorer()
    {
        if (SetSelfTokenID(tokenId_) != 0) {
            MEDIA_ERR_LOG("Restore self token failed");
            return;
        }
        int32_t ret = Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        if (ret < 0) {
            MEDIA_ERR_LOG("Reload Native Token Info failed when restoring self token");
        }
    }

private:
    uint64_t tokenId_;
};

static const string SQL_INSERT_PHOTO =
    "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_FILE_PATH + ", " +
    MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " + MediaColumn::MEDIA_NAME + ", " +
    MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
    MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", " +
    MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " +
    MediaColumn::MEDIA_DATE_TRASHED + ", " + MediaColumn::MEDIA_HIDDEN + ", " +
    PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ")";
static const string VALUES_END = ") ";

static int32_t ClearTable(const string &table)
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("ClearTable skipped because g_rdbStore is null, table: %{public}s", table.c_str());
        return E_HAS_DB_ERROR;
    }
    RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear table, table: %{public}s, err: %{public}d", table.c_str(), err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t ClearRelatedTables()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("ClearRelatedTables skipped because g_rdbStore is null");
        return E_HAS_DB_ERROR;
    }

    static const vector<string> tablesToClear = {
        PhotoColumn::PHOTOS_TABLE,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE,
        AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE,
    };

    for (const auto &table : tablesToClear) {
        if (ClearTable(table) != E_OK) {
            return E_HAS_DB_ERROR;
        }
    }

    return E_OK;
}

void CheckPhotoUrisReadPermissionTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("CheckPhotoUrisReadPermissionTest::SetUpTestCase:: invoked");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get g_rdbStore");
        GTEST_FAIL() << "Unable to acquire MediaLibraryRdbStore";
        return;
    }
    ClearRelatedTables();
    MEDIA_INFO_LOG("CheckPhotoUrisReadPermissionTest::SetUpTestCase:: Finish");
}

void CheckPhotoUrisReadPermissionTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase start");
    ClearRelatedTables();
    MEDIA_INFO_LOG("TearDownTestCase end");
}

void CheckPhotoUrisReadPermissionTest::SetUp(void)
{
    MEDIA_INFO_LOG("SetUp");
}

void CheckPhotoUrisReadPermissionTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static int32_t CheckPhotoUrisReadPermission(const vector<string> &uris, map<string, int32_t> &stateMap)
{
    CheckPhotoUrisReadPermissionReqBody reqBody;
    reqBody.uris = uris;

    MessageParcel data;
    if (!reqBody.Marshalling(data)) {
        MEDIA_ERR_LOG("reqBody marshalling failed");
        return E_ERR;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->CheckPhotoUrisReadPermission(data, reply);

    IPC::MediaRespVo<CheckPhotoUrisReadPermissionRespBody> respVo;
    if (!respVo.Unmarshalling(reply)) {
        MEDIA_ERR_LOG("respVo unmarshalling failed");
        return E_ERR;
    }

    stateMap = respVo.GetBody().uriPermissionStateMap;
    return respVo.GetErrCode();
}

static int32_t InsertPhotoAsset(const string &displayName, int32_t hidden, int64_t dateTrashed)
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("InsertPhotoAsset failed because g_rdbStore is null");
        return E_HAS_DB_ERROR;
    }
    string insertSql =
        SQL_INSERT_PHOTO + " VALUES (" +
        "'/storage/cloud/files/Photo/16/" + displayName + "', 175258, '" + displayName + "', '" + displayName +
        "', 1, " +
        "'com.ohos.camera', 'camera', 1501924205218, 0, 1501924205, 0, 0, " +
        to_string(dateTrashed) + ", " + to_string(hidden) + ", 1280, 960, 0, '1'" + VALUES_END;
    return g_rdbStore->ExecuteSql(insertSql);
}

static int32_t QueryPhotoIdByDisplayName(const string &displayName)
{
    vector<string> columns;
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return -1;
    }
    return GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
}

static int32_t GrantReadImageVideoPermissionForCurrentTest()
{
    vector<string> permissions = { READ_IMAGEVIDEO_PERMISSION };
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("CheckPhotoUrisReadPermissionTest", permissions, tokenId);
    if (tokenId == 0) {
        MEDIA_ERR_LOG("SetAccessTokenPermission failed for %{public}s", READ_IMAGEVIDEO_PERMISSION.c_str());
        return E_ERR;
    }
    return E_OK;
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_001
 * @tc.name      : 输入空列表返回成功且结果为空
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_001, TestSize.Level1)
{
    map<string, int32_t> stateMap;
    int32_t ret = CheckPhotoUrisReadPermission({}, stateMap);

    ASSERT_EQ(ret, E_OK);
    ASSERT_TRUE(stateMap.empty());
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_002
 * @tc.name      : 非媒体库格式URI返回格式错误状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_002, TestSize.Level1)
{
    const string invalidUri = "file://invalid/Photo/12345";
    map<string, int32_t> stateMap;
    int32_t ret = CheckPhotoUrisReadPermission({invalidUri}, stateMap);

    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[invalidUri], URI_FORMAT_ERROR_STATE);
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_003
 * @tc.name      : 资源不存在返回文件不存在状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_003, TestSize.Level1)
{
    const string notExistUri = PhotoColumn::PHOTO_URI_PREFIX + string("99999999");
    map<string, int32_t> stateMap;
    int32_t ret = CheckPhotoUrisReadPermission({notExistUri}, stateMap);

    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[notExistUri], FILE_NOT_EXIST_STATE);
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_004
 * @tc.name      : 混合输入按URI分别返回状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_004, TestSize.Level1)
{
    const string invalidUri = "invalid://uri";
    const string notExistUri = PhotoColumn::PHOTO_URI_PREFIX + string("99999998");
    map<string, int32_t> stateMap;
    int32_t ret = CheckPhotoUrisReadPermission({invalidUri, notExistUri}, stateMap);

    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 2);
    ASSERT_EQ(stateMap[invalidUri], URI_FORMAT_ERROR_STATE);
    ASSERT_EQ(stateMap[notExistUri], FILE_NOT_EXIST_STATE);
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_005
 * @tc.name      : 隐藏资源返回文件不存在状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_005, TestSize.Level1)
{
    const string hiddenDisplayName = "hidden_asset.jpg";
    int32_t ret = InsertPhotoAsset(hiddenDisplayName, 1, 0);
    ASSERT_EQ(ret, E_OK);

    int32_t fileId = QueryPhotoIdByDisplayName(hiddenDisplayName);
    GTEST_LOG_(INFO) << "QueryPhotoIdByDisplayName fileId: " << fileId;
    ASSERT_GT(fileId, 0);
    const string hiddenUri = PhotoColumn::PHOTO_URI_PREFIX + to_string(fileId);

    map<string, int32_t> stateMap;
    ret = CheckPhotoUrisReadPermission({hiddenUri}, stateMap);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[hiddenUri], FILE_NOT_EXIST_STATE);
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_006
 * @tc.name      : 回收站资源返回文件不存在状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_006, TestSize.Level1)
{
    const string trashedDisplayName = "trashed_asset.jpg";
    int32_t ret = InsertPhotoAsset(trashedDisplayName, 0, 1710000000);
    ASSERT_EQ(ret, E_OK);

    int32_t fileId = QueryPhotoIdByDisplayName(trashedDisplayName);
    GTEST_LOG_(INFO) << "QueryPhotoIdByDisplayName fileId: " << fileId;
    ASSERT_GT(fileId, 0);
    const string trashedUri = PhotoColumn::PHOTO_URI_PREFIX + to_string(fileId);

    map<string, int32_t> stateMap;
    ret = CheckPhotoUrisReadPermission({trashedUri}, stateMap);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[trashedUri], FILE_NOT_EXIST_STATE);
}

/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_007
 * @tc.name      : 可见资源未授权返回无读权限状态
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_007, TestSize.Level1)
{
    const string visibleDisplayName = "visible_no_grant.jpg";
    int32_t ret = InsertPhotoAsset(visibleDisplayName, 0, 0);
    ASSERT_EQ(ret, E_OK);

    int32_t fileId = QueryPhotoIdByDisplayName(visibleDisplayName);
    GTEST_LOG_(INFO) << "QueryPhotoIdByDisplayName fileId: " << fileId;
    ASSERT_GT(fileId, 0);
    const string visibleUri = PhotoColumn::PHOTO_URI_PREFIX + to_string(fileId);

    map<string, int32_t> stateMap;
    ret = CheckPhotoUrisReadPermission({visibleUri}, stateMap);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[visibleUri], NO_READ_PERMISSION_STATE);
}


/**
 * @tc.number    : MediaAssetsController_CheckPhotoUrisReadPermission_test_008
 * @tc.name      : 重复URI输入返回稳定状态映射
 */
HWTEST_F(CheckPhotoUrisReadPermissionTest,
    MediaAssetsController_CheckPhotoUrisReadPermission_test_008, TestSize.Level1)
{
    const string duplicateUri = PhotoColumn::PHOTO_URI_PREFIX + string("99999997");
    map<string, int32_t> stateMap;
    int32_t ret = CheckPhotoUrisReadPermission({duplicateUri, duplicateUri}, stateMap);

    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(stateMap.size(), 1);
    ASSERT_EQ(stateMap[duplicateUri], FILE_NOT_EXIST_STATE);
}
} // namespace OHOS::Media