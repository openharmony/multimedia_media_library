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
 
#define MLOG_TAG "PersistPermissionTest"
 
#include "persist_permission_test.h"
 
#include <string>
#include <vector>
 
#include "media_assets_controller_service.h"
 
#include "grant_photo_uri_permission_inner_vo.h"
#include "check_photo_uri_permission_inner_vo.h"
#include "get_photo_uri_persist_permission_vo.h"
#include "cancel_photo_uri_persist_permission_vo.h"
#include "create_asset_vo.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "ipc_skeleton.h"
 
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
 
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "result_set_utils.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_column.h"
#include "media_log.h"
 
namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
 
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;
 
static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear table %{public}s, err: %{public}d", table.c_str(), err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}
 
void PersistPermissionTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start PersistPermissionTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}
 
void PersistPermissionTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}
 
void PersistPermissionTest::SetUp()
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}
 
void PersistPermissionTest::TearDown(void) {}
 
static std::string CreatePhotoAsset(const string &displayName)
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.displayName = displayName;
 
    MessageParcel data;
    EXPECT_TRUE(reqBody.Marshalling(data));
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->SystemCreateAsset(data, reply);
    IPC::MediaRespVo<CreateAssetRespBody> respVo;
    EXPECT_TRUE(respVo.Unmarshalling(reply));
    EXPECT_EQ(respVo.GetErrCode(), 0);
    return respVo.GetBody().outUri;
}
 
static int32_t GrantPersistPermissionInner(const std::string &fileId,
    int32_t permissionType, int32_t uriType = 1)
{
    GrantUrisPermissionInnerReqBody reqBody;
    reqBody.tokenId = IPCSkeleton::GetCallingTokenID();
    reqBody.srcTokenId = IPCSkeleton::GetCallingTokenID();
    reqBody.fileIds = { fileId };
    reqBody.permissionTypes = { permissionType };
    reqBody.hideSensitiveType = 0;
    reqBody.uriTypes = { uriType };
 
    MessageParcel data;
    EXPECT_TRUE(reqBody.Marshalling(data));
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GrantPhotoUriPermissionInner(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    EXPECT_TRUE(respVo.Unmarshalling(reply));
    return respVo.GetErrCode();
}
 
static int32_t GrantPermissionForToken(const std::string &fileId,
    uint32_t targetTokenId, int32_t permissionType, int32_t uriType = 1)
{
    GrantUrisPermissionInnerReqBody reqBody;
    reqBody.tokenId = static_cast<int64_t>(targetTokenId);
    reqBody.srcTokenId = IPCSkeleton::GetCallingTokenID();
    reqBody.fileIds = { fileId };
    reqBody.permissionTypes = { permissionType };
    reqBody.hideSensitiveType = 0;
    reqBody.uriTypes = { uriType };
 
    MessageParcel data;
    EXPECT_TRUE(reqBody.Marshalling(data));
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GrantPhotoUriPermissionInner(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    EXPECT_TRUE(respVo.Unmarshalling(reply));
    return respVo.GetErrCode();
}
 
static int32_t CountDbPermissionsByType(uint32_t tokenId, int32_t permissionType)
{
    RdbPredicates predicates(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, static_cast<int64_t>(tokenId));
    predicates.EqualTo(AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    std::vector<std::string> columns = { AppUriPermissionColumn::ID };
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr) {
        return -1;
    }
    int32_t count = 0;
    resultSet->GetRowCount(count);
    return count;
}
 
static int32_t QueryPersistPermission(uint32_t tokenId, std::vector<int32_t> &outPermTypes)
{
    GetPhotoUriPersistPermissionReqBody reqBody;
    reqBody.tokenId = static_cast<int64_t>(tokenId);
    MessageParcel data;
    EXPECT_TRUE(reqBody.Marshalling(data));
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->GetPhotoUriPersistPermission(data, reply);
    IPC::MediaRespVo<GetPhotoUriPersistPermissionRespBody> respVo;
    EXPECT_TRUE(respVo.Unmarshalling(reply));
    outPermTypes = respVo.GetBody().permissionTypes;
    return respVo.GetErrCode();
}
 
static int32_t CancelPersistPermission(uint32_t tokenId)
{
    CancelPhotoUriPersistPermissionReqBody reqBody;
    reqBody.tokenId = static_cast<int64_t>(tokenId);
    MessageParcel data;
    EXPECT_TRUE(reqBody.Marshalling(data));
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->CancelPhotoUriPersistPermission(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    EXPECT_TRUE(respVo.Unmarshalling(reply));
    return respVo.GetErrCode();
}
 
/*
 * Acceptance scenario 1: App uses persistPermission interface to get persistent permission.
 * After revoking, the permission should no longer exist.
 * PhotoPermissionType::PERSIST_READ_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Revoke_PersistInterface_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_001 start");
    string uri = CreatePhotoAsset("persist_test_001.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(permTypes.empty());
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    permTypes.clear();
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_001 end");
}
 
/*
 * Acceptance scenario 2: App uses persistPermission interface to get persistent permission.
 * After revoking, the permission should no longer exist.
 * PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Revoke_PersistInterface_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_002 start");
    string uri = CreatePhotoAsset("persist_test_002.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(permTypes.empty());
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    permTypes.clear();
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_002 end");
}
 
/*
 * Acceptance scenario 3: App uses persistPermission interface to get persistent permission.
 * After revoking, the permission should no longer exist.
 * PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Revoke_PersistInterface_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_003 start");
    string uri = CreatePhotoAsset("persist_test_003.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    permTypes.clear();
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Revoke_PersistInterface_003 end");
}
 
/*
 * Acceptance scenario 4: PhotoPicker selects image → persistent read is granted.
 * After user cancels persistent authorization, permission query returns empty.
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Revoke_PhotoPicker_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Revoke_PhotoPicker_004 start");
    string uri = CreatePhotoAsset("persist_test_004.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
    bool hasRead = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)) != permTypes.end();
    EXPECT_TRUE(hasRead);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    permTypes.clear();
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Revoke_PhotoPicker_004 end");
}
 
/*
 * Acceptance scenario 5: App saves image → persistent read+write granted.
 * After revoking, both read and write persistent permissions should be gone.
 * Also verifies PERSIST_READWRITE_IMAGEVIDEO is synthesized when both read and write exist.
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Revoke_ReadWrite_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Revoke_ReadWrite_005 start");
    string uri = CreatePhotoAsset("persist_test_005.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(permTypes.size(), static_cast<size_t>(2));
    bool hasRead = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)) != permTypes.end();
    bool hasWrite = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO)) != permTypes.end();
    bool hasReadWrite = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO)) != permTypes.end();
    EXPECT_TRUE(hasRead);
    EXPECT_TRUE(hasWrite);
    EXPECT_TRUE(hasReadWrite);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    permTypes.clear();
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Revoke_ReadWrite_005 end");
}
 
/*
 * Edge case: Cancel persist permission for a tokenId with no persistent permissions.
 * Should succeed without error.
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Cancel_Empty_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Cancel_Empty_006 start");
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
 
    int32_t ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Cancel_Empty_006 end");
}
 
/*
 * Edge case: Query persist permission for a tokenId with no permissions.
 * Should return empty list.
 */
HWTEST_F(PersistPermissionTest, PersistPermission_Query_Empty_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_Query_Empty_007 start");
    uint32_t tokenId = 99999;
    std::vector<int32_t> permTypes;
    int32_t ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
    MEDIA_INFO_LOG("PersistPermission_Query_Empty_007 end");
}
 
/*
 * Critical: Cancel must NOT delete temporary permissions.
 * Grants both temporary and persistent permissions, cancels, then verifies
 * temporary permission still exists in the database.
 * PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TemporaryNotAffected_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_008 start");
    string uri = CreatePhotoAsset("persist_test_008.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    int32_t tempCountBefore = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
    EXPECT_GT(tempCountBefore, 0);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
 
    int32_t tempCountAfter = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
    EXPECT_EQ(tempCountAfter, tempCountBefore);
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_008 end");
}
 
/*
 * Critical: Cancel must NOT delete temporary permissions.
 * Grants both temporary and persistent permissions, cancels, then verifies
 * temporary permission still exists in the database.
 * PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TemporaryNotAffected_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_009 start");
    string uri = CreatePhotoAsset("persist_test_009.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    int32_t tempCountBefore = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    EXPECT_GT(tempCountBefore, 0);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
 
    int32_t tempCountAfter = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    EXPECT_EQ(tempCountAfter, tempCountBefore);
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_009 end");
}
 
/*
 * Critical: Cancel must NOT delete temporary permissions.
 * Grants both temporary and persistent permissions, cancels, then verifies
 * temporary permission still exists in the database.
 * PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TemporaryNotAffected_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_010 start");
    string uri = CreatePhotoAsset("persist_test_010.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    int32_t tempCountBefore = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO));
    EXPECT_GT(tempCountBefore, 0);
 
    ret = CancelPersistPermission(tokenId);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypes.empty());
 
    int32_t tempCountAfter = CountDbPermissionsByType(tokenId,
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(tempCountAfter, tempCountBefore);
    MEDIA_INFO_LOG("PersistPermission_TemporaryNotAffected_010 end");
}
 
/*
 * Isolation: Canceling permissions for tokenId A must not affect tokenId B.
 * PhotoPermissionType::PERSIST_READ_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TokenIdIsolation_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_011 start");
    string uri = CreatePhotoAsset("persist_test_011.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    uint32_t tokenIdA = IPCSkeleton::GetCallingTokenID();
    uint32_t tokenIdB = tokenIdA + 1;
 
    int32_t ret = GrantPermissionForToken(fileId, tokenIdA,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPermissionForToken(fileId, tokenIdB,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesB;
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
 
    ret = CancelPersistPermission(tokenIdA);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesA;
    ret = QueryPersistPermission(tokenIdA, permTypesA);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypesA.empty());
 
    permTypesB.clear();
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_011 end");
}
 
/*
 * Isolation: Canceling permissions for tokenId A must not affect tokenId B.
 * PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TokenIdIsolation_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_012 start");
    string uri = CreatePhotoAsset("persist_test_012.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    uint32_t tokenIdA = IPCSkeleton::GetCallingTokenID();
    uint32_t tokenIdB = tokenIdA + 1;
 
    int32_t ret = GrantPermissionForToken(fileId, tokenIdA,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPermissionForToken(fileId, tokenIdB,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesB;
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
 
    ret = CancelPersistPermission(tokenIdA);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesA;
    ret = QueryPersistPermission(tokenIdA, permTypesA);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypesA.empty());
 
    permTypesB.clear();
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_012 end");
}
 
/*
 * Isolation: Canceling permissions for tokenId A must not affect tokenId B.
 * PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO
 */
HWTEST_F(PersistPermissionTest, PersistPermission_TokenIdIsolation_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_013 start");
    string uri = CreatePhotoAsset("persist_test_013.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
 
    uint32_t tokenIdA = IPCSkeleton::GetCallingTokenID();
    uint32_t tokenIdB = tokenIdA + 1;
 
    int32_t ret = GrantPermissionForToken(fileId, tokenIdA,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    ret = GrantPermissionForToken(fileId, tokenIdB,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesB;
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
 
    ret = CancelPersistPermission(tokenIdA);
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypesA;
    ret = QueryPersistPermission(tokenIdA, permTypesA);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(permTypesA.empty());
 
    permTypesB.clear();
    ret = QueryPersistPermission(tokenIdB, permTypesB);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("PersistPermission_TokenIdIsolation_013 end");
}
 
/*
 * Query with only PERSIST_WRITE: Verify PERSIST_WRITE is returned
 * and PERSIST_READ is NOT present when only write was granted.
 */
HWTEST_F(PersistPermissionTest, PersistPermission_WriteOnly_014, TestSize.Level1)
{
    MEDIA_INFO_LOG("PersistPermission_WriteOnly_014 start");
    string uri = CreatePhotoAsset("persist_test_014.jpg");
    ASSERT_FALSE(uri.empty());
    string fileId = MediaFileUtils::GetIdFromUri(uri);
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
 
    int32_t ret = GrantPersistPermissionInner(fileId,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
 
    std::vector<int32_t> permTypes;
    ret = QueryPersistPermission(tokenId, permTypes);
    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(permTypes.empty());
 
    bool hasWrite = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO)) != permTypes.end();
    bool hasRead = std::find(permTypes.begin(), permTypes.end(),
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)) != permTypes.end();
    EXPECT_TRUE(hasWrite);
    EXPECT_FALSE(hasRead);
    MEDIA_INFO_LOG("PersistPermission_WriteOnly_014 end");
}
 
} // namespace OHOS::Media