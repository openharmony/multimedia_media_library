/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "CloudPermissionTest"

#include "cloud_permission_test.h"

#include <unordered_map>

#include "media_column.h"
#include "media_cloud_permission_check.h"
#include "media_log.h"
#include "media_permission_header_req.h"
#include "media_permission_policy_type.h"
#include "medialibrary_errno.h"
#include "medialibrary_mock_tocken.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"
#include "media_file_uri.h"
#include "media_upgrade.h"
#include "permission_utils.h"
#include "photo_album_column.h"
#include "userfile_manager_types.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "ipc_skeleton.h"
#include "rdb_utils.h"
#include "uri.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

constexpr int64_t TEST_TIMESTAMP = 1752000000000;
constexpr int32_t TEST_URI_TYPE = 1;
constexpr int32_t TEST_USER_ID = 100;
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::shared_ptr<MediaLibraryMockHapToken> g_hapToken;
static uint64_t g_shellToken = 0;
static constexpr int32_t SLEEP_SECONDS = 1;

static std::vector<std::string> createTableSqlLists = {
    PhotoAlbumColumns::CREATE_TABLE,
    PhotoUpgrade::CREATE_PHOTO_TABLE,
};

static std::vector<std::string> testTables = {
    PhotoAlbumColumns::TABLE,
    PhotoColumn::PHOTOS_TABLE,
};

void CloudPermissionTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(g_rdbStore, createTableSqlLists);

    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.MEDIA_LOCATION");
    perms.push_back("ohos.permission.READ_AUDIO");
    perms.push_back("ohos.permission.WRITE_AUDIO");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    g_hapToken = std::make_shared<MediaLibraryMockHapToken>("com.ohos.medialibrary.medialibrarydata", perms);
}

void CloudPermissionTest::TearDownTestCase(void)
{
    MEDIA_ERR_LOG("TearDownTestCase start");
    MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    g_hapToken = nullptr;
    MediaLibraryMockTokenUtils::ResetToken();
    SetSelfTokenID(g_shellToken);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase end");
}

void CloudPermissionTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables);
}
void CloudPermissionTest::TearDown(void)
{}

void CloudPermissionTest::MockPermission(const std::vector<std::string> &perms)
{
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    for (const auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(tokenId, perm, 0);
    }
}

void CloudPermissionTest::SetPermissionWithReadImageVideo()
{
    MockPermission({"ohos.permission.READ_IMAGEVIDEO"});
}

void CloudPermissionTest::SetPermissionWithReadCloudImageVideo()
{
    MockPermission({"ohos.permission.READ_CLOUD_IMAGEVIDEO"});
}

void CloudPermissionTest::SetPermissionWithBoth()
{
    MockPermission({"ohos.permission.READ_IMAGEVIDEO", "ohos.permission.READ_CLOUD_IMAGEVIDEO"});
}

void CloudPermissionTest::SetPermissionWithoutAny()
{
    MockPermission({});
}

int64_t CloudPermissionTest::InsertAssetWithPosition(PhotoPositionType position)
{
    if (g_rdbStore == nullptr) {
        return -1;
    }

    int32_t pos = static_cast<int32_t>(position);
    std::string title = "IMG_POS_" + std::to_string(pos);
    std::string displayName = title + ".jpg";
    std::string filePath = "/storage/cloud/files/photo/" + std::to_string(pos) + "/" + title + ".jpg";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, filePath);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, TEST_TIMESTAMP);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, TEST_TIMESTAMP);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    valuesBucket.PutInt(PhotoColumn::PHOTO_IS_TEMP, 0);
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, pos);

    int64_t fileId = -1;
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Insert asset failed, ret=%{public}d", ret);
        return -1;
    }
    return fileId;
}

static PermissionHeaderReq BuildPermissionHeaderReq(int64_t fileId)
{
    std::unordered_map<std::string, std::string> headerMap;
    headerMap[PermissionHeaderReq::FILE_ID_KEY] = std::to_string(fileId);
    headerMap[PermissionHeaderReq::URI_TYPE_KEY] = std::to_string(TEST_URI_TYPE);
    std::vector<std::vector<PermissionType>> permissionPolicy;
    return PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, TEST_USER_ID, permissionPolicy, false);
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_Local_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadImageVideo();
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(std::to_string(fileId));
    EXPECT_EQ(result, E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_Cloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadCloudImageVideo();
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(std::to_string(fileId));
    EXPECT_NE(result, E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_LocalAndCloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL_AND_CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithBoth();
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(std::to_string(fileId));
    EXPECT_EQ(result, E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_Local_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadCloudImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_NE(checker.CheckPermission(0, data), E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_Cloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadCloudImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_NE(checker.CheckPermission(0, data), E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_LocalAndCloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL_AND_CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadCloudImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_NE(checker.CheckPermission(0, data), E_SUCCESS);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_Local_002, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_Cloud_002, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_LocalAndCloud_002, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL_AND_CLOUD);
    ASSERT_GE(fileId, 0);

    SetPermissionWithReadImageVideo();
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}

HWTEST_F(CloudPermissionTest, CloudWritePermissionCheck_CheckPermission_Local_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL);
    ASSERT_GE(fileId, 0);

    CloudWritePermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}

HWTEST_F(CloudPermissionTest, CloudWritePermissionCheck_CheckPermission_Cloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::CLOUD);
    ASSERT_GE(fileId, 0);

    CloudWritePermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}

HWTEST_F(CloudPermissionTest, CloudWritePermissionCheck_CheckPermission_LocalAndCloud_001, TestSize.Level1)
{
    int64_t fileId = InsertAssetWithPosition(PhotoPositionType::LOCAL_AND_CLOUD);
    ASSERT_GE(fileId, 0);

    CloudWritePermissionCheck checker;
    PermissionHeaderReq data = BuildPermissionHeaderReq(fileId);
    EXPECT_EQ(checker.CheckPermission(0, data), E_PERMISSION_DENIED);
}
}  // namespace Media
}  // namespace OHOS