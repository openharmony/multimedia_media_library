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

#define MLOG_TAG "PhotoAlbumUpdateDateModifiedOperationTest"

#include "photo_album_update_date_modified_operation_test.h"

#include "medialibrary_mock_tocken.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "photo_album_column.h"
#include "photo_album_update_date_modified_operation.h"

using namespace testing::ext;

namespace OHOS::Media {
using namespace OHOS::NativeRdb;
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static uint64_t g_shellToken = 0;
static MediaLibraryMockHapToken* mockToken = nullptr;

struct PhotoAlbumData {
    string albumName;
    int32_t albumType;
    int64_t dateModified;
    int64_t dateAdded;
    int32_t dirty;
    string cloudId;
};

static int32_t ClearTable(const string &table)
{
    NativeRdb::RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    MEDIA_INFO_LOG("clear table: %{public}s, rows: %{public}d, err: %{public}d", table.c_str(), rows, err);
    EXPECT_EQ(err, E_OK);
    return E_OK;
}

static int32_t InsertPhotoAlbum(const PhotoAlbumData &albumData)
{
    EXPECT_NE((g_rdbStore == nullptr), true);

    int64_t albumId = -1;
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, albumData.albumType);
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumData.albumName);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, albumData.dateModified);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, albumData.dateAdded);
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, albumData.dirty);
    values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, albumData.cloudId);
    int32_t ret = g_rdbStore->Insert(albumId, PhotoAlbumColumns::TABLE, values);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertPhotoAlbum albumId is %{public}s", to_string(albumId).c_str());
    return E_OK;
}

void PhotoAlbumUpdateDateModifiedOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE((g_rdbStore == nullptr), true);

    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);

    vector<string> perms;
    perms.push_back("ohos.permission.MANAGE_SETTINGS");
    mockToken = new MediaLibraryMockHapToken(
        "com.ohos.medialibrary.medialibrarydata", perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }
}

void PhotoAlbumUpdateDateModifiedOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearTable(PhotoAlbumColumns::TABLE);
    if (mockToken != nullptr) {
        delete mockToken;
        mockToken = nullptr;
    }
    MediaLibraryMockTokenUtils::ResetToken();
    SetSelfTokenID(g_shellToken);
    EXPECT_EQ(g_shellToken, IPCSkeleton::GetSelfTokenID());
}

void PhotoAlbumUpdateDateModifiedOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearTable(PhotoAlbumColumns::TABLE);
}

void PhotoAlbumUpdateDateModifiedOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_001 - empty database");
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_001");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_002 - date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_002");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_003 - date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_003");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_004 - album not needing fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000,
        1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_004");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_005 - album_type=1024 ignored");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_005");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_006 - dirty=4 ignored");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_006");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_007 - multiple albums need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album3", PhotoAlbumType::USER, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_007");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_008 - mixed albums");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 1234567890000,
        1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_008");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_009 - SOURCE type album need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SOURCE, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_009");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_010 - SMART type album need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SMART, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_010");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_011 - album_type=2048 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 2048, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_011");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_012 - album_type=0 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 0, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_012");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_013 - dirty=0 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_013");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_014 - dirty=1 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_014");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_015 - dirty=2 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_015");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_016 - dirty=3 need fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_016");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_017 - album_type=1024 and dirty=4");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_017");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_018 - album_type=1024, date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_018");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_019 - dirty=4, date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_019");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_020 - negative date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, -1, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_020");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_021, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_021 - large date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 9999999999999, 9999999999999, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_021");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_022, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_022 - cloud_id present");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_022");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_023, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_023 - 10 albums all need fix");
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_023");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_024, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_024 - 10 albums none need fix");
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_024");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_025, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_025 - 50 albums mixed status");
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_fix_" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_025");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_026, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_026 - album_type=1024, date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 1234567890000, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_026");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_027, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_027 - dirty=4, date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_027");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_028, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_028 - both dates = 0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_028");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_029, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_029 - Test with date_modified=0 but date_added valid");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_029");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_030, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_030 - Test with date_added=0 but date_modified valid");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_030");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_031, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_031 - Test with album_type=1024 and both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_031");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_032, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_032 - Test with dirty=4 and both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_032");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_033, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_033 - Test with different album types mixed");
    InsertPhotoAlbum(PhotoAlbumData{"user_album", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_album", PhotoAlbumType::SOURCE, 1234567890000, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_album", PhotoAlbumType::SMART, 1234567890000, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_033");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_034, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_034 - Test with dirty values mixed");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_034");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_035, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_035 - Test with dirty=4 album mixed with normal albums");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_035");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_036, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_036 - Test with album_type=1024 album mixed with normal albums");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_036");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_037, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_037 - Test with date_modified=1 (minimum non-zero)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_037");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_038, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_038 - Test with date_added=1 (minimum non-zero)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 1, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_038");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_039, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_039 - Test with very small date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 100, 200, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_039");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_040, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_040 - Test with cloud_id empty string");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_040");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_041, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_041 - Test with cloud_id non-empty string");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "test_cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_041");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_042, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_042 - Test with cloud_id and dirty=2");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_042");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_043, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_043 - Test with 100 albums all needing fix");
    for (int i = 0; i < 100; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_043");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_044, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_044 - Test with only one album needing fix out of 100");
    for (int i = 0; i < 99; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    InsertPhotoAlbum(PhotoAlbumData{"album_fix", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_044");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_045, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_045 - Test with dirty values 0,1,2,3,4,5");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 1234567890000, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_3", PhotoAlbumType::USER, 1234567890000, 1234567890000, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_5", PhotoAlbumType::USER, 0, 1234567890000, 5, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_045");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_046, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_046 - Test with album_type=1024 and various dirty values");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_0", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_1", 1024, 0, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_2", 1024, 0, 0, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_3", 1024, 0, 0, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_4", 1024, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_046");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_047, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_047 - Test with dirty=4 and various album types");
    InsertPhotoAlbum(PhotoAlbumData{"user_dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_dirty_4", PhotoAlbumType::SOURCE, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_dirty_4", PhotoAlbumType::SMART, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_0_dirty_4", 0, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_2048_dirty_4", 2048, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_047");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_048, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_048 - Test with album_type=1024 and dirty=4 both ignored");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_048");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_049, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_049 - Test with date_modified=0 and cloud_id present");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_049");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, CheckAlbumDateNeedFix_test_050, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CheckAlbumDateNeedFix_test_050 - Test with date_added=0 and cloud_id present");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool result = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End CheckAlbumDateNeedFix_test_050");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_001 - Test with empty database");
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_001");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_002 - Test fixing date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_002");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_003 - Test fixing date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_003");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_004 - Test fixing both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_004");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_005 - Test with album_type=1024");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_005");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_006 - Test with dirty=4 (should not be updated)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_006");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_007 - Test with cloud_id present " \
        "(dirty should be set to 2)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_007");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_008 - Test with cloud_id empty " \
        "(dirty should not change)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_008");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_009 - Test with multiple albums needing fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album3", PhotoAlbumType::USER, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_009");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_010 - Test with mixed albums");
    InsertPhotoAlbum(PhotoAlbumData{"album_fix", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album_ok", PhotoAlbumType::USER, 1234567890000, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_010");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_011 - Test with SOURCE type album");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SOURCE, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_011");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_012 - Test with SMART type album");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SMART, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_012");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_013 - Test with album_type=2048");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 2048, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_013");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_014 - Test with album_type=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 0, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_014");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_015 - Test with dirty=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_015");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_016 - Test with dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_016");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_017 - Test with dirty=2 and cloud_id present");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_017");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_018 - Test with dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_018");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_019 - Test with album_type=1024 and dirty=4");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_019");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_020 - Test with 10 albums all needing fix");
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_020");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_021, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_021 - Test with 50 albums mixed status");
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_fix_" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_021");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_022, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_022 - Test with cloud_id and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_022");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_023, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_023 - Test with cloud_id and date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 1, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_023");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_024, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_024 - Test with cloud_id and both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 1, "cloud_id_123"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_024");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_025, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_025 - Test with no cloud_id and dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_025");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_026, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_026 - Test with no no cloud_id and dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_026");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_027, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_027 - Test with different album types mixed");
    InsertPhotoAlbum(PhotoAlbumData{"user_album", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_album", PhotoAlbumType::SOURCE, 12345612, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_album", PhotoAlbumType::SMART, 1234567890000, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_027");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_028, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_028 - Test with dirty values mixed");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_028");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_029, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_029 - Test with dirty=4 album " \
        "mixed with normal albums");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_029");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_030, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_030 - Test with album_type=1024 " \
        "album mixed with normal albums");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_030");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_031, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_031 - Test with 100 albums all needing fix");
    for (int i = 0; i < 100; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_031");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_032, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_032 - Test with only one album " \
        "needing fix out of 100");
    for (int i = 0; i < 99; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    InsertPhotoAlbum(PhotoAlbumData{"album_fix", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_032");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_033, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_033 - Test with dirty values 0,1,2,3,4,5");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 1234567890000, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_3", PhotoAlbumType::USER, 1234567890000, 1234567890000, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_5", PhotoAlbumType::USER, 0, 1234567890000, 5, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_033");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_034, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_034 - Test with album_type=1024 " \
        "and various dirty values");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_0", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_1", 1024, 0, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_2", 1024, 0, 0, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_3", 1024, 0, 0, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_4", 1024, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_034");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_035, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_035 - Test with dirty=4 and various album types");
    InsertPhotoAlbum(PhotoAlbumData{"user_dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_dirty_4", PhotoAlbumType::SOURCE, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_dirty_4", PhotoAlbumType::SMART, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_0_dirty_4", 0, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_2048_dirty_4", 2048, 0, 0, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_035");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_036, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_036 - Test with album_type=1024 " \
        "and dirty=4 both ignored");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_036");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_037, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_037 - Test with cloud_id and dirty=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_037");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_038, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_038 - Test with cloud_id and dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_038");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_039, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_039 - Test with cloud_id and dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_039");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_040, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_040 - Test with cloud_id and dirty=4");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, "cloud_id"});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_040");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_041, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_041 - Test with valid dates (no fix needed)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_041");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_042, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_042 - date_modified ok, date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_042");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_043, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_043 - Test with date_added valid but date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_043");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_044, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_044 - Test with album_type=1024 and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_044");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_045, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_045 - Test with dirty=4 and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 4, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_045");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_046, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_046 - Test with both date_modified and date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_046");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_047, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_047 - Test with multiple operations");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult1 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult1);
    
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    bool checkResult2 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(checkResult2);
    
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult3 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult3);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_047");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_048, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_048 - Test with large date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 9999999999999, 9999999999999, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_048");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_049, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_049 - Test with small date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1, 1, 0, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_049");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_shared_ptr_test_050, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_shared_ptr_test_050 - Test with cloud_id empty and dirty=2");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, ""});
    PhotoAlbumUpdateDateModifiedOperation operation;
    operation.UpdateAlbumDateNeedFix(g_rdbStore);
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_shared_ptr_test_050");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_001 - Test with empty database");
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_001");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_002 - Test fixing date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_002");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_003 - Test fixing date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_003");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_004 - Test fixing both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_004");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_005 - Test with album_type=1024 " \
        "(should not be updated)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_005");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_006 - Test with dirty=4 (should not be updated)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_006");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_007 - Test with cloud_id present " \
        "(dirty should be set to 2)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id_123"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_007");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_008 - Test with cloud_id empty " \
        "(dirty should not change)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_008");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_009 - Test with multiple albums needing fix");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album3", PhotoAlbumType::USER, 0, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_009");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_010 - Test with mixed albums");
    InsertPhotoAlbum(PhotoAlbumData{"album_fix", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album_ok", PhotoAlbumType::USER, 1234567890000, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_010");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_011 - Test with SOURCE type album");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SOURCE, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_011");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_012 - Test with SMART type album");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::SMART, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_012");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_013 - Test with album_type=2048");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 2048, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_013");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_014 - Test with album_type=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 0, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_014");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_015 - Test with dirty=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_015");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_016 - Test with dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_016");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_017 - Test with dirty=2 and cloud_id present");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, "cloud_id"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_017");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_018 - Test with dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_018");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_019 - Test with album_type=1024 and dirty=4");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_019");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_020 - Test with 10 albums all needing fix");
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_020");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_021, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_021 - Test with 50 albums mixed status");
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_fix_" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    for (int i = 0; i < 25; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_021");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_022, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_022 - Test with cloud_id and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, "cloud_id_123"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_022");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_023, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_023 - Test with cloud_id and date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 1, "cloud_id_123"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_023");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_024, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_024 - Test with cloud_id and both dates=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 1, "cloud_id_123"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_024");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_025, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_025 - Test with no cloud_id and dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_025");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_026, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_026 - Test with no cloud_id and dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_026");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_027, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_027 - Test with different album types mixed");
    InsertPhotoAlbum(PhotoAlbumData{"user_album", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_album", PhotoAlbumType::SOURCE, 1234567890000, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_album", PhotoAlbumType::SMART, 1234567890000, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_027");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_028, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_028 - Test with dirty values mixed");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_028");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_029, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_029 - dirty=4 album mixed with normal");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_029");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_030, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_030 - Test with album_type=1024 " \
        "album mixed with normal albums");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"normal", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_030");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_031, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_031 - Test with 100 albums all needing fix");
    for (int i = 0; i < 100; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album" + to_string(i), PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    }
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_031");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_032, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_032 - Test with only one album needing fix out of 100");
    for (int i = 0; i < 99; i++) {
        InsertPhotoAlbum(PhotoAlbumData{"album_ok_" + to_string(i), PhotoAlbumType::USER, 1234567890000,
            1234567890000, 0, ""});
    }
    InsertPhotoAlbum(PhotoAlbumData{"album_fix", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_032");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_033, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_033 - Test with dirty values 0,1,2,3,4,5");
    InsertPhotoAlbum(PhotoAlbumData{"dirty_0", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_1", PhotoAlbumType::USER, 1234567890000, 1234567890000, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_2", PhotoAlbumType::USER, 1234567890000, 1234567890000, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_3", PhotoAlbumType::USER, 1234567890000, 1234567890000, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"dirty_5", PhotoAlbumType::USER, 0, 1234567890000, 5, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_033");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_034, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_034 - Test with album_type=1024 " \
        "and various dirty values");
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_0", 1024, 0, 0, 0, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_1", 1024, 0, 0, 1, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_2", 1024, 0, 0, 2, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_3", 1024, 0, 0, 3, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_1024_dirty_4", 1024, 0, 0, 4, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_034");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_035, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_035 - Test with dirty=4 and various album types");
    InsertPhotoAlbum(PhotoAlbumData{"user_dirty_4", PhotoAlbumType::USER, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"source_dirty_4", PhotoAlbumType::SOURCE, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"smart_dirty_4", PhotoAlbumType::SMART, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_0_dirty_4", 0, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"type_2048_dirty_4", 2048, 0, 0, 4, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_035");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_036, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_036 - Test with album_type=1024 " \
        "and dirty=4 both ignored");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 0, 4, ""});
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_036");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_037, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_037 - Test with cloud_id and dirty=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, "cloud_id"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_037");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_038, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_038 - Test with cloud_id and dirty=1");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 1, "cloud_id"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_038");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_039, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_039 - Test with cloud_id and dirty=3");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 3, "cloud_id"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_039");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_040, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_040 - Test with cloud_id and dirty=4");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 4, "cloud_id"});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_040");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_041, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_041 - Test with valid dates (no fix needed)");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_041");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_042, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_042 - Test with date_modified valid but date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1234567890000, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_042");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_043, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_043 - Test with date_added valid but date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_043");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_044, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_044 - Test with album_type=1024 and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", 1024, 0, 1234567890000, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_044");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_045, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_045 - Test with dirty=4 and date_modified=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 4, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_045");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_046, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_046 - Test with both date_modified and date_added=0");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 0, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_046");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_047, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_047 - Test with multiple operations");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    int32_t result1 = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result1, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult1 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult1);
    
    InsertPhotoAlbum(PhotoAlbumData{"album2", PhotoAlbumType::USER, 0, 1234567890000, 0, ""});
    bool checkResult2 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_TRUE(checkResult2);
    
    int32_t result2 = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result2, NativeRdb::E_OK);
    bool checkResult3 = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult3);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_047");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_048, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_048 - Test with large date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 9999999999999, 9999999999999, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_048");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_049, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_049 - Test with small date values");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 1, 1, 0, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_049");
}

HWTEST_F(PhotoAlbumUpdateDateModifiedOperationTest, UpdateAlbumDateNeedFix_rdbstore_test_050, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start UpdateAlbumDateNeedFix_rdbstore_test_050 - Test with cloud_id empty and dirty=2");
    InsertPhotoAlbum(PhotoAlbumData{"album1", PhotoAlbumType::USER, 0, 1234567890000, 2, ""});
    int32_t result = PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(*MediaLibraryRdbStore::GetRaw());
    EXPECT_EQ(result, NativeRdb::E_OK);
    PhotoAlbumUpdateDateModifiedOperation operation;
    bool checkResult = operation.CheckAlbumDateNeedFix(g_rdbStore);
    EXPECT_FALSE(checkResult);
    MEDIA_INFO_LOG("End UpdateAlbumDateNeedFix_rdbstore_test_050");
}

}  // namespace OHOS::Media