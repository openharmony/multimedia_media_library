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

#define MLOG_TAG "PhotoAlbumUploadStatusOperationTest"

#include "photo_album_upload_status_operation_test.h"

#include "medialibrary_mock_tocken.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "photo_album_column.h"
#include "photo_album_upload_status_operation.h"
#include "settings_data_manager.h"

using namespace testing::ext;

namespace OHOS::Media {
using namespace OHOS::NativeRdb;
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_THREE_SECONDS = 3;
static uint64_t g_shellToken = 0;
static MediaLibraryMockHapToken* mockToken = nullptr;
const std::string ABILITY_ENABLE_XML = "/data/storage/el2/base/preferences/ability_enable.xml";
const std::string HISTORY_UPLOAD_ALBUM_ENABLE = "history_upload_album_enable";

static int32_t ClearTable(const string &table)
{
    NativeRdb::RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    MEDIA_INFO_LOG("clear table: %{public}s, rows: %{public}d, err: %{public}d", table.c_str(), rows, err);
    EXPECT_EQ(err, E_OK);
    return E_OK;
}

static int32_t InsertPhotoAlbum(const string &albumName, const int32_t albumType, const int32_t uploadStatus)
{
    EXPECT_NE((g_rdbStore == nullptr), true);

    int64_t albumId = -1;
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, albumType);
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    values.PutInt(PhotoAlbumColumns::UPLOAD_STATUS, uploadStatus);
    int32_t ret = g_rdbStore->Insert(albumId, PhotoAlbumColumns::TABLE, values);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertPhotoAlbum albumId is %{public}s", to_string(albumId).c_str());
    return E_OK;
}

static int32_t GetHistoryUploadAlbumEnable()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(ABILITY_ENABLE_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, E_ERR, "Get preferences error: %{public}d", errCode);
    int32_t historyEnable = prefs->GetInt(HISTORY_UPLOAD_ALBUM_ENABLE, -1);
    return historyEnable;
}

static int32_t SetHistoryUploadAlbumEnable(const int32_t historyEnable)
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(ABILITY_ENABLE_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, E_ERR, "Get preferences error: %{public}d", errCode);
    prefs->PutInt(HISTORY_UPLOAD_ALBUM_ENABLE, historyEnable);
    prefs->FlushSync();
    return E_OK;
}

void PhotoAlbumUploadStatusOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE((g_rdbStore == nullptr), true);

    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);

    vector<string> perms;
    perms.push_back("ohos.permission.MANAGE_SETTINGS");
    // mock  tokenID
    mockToken = new MediaLibraryMockHapToken("com.ohos.medialibrary.medialibrarydata", perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }
}

void PhotoAlbumUploadStatusOperationTest::TearDownTestCase(void)
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
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_THREE_SECONDS));
}

void PhotoAlbumUploadStatusOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearTable(PhotoAlbumColumns::TABLE);
}

void PhotoAlbumUploadStatusOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_001, TestSize.Level0)
{
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    InsertPhotoAlbum("album1", PhotoAlbumType::SOURCE, 0);
    result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_002, TestSize.Level0)
{
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(PhotoAlbumColumns::LPATH_CAMERA);
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(PhotoAlbumColumns::LPATH_SCREENSHOT);
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(PhotoAlbumColumns::LPATH_SCREENRECORD);
    EXPECT_EQ(result, 1);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Users/album1");
    EXPECT_GE(result, 0);
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_003, TestSize.Level0)
{
    bool isSupport = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();

    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::DEFAULT);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    int32_t enableResult = GetHistoryUploadAlbumEnable();
    int32_t expectResult = isSupport ? static_cast<int32_t>(EnableUploadStatus::DEFAULT) :
        static_cast<int32_t>(EnableUploadStatus::OFF);
    EXPECT_EQ(enableResult, expectResult);

    historyEnable = static_cast<int32_t>(EnableUploadStatus::ON);
    SetHistoryUploadAlbumEnable(historyEnable);
    ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    enableResult = GetHistoryUploadAlbumEnable();
    EXPECT_EQ(enableResult, static_cast<int32_t>(EnableUploadStatus::ON));

    historyEnable = static_cast<int32_t>(EnableUploadStatus::OFF);
    SetHistoryUploadAlbumEnable(historyEnable);
    ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    enableResult = GetHistoryUploadAlbumEnable();
    expectResult = isSupport ? static_cast<int32_t>(EnableUploadStatus::ON) :
        static_cast<int32_t>(EnableUploadStatus::OFF);
    EXPECT_EQ(enableResult, expectResult);
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_004 - Test GetAlbumUploadStatus with empty DB");
    ClearTable(PhotoAlbumColumns::TABLE);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_004");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_005 - Test GetAlbumUploadStatus with multiple albums");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album3", PhotoAlbumType::SOURCE, 1);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_005");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_006 - Test GetAlbumUploadStatus with mixed upload status");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    InsertPhotoAlbum("album3", PhotoAlbumType::SOURCE, 1);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_EQ(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_006");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_007 - "
        "Test GetAlbumUploadStatusWithLpath with different paths");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera");
    EXPECT_GE(result, 0);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots");
    EXPECT_GE(result, 0);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecords");
    EXPECT_GE(result, 0);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Custom");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_007");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_008 - "
        "Test GetAlbumUploadStatusWithLpath case insensitive");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/CAMERA");
    EXPECT_EQ(result, 1);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENSHOTS");
    EXPECT_EQ(result, 1);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENRECORDS");
    EXPECT_EQ(result, 1);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/dcim/camera");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_008");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_009 - Test GetAlbumUploadStatusWithLpath with mixed case");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DcIm/CaMeRa");
    EXPECT_EQ(result, 1);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PiCtUrEs/ScReEnShOtS");
    EXPECT_EQ(result, 1);
    
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PiCtUrEs/ScrEEnRecOrDs");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_009");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_010 - Test IsAllAlbumUploadOnInDb with no albums");
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_010");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_011 - "
        "Test IsAllAlbumUploadOnInDb with one album upload on");
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_011");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_012 - "
        "Test IsAllAlbumUploadOnInDb with all albums upload on");
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album3", PhotoAlbumType::SOURCE, 1);
    InsertPhotoAlbum("album4", PhotoAlbumType::SOURCE, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_012");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_013 - "
        "Test IsAllAlbumUploadOnInDb with one album upload off");
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_013");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_014 - "
        "Test IsAllAlbumUploadOnInDb with different album types");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::SOURCE, 1);
    InsertPhotoAlbum("album3", PhotoAlbumType::SMART, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_014");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_015 - Test IsSupportUploadStatus basic");
    bool isSupport = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    EXPECT_TRUE(isSupport);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_015");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_016 - Test JudgeUploadAlbumEnable with DEFAULT status");
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::DEFAULT);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_016");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_017 - Test JudgeUploadAlbumEnable with OFF status");
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::OFF);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_017");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_018 - Test JudgeUploadAlbumEnable with ON status");
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::ON);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_018");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_019 - Test GetAlbumUploadStatusWithLpath with empty path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_019");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_020 - "
        "Test GetAlbumUploadStatusWithLpath with random path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Random/Path/Album");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Photos/MyPictures");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Images");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_020");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_021, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_021 - "
        "Test GetAlbumUploadStatusWithLpath with similar paths");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera123");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera_001");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots_2024");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_021");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_022, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_022 - "
        "Test IsAllAlbumUploadOnInDb with multiple album types");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album_user", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album_source", PhotoAlbumType::SOURCE, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_022");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_023, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_023 - Test IsAllAlbumUploadOnInDb with all upload off");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_023");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_024, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_024 - Test GetAlbumUploadStatus multiple calls");
    int32_t status1 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    int32_t status2 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    int32_t status3 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status1, 0);
    EXPECT_GE(status2, 0);
    EXPECT_GE(status3, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_024");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_025, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_025 - Test IsSupportUploadStatus multiple calls");
    bool isSupport1 = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    bool isSupport2 = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    bool isSupport3 = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    EXPECT_TRUE(isSupport1 == isSupport2);
    EXPECT_TRUE(isSupport2 == isSupport3);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_025");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_026, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_026 - Test JudgeUploadAlbumEnable multiple scenarios");
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::DEFAULT);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    historyEnable = static_cast<int32_t>(EnableUploadStatus::ON);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    historyEnable = static_cast<int32_t>(EnableUploadStatus::OFF);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_026");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_027, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_027 - "
        "Test GetAlbumUploadStatusWithLpath with path variations");
    std::vector<std::string> paths = {
        "/DCIM",
        "/DCIM/",
        "/Pictures",
        "/Pictures/",
        "/Videos",
        "/Videos/"
    };
    
    for (const auto& path : paths) {
        int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(path);
        EXPECT_GE(result, 0);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_027");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_028, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_028 - Test IsAllAlbumUploadOnInDb after multiple inserts");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum("album" + to_string(i), PhotoAlbumType::USER, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_028");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_029, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_029 - Test IsAllAlbumUploadOnInDb with partial upload on");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album3", PhotoAlbumType::USER, 0);
    InsertPhotoAlbum("album4", PhotoAlbumType::USER, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_029");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_030, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_030 - "
        "Test GetAlbumUploadStatus with album type 2048");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", 2048, 1);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_030");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_031, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_031 - "
        "Test GetAlbumUploadStatusWithLpath special chars in path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera%20Photos");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screen#Shot");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/Movie-Test");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_031");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_032, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_032 - Test GetAlbumUploadStatusWithLpath unicode path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/相机");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/图片/截图");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/视频/屏幕录制");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_032");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_033, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_033 - Test IsAllAlbumUploadOnInDb with dirty albums");
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_033");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_034, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_034 - Test JudgeUploadAlbumEnable toggle scenario");
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::DEFAULT);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    
    int32_t currentEnable = GetHistoryUploadAlbumEnable();
    MEDIA_INFO_LOG("Current enable status: %{public}d", currentEnable);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_034");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_035, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_035 - Test GetAlbumUploadStatus after enable in db");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    
    int32_t historyEnable = static_cast<int32_t>(EnableUploadStatus::OFF);
    SetHistoryUploadAlbumEnable(historyEnable);
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_035");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_036, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_036 - Test GetAlbumUploadStatusWithLpath with long path");
    std::string longPath = "/";
    for (int i = 0; i < 20; i++) {
        longPath += "verylongfoldername/";
    }
    longPath += "album";
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(longPath);
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_036");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_037, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_037 - Test IsSupportUploadStatus consecutive calls");
    for (int i = 0; i < 5; i++) {
        bool isSupport = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
        EXPECT_TRUE(isSupport);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_037");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_038, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_038 - Test IsAllAlbumUploadOnInDb sequential with clear");
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result1 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result1);
    
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    bool result2 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result2);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result3 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result3);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_038");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_039, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_039 - Test GetAlbumUploadStatusWithLpath numerical path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/123/456");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/0/1");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/999/888");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_039");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_040, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_040 - Test JudgeUploadAlbumEnable state transitions");
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::ON));
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_040");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_041, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_041 - Test GetAlbumUploadStatusWithLpath root path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_041");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_042, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_042 - "
        "Test IsAllAlbumUploadOnInDb with upload status 2");
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 2);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_042");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_043, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_043 - "
        "Test GetAlbumUploadStatusWithLpath uppercase special");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/CAMERA");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENSHOTS");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENRECORDS");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_043");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_044, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_044 - Test GetAlbumUploadStatus with various album types");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album_type_0", 0, 1);
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album_type_2048", 2048, 1);
    status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_044");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_045, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_045 - "
        "Test GetAlbumUploadStatusWithLpath path with numbers");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera1");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera2024");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshot001");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_045");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_046, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_046 - "
        "Test IsAllAlbumUploadOnInDb with negative upload status");
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, -1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_046");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_047, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_047 - "
        "Test GetAlbumUploadStatusWithLpath space variations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/ Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera ");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(" /DCIM/Camera");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_047");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_048, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_048 - Test GetAlbumUploadStatusWithLpath partial match");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Screenshot");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/ScreenRecord");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_048");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_049, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_049 - "
        "Test JudgeUploadAlbumEnable consecutive different states");
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::ON));
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_049");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_050, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_050 - "
        "Test IsAllAlbumUploadOnInDb single album various status");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    bool result0 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result0);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    bool result1 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result1);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 2);
    bool result2 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result2);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_050");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_051, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_051 - Test GetAlbumUploadStatusWithLpath trailing slash");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera/");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots/");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecord/");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_051");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_052, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_052 - Test IsAllAlbumUploadOnInDb large dataset");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 50; i++) {
        InsertPhotoAlbum("album" + to_string(i), PhotoAlbumType::USER, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_052");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_053, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_053 - Test GetAlbumUploadStatus various scenarios");
    ClearTable(PhotoAlbumColumns::TABLE);
    int32_t status1 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status1, 0);
    
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    int32_t status2 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status2, 0);
    
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    int32_t status3 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_EQ(status3, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_053");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_054, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_054 - "
        "Test GetAlbumUploadStatusWithLpath camera variations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/CAMERA");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/dcim/camera");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/dCiM/CaMeRa");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_054");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_055, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_055 - "
        "Test GetAlbumUploadStatusWithLpath screenshot variations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENSHOTS");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/pictures/screenshots");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_055");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_056, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_056 - "
        "Test GetAlbumUploadStatusWithLpath screenrecord variations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/PICTURES/SCREENRECORDS");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenrecords");
    EXPECT_EQ(result, 1);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/pictures/screenrecords");
    EXPECT_EQ(result, 1);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_056");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_057, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_057 - Test IsAllAlbumUploadOnInDb mixed types all on");
    InsertPhotoAlbum("user_album", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("source_album", PhotoAlbumType::SOURCE, 1);
    InsertPhotoAlbum("smart_album", PhotoAlbumType::SMART, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_057");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_058, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_058 - Test JudgeUploadAlbumEnable verify final state");
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::ON));
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_058");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_059, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_059 - "
        "Test GetAlbumUploadStatusWithLpath with album name in path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/My Album");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera/2024");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecord/Meeting");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_059");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_060, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_060 - Test IsAllAlbumUploadOnInDb with exactly one off");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 5; i++) {
        InsertPhotoAlbum("album_on_" + to_string(i), PhotoAlbumType::USER, 1);
    }
    InsertPhotoAlbum("album_off", PhotoAlbumType::USER, 0);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_060");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_061, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_061 - "
        "Test GetAlbumUploadStatusWithLpath single char path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/a");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_061");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_062, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_062 - "
        "Test GetAlbumUploadStatusWithLpath multiple albums path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Users/Album1/SubAlbum");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera/2024/January");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_062");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_063, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_063 - "
        "Test IsAllAlbumUploadOnInDb after delete operations");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 1);
    bool result1 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result1);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result2 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result2);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_063");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_064, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_064 - "
        "Test GetAlbumUploadStatusWithLpath common album paths");
    std::vector<std::string> commonPaths = {
        "/Photos",
        "/Photo",
        "/My Photos",
        "/My Pictures",
        "/Camera Roll",
        "/Screenshots",
        "/ScreenShots",
        "/截屏"
    };
    
    for (const auto& path : commonPaths) {
        int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(path);
        EXPECT_GE(result, 0);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_064");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_065, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_065 - "
        "Test IsAllAlbumUploadOnInDb zero album type");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album_type_0", 0, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_065");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_066, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_066 - "
        "Test GetAlbumUploadStatusWithLpath path with special chars");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera@123");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshot#1");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/Movie[1]");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_066");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_067, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_067 - Test JudgeUploadAlbumEnable DEFAULT with support");
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_067");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_068, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_068 - Test IsAllAlbumUploadOnInDb type 2048 albums");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("cloud_album_1", 2048, 1);
    InsertPhotoAlbum("cloud_album_2", 2048, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_068");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_069, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_069 - Test GetAlbumUploadStatusWithLpath reverse path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("Camera/DCIM");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("Screenshots/Pictures");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_069");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_070, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_070 - Test comprehensive upload status check");
    ClearTable(PhotoAlbumColumns::TABLE);
    bool dbResult = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    int32_t statusResult = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    bool supportResult = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    
    EXPECT_FALSE(dbResult);
    EXPECT_GE(statusResult, 0);
    EXPECT_TRUE(supportResult);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_070");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_071, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_071 - "
        "Test GetAlbumUploadStatusWithLpath combined special paths");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera/Photo_2024");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots/2024-01-01");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecord/Recording_001");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_071");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_072, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_072 - "
        "Test IsAllAlbumUploadOnInDb with large album count");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 100; i++) {
        InsertPhotoAlbum("album_" + to_string(i), PhotoAlbumType::USER, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_072");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_073, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_073 - "
        "Test IsAllAlbumUploadOnInDb with 2048 and 0 type mix");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("type_0", 0, 1);
    InsertPhotoAlbum("type_2048", 2048, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_073");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_074, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_074 - "
        "Test GetAlbumUploadStatusWithLpath with emoji");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/📷/Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/🖼️/Screenshots");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_074");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_075, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_075 - Test JudgeUploadAlbumEnable check db update");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_075");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_076, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_076 - Test IsAllAlbumUploadOnInDb edge with one type off");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("type_0", 0, 1);
    InsertPhotoAlbum("type_2048", 2048, 0);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_076");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_077, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_077 - Test GetAlbumUploadStatusWithLpath deep path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(
        "/Pictures/Folder1/Folder2/Folder3/DeepAlbum");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(
        "/DCIM/Camera/Year/Month/Day/Photo");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_077");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_078, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_078 - Test IsAllAlbumUploadOnInDb reset behavior");
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result1 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result1);
    
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    bool result2 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result2);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    bool result3 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result3);
    
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 1);
    bool result4 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result4);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_078");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_079, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_079 - "
        "Test GetAlbumUploadStatusWithLpath similar to camera");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/CAMERA");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/CAMERAS");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/SCREENSHOT");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/SCREENSHOTS");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_079");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_080, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_080 - Test JudgeUploadAlbumEnable sequence");
    std::vector<int32_t> states = {
        static_cast<int32_t>(EnableUploadStatus::DEFAULT),
        static_cast<int32_t>(EnableUploadStatus::OFF),
        static_cast<int32_t>(EnableUploadStatus::ON),
        static_cast<int32_t>(EnableUploadStatus::DEFAULT),
        static_cast<int32_t>(EnableUploadStatus::OFF)
    };
    
    for (int32_t state : states) {
        SetHistoryUploadAlbumEnable(state);
        int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
        EXPECT_EQ(ret, E_OK);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_080");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_081, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_081 - Test IsAllAlbumUploadOnInDb all off");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    InsertPhotoAlbum("album3", PhotoAlbumType::SOURCE, 0);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_081");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_082, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_082 - "
        "Test GetAlbumUploadStatusWithLpath slash combinations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("DCIM/Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("Pictures//Screenshots");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("//Videos//ScreenRecord//");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_082");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_083, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_083 - Test IsAllAlbumUploadOnInDb with album_type 0 only");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("type0_1", 0, 1);
    InsertPhotoAlbum("type0_2", 0, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_083");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_084, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_084 - "
        "Test IsAllAlbumUploadOnInDb with album_type 2048 only");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("type2048_1", 2048, 1);
    InsertPhotoAlbum("type2048_2", 2048, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_084");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_085, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_085 - Test GetAlbumUploadStatusWithLpath numeric suffix");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera0");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera01");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshot10");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_085");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_086, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_086 - Test GetAlbumUploadStatusWithLpath chinese camera");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/相机");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/截图");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/屏幕录制");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_086");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_087, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_087 - Test JudgeUploadAlbumEnable final state check");
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::ON));
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_087");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_088, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_088 - Test IsAllAlbumUploadOnInDb complex mix");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::SOURCE, 1);
    InsertPhotoAlbum("album3", 2048, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_088");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_089, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_089 - Test GetAlbumUploadStatusWithLpath empty strings");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("   ");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("\t");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_089");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_090, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_090 - Final comprehensive test");
    ClearTable(PhotoAlbumColumns::TABLE);
    
    bool isSupport = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    EXPECT_TRUE(isSupport);
    
    bool dbEmpty = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(dbEmpty);
    
    InsertPhotoAlbum("test_album", PhotoAlbumType::USER, 1);
    bool dbWithData = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(dbWithData);
    
    int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status, 0);
    
    int32_t cameraStatus = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera");
    EXPECT_EQ(cameraStatus, 1);
    
    int32_t otherStatus = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Other");
    EXPECT_GE(otherStatus, 0);
    
    int32_t judgeResult = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(judgeResult, E_OK);
    
    MEDIA_INFO_LOG("End album_upload_status_operation_test_090");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_091, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_091 - "
        "Test GetAlbumUploadStatusWithLpath multiple queries");
    for (int i = 0; i < 10; i++) {
        int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera");
        EXPECT_EQ(result, 1);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_091");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_092, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_092 - Test IsAllAlbumUploadOnInDb stress test");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 30; i++) {
        InsertPhotoAlbum("album_" + to_string(i), PhotoAlbumType::USER, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_092");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_093, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_093 - Test IsSupportUploadStatus repeated");
    for (int i = 0; i < 10; i++) {
        bool result = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
        EXPECT_TRUE(result);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_093");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_094, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_094 - Test GetAlbumUploadStatus sequence");
    ClearTable(PhotoAlbumColumns::TABLE);
    int32_t status1 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status1, 0);
    
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    int32_t status2 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status2, 0);
    
    InsertPhotoAlbum("album2", PhotoAlbumType::USER, 0);
    int32_t status3 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_EQ(status3, 0);
    
    InsertPhotoAlbum("album3", PhotoAlbumType::USER, 1);
    int32_t status4 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_EQ(status4, 0);
    
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album4", PhotoAlbumType::USER, 1);
    int32_t status5 = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(status5, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_094");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_095, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_095 - Test GetAlbumUploadStatusWithLpath variation loop");
    std::vector<std::string> paths = {
        "/DCIM", "/DCIM/", "/DCIM/Camera", "/DCIM/Camera/",
        "/Pictures", "/Pictures/", "/Pictures/Screenshots", "/Pictures/Screenshots/",
        "/Videos", "/Videos/", "/Videos/ScreenRecord", "/Videos/ScreenRecord/"
    };
    
    for (const auto& path : paths) {
        int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(path);
        EXPECT_GE(result, 0);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_095");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_096, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_096 - Test JudgeUploadAlbumEnable state machine");
    std::vector<pair<int32_t, int32_t>> testCases = {
        {static_cast<int32_t>(EnableUploadStatus::DEFAULT), static_cast<int32_t>(EnableUploadStatus::DEFAULT)},
        {static_cast<int32_t>(EnableUploadStatus::ON), static_cast<int32_t>(EnableUploadStatus::ON)},
        {static_cast<int32_t>(EnableUploadStatus::OFF), static_cast<int32_t>(EnableUploadStatus::OFF)},
        {static_cast<int32_t>(EnableUploadStatus::DEFAULT), static_cast<int32_t>(EnableUploadStatus::DEFAULT)},
        {static_cast<int32_t>(EnableUploadStatus::ON), static_cast<int32_t>(EnableUploadStatus::ON)}
    };
    
    for (const auto& testCase : testCases) {
        SetHistoryUploadAlbumEnable(testCase.first);
        int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
        EXPECT_EQ(ret, E_OK);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_096");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_097, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_097 - Test IsAllAlbumUploadOnInDb mixed status");
    ClearTable(PhotoAlbumColumns::TABLE);
    std::vector<int32_t> statuses = {0, 1, 0, 1, 0, 1, 0, 1};
    for (size_t i = 0; i < statuses.size(); i++) {
        InsertPhotoAlbum("album_" + to_string(i), PhotoAlbumType::USER, statuses[i]);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_097");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_098, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_098 - "
        "Test GetAlbumUploadStatusWithLpath special folder names");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera Backup");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera_Backup");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshot (1)");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecord~tmp");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_098");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_099, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_099 - Test IsAllAlbumUploadOnInDb all type 0 albums");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 20; i++) {
        InsertPhotoAlbum("type0_" + to_string(i), 0, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_099");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_100, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_100 - Test IsAllAlbumUploadOnInDb all type 2048 albums");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 20; i++) {
        InsertPhotoAlbum("type2048_" + to_string(i), 2048, 1);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_100");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_101, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_101 - Test GetAlbumUploadStatusWithLpath album prefix");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/CameraRoll");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/CameraRolls");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/ScreenshotFolder");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/ScreenRecording");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_101");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_102, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_102 - Test comprehensive status query");
    ClearTable(PhotoAlbumColumns::TABLE);
    
    bool dbEmptyResult = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(dbEmptyResult);
    
    bool supportResult = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    EXPECT_TRUE(supportResult);
    
    int32_t statusEmpty = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(statusEmpty, 0);
    
    InsertPhotoAlbum("test", PhotoAlbumType::USER, 1);
    
    bool dbResult = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(dbResult);
    
    int32_t statusWithData = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(statusWithData, 0);
    
    int32_t lpathResult = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Test");
    EXPECT_GE(lpathResult, 0);
    
    int32_t judgeResult = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(judgeResult, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_102");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_103, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_103 - "
        "Test JudgeUploadAlbumEnable with new album");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 0);
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_103");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_104, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_104 - "
        "Test GetAlbumUploadStatusWithLpath windows style path");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("C:\\DCIM\\Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("D:\\Pictures\\Screenshots");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_104");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_105, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_105 - Test IsAllAlbumUploadOnInDb with alternating");
    ClearTable(PhotoAlbumColumns::TABLE);
    for (int i = 0; i < 10; i++) {
        InsertPhotoAlbum("even_" + to_string(i), PhotoAlbumType::USER, (i % 2 == 0) ? 1 : 0);
    }
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_105");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_106, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_106 - Test GetAlbumUploadStatusWithLpath unicode chars");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/照相机");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/图片/屏幕截图");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/视频/屏幕录制");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_106");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_107, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_107 - Test IsAllAlbumUploadOnInDb with large album");
    ClearTable(PhotoAlbumColumns::TABLE);
    std::string longName = "";
    for (int i = 0; i < 100; i++) {
        longName += "a";
    }
    InsertPhotoAlbum(longName, PhotoAlbumType::USER, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_107");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_108, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_108 - Test JudgeUploadAlbumEnable all states");
    for (int state = 0; state <= 2; state++) {
        SetHistoryUploadAlbumEnable(state);
        int32_t ret = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
        EXPECT_EQ(ret, E_OK);
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_108");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_109, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_109 - Test GetAlbumUploadStatusWithLpath root variations");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("//");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("///");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_109");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_110, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_110 - Test GetAlbumUploadStatus sequence with clear");
    ClearTable(PhotoAlbumColumns::TABLE);
    
    for (int round = 0; round < 3; round++) {
        int32_t status = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
        EXPECT_GE(status, 0);
        
        if (round < 2) {
            InsertPhotoAlbum("album" + to_string(round), PhotoAlbumType::USER, 1);
        }
    }
    MEDIA_INFO_LOG("End album_upload_status_operation_test_110");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_111, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_111 - Test IsAllAlbumUploadOnInDb verify close behavior");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    bool result1 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result1);
    bool result2 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result2);
    bool result3 = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result3);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_111");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_112, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_112 - Test GetAlbumUploadStatusWithLpath path segments");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera/2024/01/15");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots/2024/January");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/ScreenRecord/Meeting/Recording");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_112");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_113, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_113 - Test IsAllAlbumUploadOnInDb verify all on");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("album1", PhotoAlbumType::USER, 1);
    InsertPhotoAlbum("album2", PhotoAlbumType::SOURCE, 1);
    InsertPhotoAlbum("album3", 2048, 1);
    bool result = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(result);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_113");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_114, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_114 - Test JudgeUploadAlbumEnable after insert");
    ClearTable(PhotoAlbumColumns::TABLE);
    InsertPhotoAlbum("test", PhotoAlbumType::USER, 1);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::DEFAULT));
    int32_t ret1 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret1, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::ON));
    int32_t ret2 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret2, E_OK);
    
    SetHistoryUploadAlbumEnable(static_cast<int32_t>(EnableUploadStatus::OFF));
    int32_t ret3 = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(ret3, E_OK);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_114");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_115, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_115 - Test GetAlbumUploadStatusWithLpath with dot");
    int32_t result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/./Camera");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/../Pictures/Screenshots");
    EXPECT_GE(result, 0);
    result = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Videos/./ScreenRecord");
    EXPECT_GE(result, 0);
    MEDIA_INFO_LOG("End album_upload_status_operation_test_115");
}

HWTEST_F(PhotoAlbumUploadStatusOperationTest, album_upload_status_operation_test_116, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start album_upload_status_operation_test_116 - Final integration test");
    ClearTable(PhotoAlbumColumns::TABLE);
    
    bool support = PhotoAlbumUploadStatusOperation::IsSupportUploadStatus();
    EXPECT_TRUE(support);
    
    bool emptyDb = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_FALSE(emptyDb);
    
    int32_t emptyStatus = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus();
    EXPECT_GE(emptyStatus, 0);
    
    InsertPhotoAlbum("user", PhotoAlbumType::USER, 1);
    bool userDb = PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb();
    EXPECT_TRUE(userDb);
    
    int32_t cameraPath = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/DCIM/Camera");
    EXPECT_EQ(cameraPath, 1);
    
    int32_t screenshotPath = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenshots");
    EXPECT_EQ(screenshotPath, 1);
    
    int32_t recordPath = PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath("/Pictures/Screenrecords");
    EXPECT_EQ(recordPath, 1);
    
    int32_t judgeRet = PhotoAlbumUploadStatusOperation::JudgeUploadAlbumEnable();
    EXPECT_EQ(judgeRet, E_OK);
    
    MEDIA_INFO_LOG("End album_upload_status_operation_test_116");
}
}  // namespace OHOS::Media