/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloneRestoreGroupPhotoTest"

#include "clone_restore_group_photo_test.h"
#include "vision_db_sqls.h"
#include "vision_db_sqls_more.h"
#define private public
#define protected public
#include "clone_group_photo_source.h"
#include "clone_restore_group_photo.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "userfile_manager_types.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "backup_const.h"
#include "clone_restore.h"
#include "media_log.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
const string TEST_BACKUP_PATH = "/data/test/backup/db";
const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
const std::unordered_map<int32_t, PhotoInfo> PHOTO_INFO_MAP = {
    {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "test.jpg", "/Photo/1/coverUri.jpg"})},
    {2, PhotoInfo({2, MediaType::MEDIA_TYPE_IMAGE, "test_002.jpg", "/Photo/1/coverUri_002.jpg"})},
};

const std::unordered_map<int32_t, PhotoInfo> PHOTO_INFO_MAP_NO_DATA = {};
static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static unique_ptr<CloneRestore> restoreService = nullptr;
static CloneGroupPhotoSource cloneSource;
static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
    CREATE_ANALYSIS_ALBUM_MAP,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    ANALYSIS_ALBUM_TABLE,
    ANALYSIS_PHOTO_MAP_TABLE,
};

const vector<string> CLEAR_SQLS = {
    "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_TABLE,
    "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE,
};

const int32_t EXPECTED_GROUP_ALBUM_COUNT = 2;

static void ExecuteSqls(shared_ptr<NativeRdb::RdbStore> store, const vector<string> &sqls)
{
    for (const auto &sql : sqls) {
        int32_t errCode = store->ExecuteSql(sql);
        if (errCode == E_OK) {
            continue;
        }
        MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
    }
}

static void InsertPhotoInNewDb(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "1, " +
        "'/storage/cloud/files/Photo/16/test.jpg', 175258, 'test', 'test.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 1501924205423, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, '1'" + VALUES_END); // cam, pic, shootingmode = 1
    rdbPtr->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "2, " +
        "'/storage/cloud/files/Photo/1/IMG_1501924307_001.jpg', 175397, 'test_002', 'test_002.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924207184, 1501924207286, 1501924207, 0, 0, 0, 0, " +
        "1280, 960, 0, ''" + VALUES_END); // cam, pic, trashed
}

static void InsertAnalysisAlbumInNewDb(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql("INSERT INTO AnalysisAlbum ("
        "album_type, album_subtype, album_name, tag_id, cover_uri, is_cover_satisfied) "
        "VALUES (4096, 4103, 'test_group_photo_album_001', 'a|c,', 'test_cover_uri', 1)");
}

static void InsertAnalysisAlbumWithMerging(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql("INSERT INTO AnalysisAlbum ("
        "album_type, album_subtype, album_name, tag_id, group_tag, cover_uri, is_cover_satisfied) "
        "VALUES (4096, 4103, 'test_group_photo_album_001', 'a|c,d', 'a|c,d', 'test_cover_uri', 1)");
}

static void InsertAnalysisPhotoMapInNewDb(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "1, 1, 1" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "1, 2, 2" + VALUES_END);
}

static void PreProcessInNewDb(std::shared_ptr<Media::MediaLibraryRdbStore> mediaRdbPtr)
{
    std::shared_ptr<NativeRdb::RdbStore> rdbPtr = mediaRdbPtr->GetRaw();
    InsertPhotoInNewDb(rdbPtr);
    InsertAnalysisAlbumInNewDb(rdbPtr);
    InsertAnalysisPhotoMapInNewDb(rdbPtr);
}

static void CreateDataWithMerging(std::shared_ptr<Media::MediaLibraryRdbStore> mediaRdbPtr)
{
    std::shared_ptr<NativeRdb::RdbStore> rdbPtr = mediaRdbPtr->GetRaw();
    InsertPhotoInNewDb(rdbPtr);
    InsertAnalysisAlbumWithMerging(rdbPtr);
    InsertAnalysisPhotoMapInNewDb(rdbPtr);
}

static void ClearGroupPhotoData(std::shared_ptr<NativeRdb::RdbStore>& mediaRdbPtr)
{
    MEDIA_INFO_LOG("Start clear data");
    ExecuteSqls(mediaRdbPtr, CLEAR_SQLS);
    MEDIA_INFO_LOG("End clear data");
}

void CloneRestoreGroupPhotoTest::Init(CloneGroupPhotoSource &cloneGroupPhotoSource,
    const string &path, const vector<string> &tableList)
{
    MEDIA_INFO_LOG("Start init clone source database");
    cloneGroupPhotoSource.Init(path, tableList);
}

void CloneRestoreGroupPhotoTest::VerifyGroupAlbumRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE album_type = " + std::to_string(SMART) +
        " AND album_subtype = " + std::to_string(GROUP_PHOTO) +
        " ORDER BY album_id ASC";

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(count, EXPECTED_GROUP_ALBUM_COUNT);
    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    std::string columnValue;

    (void)resultSet->GetColumnIndex("album_name", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "test_group_photo_album_001");

    (void)resultSet->GetColumnIndex("tag_id", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "a|b,");

    (void)resultSet->GetColumnIndex("cover_uri", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "file://media/Photo/1/coverUri/test.jpg");

    (void)resultSet->GetColumnIndex("is_cover_satisfied", index);
    int isCoverSatisfied;
    resultSet->GetInt(index, isCoverSatisfied);
    EXPECT_EQ(isCoverSatisfied, 1);
}

void CloneRestoreGroupPhotoTest::VerifyGroupPhotoAlbumWithoutData(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE album_type = " + std::to_string(SMART) +
        " AND album_subtype = " + std::to_string(GROUP_PHOTO);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(count, EXPECTED_GROUP_ALBUM_COUNT);
    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    std::string columnValue;

    (void)resultSet->GetColumnIndex("album_name", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "test_group_photo_album_001");

    (void)resultSet->GetColumnIndex("tag_id", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "a|b,");

    (void)resultSet->GetColumnIndex("cover_uri", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "");

    (void)resultSet->GetColumnIndex("is_cover_satisfied", index);
    int isCoverSatisfied;
    resultSet->GetInt(index, isCoverSatisfied);
    EXPECT_EQ(isCoverSatisfied, 0);
}

void CloneRestoreGroupPhotoTest::VerifyGroupPhotoAlbumWithMerging(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE album_type = " + std::to_string(SMART) +
        " AND album_subtype = " + std::to_string(GROUP_PHOTO);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(count, EXPECTED_GROUP_ALBUM_COUNT);
    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    std::string columnValue;

    (void)resultSet->GetColumnIndex("album_name", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "test_group_photo_album_001");

    (void)resultSet->GetColumnIndex("tag_id", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "a|b,");

    (void)resultSet->GetColumnIndex("group_tag", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "");

    (void)resultSet->GetColumnIndex("cover_uri", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "");

    (void)resultSet->GetColumnIndex("is_cover_satisfied", index);
    int isCoverSatisfied;
    resultSet->GetInt(index, isCoverSatisfied);
    EXPECT_EQ(isCoverSatisfied, 0);
}

void CloneRestoreGroupPhotoTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start CloneRestoreGroupPhotoTest::Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(g_rdbStore, createTableSqlLists);
    MEDIA_INFO_LOG("Start init restoreService");
    restoreService = make_unique<CloneRestore>();
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw(); // destination database
}

void CloneRestoreGroupPhotoTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("CloneRestoreGroupPhotoTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    restoreService->mediaLibraryRdb_ = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void CloneRestoreGroupPhotoTest::SetUp()
{
    ASSERT_NE(g_rdbStore, nullptr);
    MediaLibraryUnitTestUtils::CleanTestTables(g_rdbStore, testTables);
}

void CloneRestoreGroupPhotoTest::TearDown(void) {}

HWTEST_F(CloneRestoreGroupPhotoTest, medialibrary_backup_clone_restore_group_photo_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_group_photo_album_test_001");
    EXPECT_NE(g_rdbStore, nullptr);
    std::shared_ptr<NativeRdb::RdbStore> rdbPtr = g_rdbStore->GetRaw();
    ClearGroupPhotoData(rdbPtr);
    vector<string> tableList = {PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    PreProcessInNewDb(g_rdbStore);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->photoInfoMap_ = PHOTO_INFO_MAP;
    restoreService->RestoreGroupPhoto();

    VerifyGroupAlbumRestore(restoreService->mediaLibraryRdb_);
}

HWTEST_F(CloneRestoreGroupPhotoTest, medialibrary_backup_clone_restore_group_photo_album_no_data_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_group_photo_album_no_data_test_001");
    EXPECT_NE(g_rdbStore, nullptr);
    EXPECT_NE(cloneSource.cloneStorePtr_, nullptr);
    ClearGroupPhotoData(cloneSource.cloneStorePtr_);
    std::shared_ptr<NativeRdb::RdbStore> rdbPtr = g_rdbStore->GetRaw();
    ClearGroupPhotoData(rdbPtr);
    PreProcessInNewDb(g_rdbStore);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->photoInfoMap_ = PHOTO_INFO_MAP_NO_DATA;
    restoreService->RestoreGroupPhoto();
    VerifyGroupPhotoAlbumWithoutData(restoreService->mediaLibraryRdb_);
}

HWTEST_F(CloneRestoreGroupPhotoTest, medialibrary_backup_clone_restore_group_photo_album_merge_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_group_photo_album_merge_test_001");
    EXPECT_NE(g_rdbStore, nullptr);
    EXPECT_NE(cloneSource.cloneStorePtr_, nullptr);
    ClearGroupPhotoData(cloneSource.cloneStorePtr_);
    std::shared_ptr<NativeRdb::RdbStore> rdbPtr = g_rdbStore->GetRaw();
    ClearGroupPhotoData(rdbPtr);
    CreateDataWithMerging(g_rdbStore);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->photoInfoMap_ = PHOTO_INFO_MAP_NO_DATA;
    restoreService->RestoreGroupPhoto();
    VerifyGroupPhotoAlbumWithMerging(restoreService->mediaLibraryRdb_);
}

HWTEST_F(CloneRestoreGroupPhotoTest, medialibrary_backup_clone_restore_group_photo_init_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medial medialibrary_backup_clone_restore_group_photo_init_test_001");
    CloneRestoreGroupPhoto restore;
    int32_t sceneCode = 1001;
    std::string taskId = "test_task_001";
    std::string restoreInfo = "test_restore_info";
    bool isCloudRestoreSatisfied = true;
    restore.Init(sceneCode, taskId, restoreInfo, g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, isCloudRestoreSatisfied);
    EXPECT_EQ(restore.sceneCode_, sceneCode);
    EXPECT_EQ(restore.taskId_, taskId);
    EXPECT_EQ(restore.restoreInfo_, restoreInfo);
    EXPECT_EQ(restore.isCloudRestoreSatisfied_, isCloudRestoreSatisfied);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_init_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_init_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(1001, "test_task_001", "test_restore_info", nullptr, nullptr, true);
    EXPECT_EQ(restore.mediaLibraryRdb_, nullptr);
    EXPECT_EQ(restore.mediaRdb_, nullptr);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = nullptr;
    restore.mediaRdb_ = nullptr;
    restore.Restore(PHOTO_INFO_MAP);
    EXPECT_EQ(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_query_album_in_old_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_query_album_in_old_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    int32_t offset = 0;
    int32_t rowCount = 0;
    std::vector<GroupPhotoAlbumDfx> result = restore.QueryGroupPhotoAlbumInOldDb(offset, rowCount);
    EXPECT_GE(result.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_query_album_in_old_db_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_query_album_in_old_db_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = nullptr;
    int32_t offset = 0;
    int32_t rowCount = 0;
    std::vector<GroupPhotoAlbumDfx> result = restore.QueryGroupPhotoAlbumInOldDb(offset, rowCount);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_record_old_album_dfx_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_record_old_album_dfx_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.RecordOldGroupPhotoAlbumDfx();
    EXPECT_GE(restore.groupPhotoAlbumDfx_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_query_all_group_tag_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_query_all_group_tag_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore.RecordOldGroupPhotoAlbumDfx();
    std::unordered_set<std::string> result = restore.QueryAllGroupTag();
    
    EXPECT_GE(result.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_log_group_photo_clone_dfx_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_log_group_photo_clone_dfx_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore.RecordOldGroupPhotoAlbumDfx();
    restore.LogGroupPhotoCloneDfx();

    EXPECT_GE(restore.groupPhotoAlbumDfx_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_album_in_new_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_album_in_new_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<std::string> deletedAlbumIds = {"1", "2", "3"};
    int32_t result = restore.DeleteGroupPhotoAlbumInNewDb(deletedAlbumIds);
    EXPECT_GE(result, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_album_in_new_db_empty_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_album_in_new_db_empty_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<std::string> deletedAlbumIds = {};
    int32_t result = restore.DeleteGroupPhotoAlbumInNewDb(deletedAlbumIds);
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_map_in_new_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_map_in_new_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<std::string> deletedAlbumIds = {"1", "2"};
    int32_t result = restore.DeleteGroupPhotoMapInNewDb(deletedAlbumIds);

    EXPECT_GE(result, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_map_in_new_db_empty_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_map_in_new_db_empty_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<std::string> deletedAlbumIds = {};
    int32_t result = restore.DeleteGroupPhotoMapInNewDb(deletedAlbumIds);

    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_album_info_in_new_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_delete_album_info_in_new_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();

    InsertAnalysisAlbumInNewDb(g_rdbStore->GetRaw());

    int32_t result = restore.DeleteGroupPhotoAlbumInfoInNewDb();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_delete_album_in_newdb_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_delete_album_info_in_new_db_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = nullptr;

    int32_t result = restore.DeleteGroupPhotoAlbumInfoInNewDb();

    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_album_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_album_info_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore.photoInfoMap_ = PHOTO_INFO_MAP;

    int32_t result = restore.RestoreGroupPhotoAlbumInfo();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_album_info_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_album_info_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = nullptr;
    restore.mediaLibraryRdb_ = nullptr;

    int32_t result = restore.RestoreGroupPhotoAlbumInfo();

    EXPECT_NE(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_insert_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_insert_album_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();

    AnalysisAlbumTbl albumInfo;
    albumInfo.albumIdNew = 100;
    albumInfo.albumName = "test_album";
    albumInfo.albumType = SMART;
    albumInfo.albumSubtype = GROUP_PHOTO;
    restore.groupPhotoAlbumInfos_.push_back(albumInfo);
    int32_t result = restore.InsertGroupPhotoAlbum();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_insert_album_empty_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_insert_album_empty_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    int32_t result = restore.InsertGroupPhotoAlbum();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_maps_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_maps_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore.photoInfoMap_ = PHOTO_INFO_MAP;
    InsertAnalysisAlbumInNewDb(g_rdbStore->GetRaw());
    InsertAnalysisPhotoMapInNewDb(g_rdbStore->GetRaw());
    int32_t result = restore.RestoreMaps();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_maps_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_maps_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = nullptr;
    restore.mediaLibraryRdb_ = nullptr;
    int32_t result = restore.RestoreMaps();

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, group_photo_insert_analysis_photo_map_empty_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_insert_analysis_photo_map_empty_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<NativeRdb::ValuesBucket> values;
    restore.InsertAnalysisPhotoMap(values);

    EXPECT_EQ(restore.mapSuccessCnt_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_report_restore_task_of_total_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_report_restore_task_of_total_test_001");
    CloneRestoreGroupPhoto restore;
    restore.sceneCode_ = 1001;
    restore.taskId_ = "test_task_001";
    restore.restoreTimeCost_ = 1000;
    restore.maxAnalysisAlbumId_ = 100;
    restore.albumSuccessCnt_ = 10;
    restore.albumDeleteCnt_ = 2;
    restore.albumFailedCnt_ = 1;
    restore.mapSuccessCnt_ = 20;
    restore.mapFailedCnt_ = 0;
    restore.ReportRestoreTaskOfTotal();

    EXPECT_EQ(restore.restoreTimeCost_, 1000);
}

HWTEST_F(CloneRestoreGroupPhotoTest, group_photo_report_restore_task_of_album_stats_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_report_restore_task_of_album_stats_test_001");
    CloneRestoreGroupPhoto restore;
    restore.sceneCode_ = 1001;
    restore.taskId_ = "test_task_001";
    restore.albumPhotoCounter_["album_1"] = 10;
    restore.albumPhotoCounter_["album_2"] = 20;
    restore.albumPhotoCounter_["album_3"] = 5;
    restore.ReportRestoreTaskOfAlbumStats();

    EXPECT_EQ(restore.albumPhotoCounter_.size(), 3);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_report_restore_task_of_album_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_report_restore_task_of_album_info_test_001");
    CloneRestoreGroupPhoto restore;
    restore.sceneCode_ = 1001;
    restore.taskId_ = "test_task_001";
    restore.albumPhotoCounter_["test_album_1"] = 10;
    restore.albumPhotoCounter_["test_album_2"] = 20;
    restore.ReportRestoreTaskOfAlbumInfo();

    EXPECT_EQ(restore.albumPhotoCounter_.size(), 2);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_report_clone_restore_task_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_report_clone_restore_task_test_001");
    CloneRestoreGroupPhoto restore;
    restore.sceneCode_ = 1001;
    restore.taskId_ = "test_task_001";
    restore.restoreTimeCost_ = 1000;
    restore.maxAnalysisAlbumId_ = 100;
    restore.albumSuccessCnt_ = 10;
    restore.albumDeleteCnt_ = 2;
    restore.albumFailedCnt_ = 1;
    restore.mapSuccessCnt_ = 20;
    restore.mapFailedCnt_ = 0;
    restore.albumPhotoCounter_["album_1"] = 10;
    restore.albumPhotoCounter_["album_2"] = 20;
    restore.ReportCloneRestoreGroupPhotoTask();

    EXPECT_EQ(restore.restoreTimeCost_, 1000);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_query_album_tbl_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_query_album_tbl_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = cloneSource.cloneStorePtr_;
    restore.mediaLibraryRdb_ = g_rdbStore->GetRaw();
    std::vector<std::string> commonColumns = {"album_id", "album_name", "album_type", "album_subtype"};
    int32_t result = restore.QueryGroupPhotoAlbumTbl(commonColumns);

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_query_album_tbl_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_query_album_tbl_null_db_test_001");
    CloneRestoreGroupPhoto restore;
    restore.mediaRdb_ = nullptr;
    restore.mediaLibraryRdb_ = nullptr;
    std::vector<std::string> commonColumns = {"album_id", "album_name"};
    int32_t result = restore.QueryGroupPhotoAlbumTbl(commonColumns);

    EXPECT_NE(result, E_OK);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_full_flow_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_full_flow_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(1001, "test_task_001", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_empty_photo_map_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_empty_photo_map_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(2002, "test_task_002", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP_NO_DATA);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_large_photo_map_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_large_photo_map_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(3003, "test_task_003", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    
    std::unordered_map<int32_t, PhotoInfo> largePhotoMap;
    for (int32_t i = 1; i <= 100; i++) {
        largePhotoMap[i] = PhotoInfo({i, MediaType::MEDIA_TYPE_IMAGE,
            "test_" + std::to_string(i) + ".jpg",
            "/Photo/" + std::to_string(i) + "/coverUri.jpg" });
    }
    restore.Restore(largePhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_cloudscape_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_cloudscape_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(4004, "test_task_004", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, false);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_EQ(restore.isCloudRestoreSatisfied_, false);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_scene_code_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_scene_code_test_001");
    CloneRestoreGroupPhoto restore;
    int32_t testSceneCode = 9999;
    restore.Init(testSceneCode, "test_task_006", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_EQ(restore.sceneCode_, testSceneCode);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_empty_task_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_empty_task_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(6006, "", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_EQ(restore.taskId_, "");
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_long_restore_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_long_restore_info_test_001");
    CloneRestoreGroupPhoto restore;
    std::string longRestoreInfo(1000, 'A');
    restore.Init(7007, "test_task_007", longRestoreInfo, g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_EQ(restore.restoreInfo_.length(), 1000);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_multiple_times_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_multiple_times_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(8008, "test_task_008", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    for (int32_t i = 0; i < 3; i++) {
        restore.Restore(PHOTO_INFO_MAP);
    }

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_with_special_chars_task_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_special_chars_task_id_test_001");
    CloneRestoreGroupPhoto restore;
    std::string specialTaskId = "test_task_!@#$%^&*()";
    restore.Init(9009, specialTaskId, "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_EQ(restore.taskId_, specialTaskId);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_counters_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_counters_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(10010, "test_task_010", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.albumSuccessCnt_, 0);
    EXPECT_GE(restore.mapSuccessCnt_, 0);
    EXPECT_GE(restore.albumFailedCnt_, 0);
    EXPECT_GE(restore.mapFailedCnt_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_time_cost_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_time_cost_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(11011, "test_task_011", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    restore.Restore(PHOTO_INFO_MAP);
    int64_t endTime = MediaFileUtils::UTCTimeMilliSeconds();

    EXPECT_GE(restore.restoreTimeCost_, 0);
    EXPECT_LE(restore.restoreTimeCost_, endTime - startTime + 100);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_album_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_album_infos_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(12012, "test_task_012", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.groupPhotoAlbumInfos_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_dfx_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_dfx_infos_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(13013, "test_task_013", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.groupPhotoAlbumDfx_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_verify_cover_uri_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_cover_uri_infos_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(14014, "test_task_014", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.coverUriInfo_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_verify_album_photo_counter_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_album_photo_counter_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(15015, "test_task_015", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.albumPhotoCounter_.size(), 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_max_album_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_max_album_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(16016, "test_task_016", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);
    EXPECT_GE(restore.maxAnalysisAlbumId_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_last_map_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_last_map_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(17017, "test_task_017", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.lastIdOfMap_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_verify_migrate_time_cost_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_migrate_time_cost_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(18018, "test_task_018", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.migrateGroupPhotoTotalTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_delete_count_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_delete_count_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(19019, "test_task_019", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_GE(restore.albumDeleteCnt_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_verify_is_map_order_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_verify_is_map_order_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(20020, "test_task_020", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP);

    EXPECT_TRUE(restore.isMapOrder_ || !restore.isMapOrder_);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_null_photo_info_map_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_null_photo_info_map_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(21021, "test_task_021", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore.Restore(PHOTO_INFO_MAP_NO_DATA);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_single_photo_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_single_photo_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(22022, "test_task_022", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> singlePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "single.jpg", "/Photo/1/single.jpg"})}
    };
    restore.Restore(singlePhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_duplicate_photos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_duplicate_photos_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(23023, "test_task_023", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> duplicatePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "duplicate.jpg", "/Photo/1/duplicate.jpg"})},
        {2, PhotoInfo({2, MediaType::MEDIA_TYPE_IMAGE, "duplicate.jpg", "/Photo/1/duplicate.jpg"})}
    };
    restore.Restore(duplicatePhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_video_media_type_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_video_media_type_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(24024, "test_task_024", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> videoPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_VIDEO, "video.mp4", "/Video/1/video.mp4"})}
    };
    restore.Restore(videoPhotoMap);
    
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_audio_media_type_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_audio_media_type_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(25025, "test_task_025", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> audioPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_AUDIO, "audio.mp3", "/Audio/1/audio.mp3"})}
    };
    restore.Restore(audioPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_zero_photo_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_zero_photo_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(26026, "test_task_026", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> zeroIdPhotoMap = {
        {0, PhotoInfo({0, MediaType::MEDIA_TYPE_IMAGE, "zero.jpg", "/Photo/0/zero.jpg"})}
    };
    restore.Restore(zeroIdPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_negative_photo_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_negative_photo_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(27027, "test_task_027", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> negativeIdPhotoMap = {
        {-1, PhotoInfo({-1, MediaType::MEDIA_TYPE_IMAGE, "negative.jpg", "/Photo/-1/negative.jpg"})}
    };
    restore.Restore(negativeIdPhotoMap);
    
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_large_photo_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_large_photo_id_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(28028, "test_task_028", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> largeIdPhotoMap = {
        {999999, PhotoInfo({999999, MediaType::MEDIA_TYPE_IMAGE, "large.jpg", "/Photo/999999/large.jpg"})}
    };
    restore.Restore(largeIdPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_empty_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_empty_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(29029, "test_task_029", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> emptyFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "", "/Photo/1/"})}
    };
    restore.Restore(emptyFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_empty_file_path_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_empty_file_path_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(30030, "test_task_030", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> emptyFilePathPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "empty.jpg", ""})}
    };
    restore.Restore(emptyFilePathPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_special_chars_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_special_chars_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(31031, "test_task_031", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> specialCharsPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "special!@#$%^&*().jpg", "/Photo/1/special!@#$%^&*().jpg"})}
    };
    restore.Restore(specialCharsPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_unicode_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_unicode_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(32032, "test_task_032", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> unicodePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "中文图片.jpg", "/Photo/1/中文图片.jpg"})}
    };
    restore.Restore(unicodePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_long_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_long_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(33033, "test_task_033", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::string longFileName(500, 'A');
    longFileName += ".jpg";
    std::unordered_map<int32_t, PhotoInfo> longFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, longFileName, "/Photo/1/" + longFileName})}
    };
    restore.Restore(longFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_long_file_path_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_long_file_path_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(34034, "test_task_034", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::string longFilePath(1000, '/');
    std::unordered_map<int32_t, PhotoInfo> longFilePathPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "long.jpg", longFilePath + "long.jpg"})}
    };
    restore.Restore(longFilePathPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_space_in_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_space_in_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(35035, "test_task_035", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> spaceFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "space file name.jpg", "/Photo/1/space file name.jpg"})}
    };
    restore.Restore(spaceFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_dot_in_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_dot_in_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(36036, "test_task_036", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> dotFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "dot.file.name.jpg", "/Photo/1/dot.file.name.jpg"})}
    };
    restore.Restore(dotFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_underscore_in_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_underscore_in_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(37037, "test_task_037", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> underscoreFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "underscore_file_name.jpg",
            "/Photo/1/underscore_file_name.jpg"})}
    };
    restore.Restore(underscoreFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_dash_in_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_dash_in_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(38038, "test_task_038", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> dashFileNamePhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "dash-file-name.jpg", "/Photo/1/dash-file-name.jpg"})}
    };
    restore.Restore(dashFileNamePhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_no_extension_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_no_extension_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(39039, "test_task_039", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    std::unordered_map<int32_t, PhotoInfo> noExtensionPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "noextension", "/Photo/1/noextension"})}
    };
    restore.Restore(noExtensionPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_with_multiple_extensions_file_name_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_multiple_extensions_file_name_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(40040, "test_task_040", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> multipleExtensionsPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "file.tar.gz.jpg", "/Photo/1/file.tar.gz.jpg"})}
    };
    restore.Restore(multipleExtensionsPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_group_photo_restore_with_uppercase_extension_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_uppercase_extension_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(41041, "test_task_041", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> uppercaseExtensionPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "uppercase.JPG", "/Photo/1/uppercase.JPG"})}
    };

    restore.Restore(uppercaseExtensionPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_jpeg_extension_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_jpeg_extension_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(78078, "test_task_078", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> jpegExtensionPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "image.jpeg", "/Photo/1/image.jpeg"})}
    };
    restore.Restore(jpegExtensionPhotoMap);

    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_with_jpe_extension_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_with_jpe_extension_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(79079, "test_task_079", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> jpeExtensionPhotoMap = {
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "image.jpe", "/Photo/1/image.jpe"})}
    };

    restore.Restore(jpeExtensionPhotoMap);
 
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_boundary_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_boundary_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(140140, "test_task_140", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> boundaryPhotoMap = {
        {-1, PhotoInfo({-1, MediaType::MEDIA_TYPE_IMAGE, "boundary_neg1.jpg", "/Photo/-1/boundary_neg1.jpg"})},
        {0, PhotoInfo({0, MediaType::MEDIA_TYPE_IMAGE, "boundary_0.jpg", "/Photo/0/boundary_0.jpg"})},
        {1, PhotoInfo({1, MediaType::MEDIA_TYPE_IMAGE, "boundary_1.jpg", "/Photo/1/boundary_1.jpg"})},
        {INT32_MAX, PhotoInfo({INT32_MAX, MediaType::MEDIA_TYPE_IMAGE, "boundary_max.jpg",
            "/Photo/max/boundary_max.jpg"})}
    };
    restore.Restore(boundaryPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_performance_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_performance_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(141141, "test_task_141", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> performancePhotoMap;
    for (int32_t i = 1; i <= 500; i++) {
        performancePhotoMap[i] = PhotoInfo({i, MediaType::MEDIA_TYPE_IMAGE,
            "perf_" + std::to_string(i) + ".jpg",
            "/Photo/" + std::to_string(i) + "/perf_" + std::to_string(i) + ".jpg"});
    }

    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    restore.Restore(performancePhotoMap);
    int64_t endTime = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t duration = endTime - startTime;

    EXPECT_GE(restore.restoreTimeCost_, 0);
    EXPECT_LT(duration, 30000);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_memory_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_memory_test_001");
    CloneRestoreGroupPhoto restore;
    restore.Init(142142, "test_task_142", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    std::unordered_map<int32_t, PhotoInfo> memoryPhotoMap;
    for (int32_t i = 1; i <= 1000; i++) {
        memoryPhotoMap[i] = PhotoInfo({i, MediaType::MEDIA_TYPE_IMAGE,
            "mem_" + std::to_string(i) + ".jpg",
            "/Photo/" + std::to_string(i) + "/mem_" + std::to_string(i) + ".jpg"});
    }
    restore.Restore(memoryPhotoMap);
    EXPECT_GE(restore.restoreTimeCost_, 0);
    EXPECT_GE(restore.albumSuccessCnt_, 0);
    EXPECT_GE(restore.mapSuccessCnt_, 0);
}

HWTEST_F(CloneRestoreGroupPhotoTest, clone_restore_group_photo_restore_concurrent_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start clone_restore_group_photo_restore_concurrent_test_001");
    CloneRestoreGroupPhoto restore1;
    restore1.Init(143143, "test_task_143", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);

    CloneRestoreGroupPhoto restore2;
    restore2.Init(144144, "test_task_144", "test_restore_info", g_rdbStore->GetRaw(),
        cloneSource.cloneStorePtr_, true);
    restore1.Restore(PHOTO_INFO_MAP);
    restore2.Restore(PHOTO_INFO_MAP);
    EXPECT_GE(restore1.restoreTimeCost_, 0);
    EXPECT_GE(restore2.restoreTimeCost_, 0);
}
}
}