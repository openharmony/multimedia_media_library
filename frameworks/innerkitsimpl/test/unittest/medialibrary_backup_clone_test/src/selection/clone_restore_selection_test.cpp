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
#define MLOG_TAG "CloneRestoreSelectionTest"

#include "clone_restore_selection_test.h"
#include "clone_restore_selection_source.h"

#include "vision_column.h"
#include "vision_db_sqls_more.h"
#include "vision_db_sqls.h"
#include "media_upgrade.h"
#define private public
#define protected public
#include "clone_restore_selection.h"
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
#include "media_upgrade.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int32_t FILE_INFO_NEW_ID = 101;
static const string TEST_BACKUP_PATH = "/data/test/backup/db";
static const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
static const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
static shared_ptr<MediaLibraryRdbStore> newRdbStore = nullptr;
static unique_ptr<CloneRestoreSelection> cloneRestoreSelection = nullptr;

static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_TAB_ANALYSIS_TOTAL_FOR_ONCREATE,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    "tab_analysis_selection",
    "tab_analysis_atom_event",
    "tab_analysis_total",
};

void CloneRestoreSelectionTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start CloneRestoreSelectionTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
}

void CloneRestoreSelectionTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("CloneRestoreSelectionTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    cloneRestoreSelection = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void CloneRestoreSelectionTest::SetUp()
{
    MEDIA_INFO_LOG("enter CloneRestoreSelectionTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);
}

void CloneRestoreSelectionTest::TearDown() {}

void CloneRestoreSelectionTest::Init(CloneRestoreSelectionSource &selectionSource, const string &path,
    const vector<string>& tableList)
{
    MEDIA_INFO_LOG("Start init clone source database");
    selectionSource.Init(path, tableList);
}

void CloneRestoreSelectionTest::SetupMockPhotoInfoMap(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = FILE_INFO_NEW_ID;
    photoInfo.displayName = "test.jpg";
    photoInfo.cloudPath = "/storage/cloud/files/Photo/14/test.jpg";
    photoInfoMap.insert(std::make_pair(1, photoInfo));
}

void CloneRestoreSelectionTest::SetupMockPhotoInfoMapMultiple(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    PhotoInfo photoInfo1;
    photoInfo1.fileIdNew = 101;
    photoInfo1.displayName = "test1.jpg";
    photoInfo1.cloudPath = "/storage/cloud/files/Photo/14/test1.jpg";
    photoInfoMap.insert(std::make_pair(1, photoInfo1));

    PhotoInfo photoInfo2;
    photoInfo2.fileIdNew = 102;
    photoInfo2.displayName = "test2.jpg";
    photoInfo2.cloudPath = "/storage/cloud/files/Photo/14/test2.jpg";
    photoInfoMap.insert(std::make_pair(2, photoInfo2));

    PhotoInfo photoInfo3;
    photoInfo3.fileIdNew = 103;
    photoInfo3.displayName = "test3.jpg";
    photoInfo3.cloudPath = "/storage/cloud/files/Photo/14/test3.jpg";
    photoInfoMap.insert(std::make_pair(3, photoInfo3));
}

void CloneRestoreSelectionTest::SetupMockPhotoInfoMapWithMissing(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    PhotoInfo photoInfo1;
    photoInfo1.fileIdNew = 101;
    photoInfo1.displayName = "test1.jpg";
    photoInfo1.cloudPath = "/storage/cloud/files/Photo/14/test1.jpg";
    photoInfoMap.insert(std::make_pair(1, photoInfo1));

    PhotoInfo photoInfo3;
    photoInfo3.fileIdNew = 103;
    photoInfo3.displayName = "test3.jpg";
    photoInfo3.cloudPath = "/storage/cloud/files/Photo/14/test3.jpg";
    photoInfoMap.insert(std::make_pair(3, photoInfo3));
}

void CloneRestoreSelectionTest::VerifySelectionRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM tab_analysis_selection";

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    int rowCount = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        rowCount++;
        int index;
        int fileId;
        int monthFlag;
        int yearFlag;
        std::string selectionVersion;
        int eventId;

        (void)resultSet->GetColumnIndex("file_id", index);
        resultSet->GetInt(index, fileId);

        (void)resultSet->GetColumnIndex("month_flag", index);
        resultSet->GetInt(index, monthFlag);

        (void)resultSet->GetColumnIndex("year_flag", index);
        resultSet->GetInt(index, yearFlag);

        (void)resultSet->GetColumnIndex("selection_version", index);
        resultSet->GetString(index, selectionVersion);

        (void)resultSet->GetColumnIndex("event_id", index);
        resultSet->GetInt(index, eventId);

        EXPECT_GT(fileId, 0);
        EXPECT_EQ(selectionVersion, "v1.0");
    }
    EXPECT_EQ(rowCount, 3);
}

void CloneRestoreSelectionTest::VerifyAtomEventRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM tab_analysis_atom_event";

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    int rowCount = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        rowCount++;
        int index;
        int eventId;
        int64_t minDate;
        int64_t maxDate;
        int count;
        int eventScore;
        std::string eventVersion;

        (void)resultSet->GetColumnIndex("event_id", index);
        resultSet->GetInt(index, eventId);

        (void)resultSet->GetColumnIndex("min_date", index);
        resultSet->GetLong(index, minDate);

        (void)resultSet->GetColumnIndex("max_date", index);
        resultSet->GetLong(index, maxDate);

        (void)resultSet->GetColumnIndex("count", index);
        resultSet->GetInt(index, count);

        (void)resultSet->GetColumnIndex("event_score", index);
        resultSet->GetInt(index, eventScore);

        (void)resultSet->GetColumnIndex("event_version", index);
        resultSet->GetString(index, eventVersion);

        EXPECT_GT(eventId, 0);
        EXPECT_GT(count, 0);
        EXPECT_EQ(eventVersion, "v1.0");
    }
    EXPECT_EQ(rowCount, 2);
}

void ClearCloneSource(CloneRestoreSelectionSource &cloneSource, const string &dbPath)
{
    cloneSource.cloneStorePtr_ = nullptr;
    NativeRdb::RdbHelper::DeleteRdbStore(dbPath);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_selection_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_selection_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->RestoreSelectionData();
    VerifySelectionRestore(newRdbStore->GetRaw());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_atom_event_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_atom_event_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_atom_event" };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->RestoreAtomEventData();
    VerifyAtomEventRestore(newRdbStore->GetRaw());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_preprocess_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_preprocess_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", "tab_analysis_atom_event", PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_selection (file_id INTEGER PRIMARY KEY, month_flag INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_atom_event (event_id INTEGER PRIMARY KEY, count INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->Preprocess();
    EXPECT_GT(cloneRestoreSelection->totalSelectionNumber_, 0);
    EXPECT_GT(cloneRestoreSelection->totalAtomEventNumber_, 0);
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_preprocess_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_preprocess_test_002");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_selection (file_id INTEGER PRIMARY KEY, month_flag INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_atom_event (event_id INTEGER PRIMARY KEY, count INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->Preprocess();
    EXPECT_EQ(cloneRestoreSelection->totalSelectionNumber_, 0);
    EXPECT_EQ(cloneRestoreSelection->totalAtomEventNumber_, 0);
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_cloud_satisfied_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_cloud_satisfied_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, true);
    cloneRestoreSelection->RestoreSelectionData();
    VerifySelectionRestore(newRdbStore->GetRaw());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_selection_with_missing_fileid_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_selection_with_missing_fileid_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapWithMissing(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->RestoreSelectionData();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_full_restore_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_full_restore_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", "tab_analysis_atom_event",
        "tab_analysis_total", PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_selection (file_id INTEGER PRIMARY KEY, month_flag INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_atom_event (event_id INTEGER PRIMARY KEY, count INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_total (file_id INTEGER PRIMARY KEY, selection INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->Restore();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_delete_existing_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_delete_existing_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", "tab_analysis_atom_event", PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_selection (file_id INTEGER PRIMARY KEY, month_flag INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_atom_event (event_id INTEGER PRIMARY KEY, count INTEGER)",
        "CREATE TABLE IF NOT EXISTS tab_analysis_total (file_id INTEGER PRIMARY KEY, selection INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->DeleteExistingSelectionInfos();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_clear_total_table_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_clear_total_table_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_total (file_id INTEGER PRIMARY KEY, selection INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->ClearTotalTableSelectionFields();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_clear_total_table_cloud_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_clear_total_table_cloud_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_total (file_id INTEGER PRIMARY KEY, selection INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, true);
    cloneRestoreSelection->ClearTotalTableSelectionFields();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_append_where_clause_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_append_where_clause_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    std::string whereClause;
    cloneRestoreSelection->AppendExtraWhereClause(whereClause);
    EXPECT_FALSE(whereClause.empty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_append_where_clause_cloud_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_append_where_clause_cloud_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, true);
    std::string whereClause;
    cloneRestoreSelection->AppendExtraWhereClause(whereClause);
    EXPECT_FALSE(whereClause.empty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_query_selection_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_query_selection_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_selection", PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->totalSelectionNumber_ = 3;
    std::vector<SelectionInfo> selectionInfos = cloneRestoreSelection->QuerySelectionTbl(0);
    EXPECT_FALSE(selectionInfos.empty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_query_atom_event_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_query_atom_event_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_atom_event" };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->totalAtomEventNumber_ = 2;
    std::vector<AtomEventInfo> atomEventInfos = cloneRestoreSelection->QueryAtomEventTbl(0);
    EXPECT_FALSE(atomEventInfos.empty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_batch_insert_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_insert_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMap(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);

    std::vector<SelectionInfo> selectionInfos;
    SelectionInfo info1;
    info1.fileId = 1;
    info1.monthFlag = 1;
    info1.yearFlag = 1;
    info1.selectionVersion = "v1.0";
    info1.eventId = 100;
    selectionInfos.push_back(info1);

    cloneRestoreSelection->BatchInsertSelectionData(selectionInfos);
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_batch_insert_empty_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_insert_empty_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);

    std::vector<SelectionInfo> selectionInfos;
    cloneRestoreSelection->BatchInsertSelectionData(selectionInfos);
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_create_values_bucket_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_create_values_bucket_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);

    SelectionInfo info;
    info.fileId = 1;
    info.monthFlag = 1;
    info.yearFlag = 1;
    info.selectionVersion = "v1.0";
    info.eventId = 100;

    NativeRdb::ValuesBucket values = cloneRestoreSelection->CreateValuesBucketFromSelectionInfo(info);
    EXPECT_FALSE(values.IsEmpty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_create_atom_event_values_bucket_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_create_atom_event_values_bucket_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);

    AtomEventInfo info;
    info.eventId = 100;
    info.minDate = 1501924205000;
    info.maxDate = 1501924206000;
    info.count = 5;
    info.dateDay = 20240304;
    info.dateMonth = 202403;
    info.dateType = 1;
    info.eventScore = 95;
    info.eventVersion = "v1.0";
    info.eventStatus = 1;

    NativeRdb::ValuesBucket values = cloneRestoreSelection->CreateValuesBucketFromAtomEventInfo(info);
    EXPECT_FALSE(values.IsEmpty());
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_batch_insert_atom_event_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_insert_atom_event_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);

    std::vector<AtomEventInfo> atomEventInfos;
    AtomEventInfo info1;
    info1.eventId = 100;
    info1.minDate = 1501924205000;
    info1.maxDate = 1501924206000;
    info1.count = 5;
    info1.dateDay = 20240304;
    info1.dateMonth = 202403;
    info1.dateType = 1;
    info1.eventScore = 95;
    info1.eventVersion = "v1.0";
    info1.eventStatus = 1;
    atomEventInfos.push_back(info1);

    cloneRestoreSelection->BatchInsertAtomEventData(atomEventInfos);
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_restore_analysis_total_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_restore_analysis_total_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { "tab_analysis_total", PhotoColumn::PHOTOS_TABLE };
    CreateTestTables(newRdbStore, {
        "CREATE TABLE IF NOT EXISTS tab_analysis_total (file_id INTEGER PRIMARY KEY, selection INTEGER)"
    });
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    SetupMockPhotoInfoMapMultiple(photoInfoMap);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, photoInfoMap, false);
    cloneRestoreSelection->RestoreAnalysisTotalSelectionStatus();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_null_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_null_db_test_001");
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", nullptr, nullptr, {}, false);
    cloneRestoreSelection->Preprocess();
    cloneRestoreSelection->Restore();
    cloneRestoreSelection = nullptr;
}

HWTEST_F(CloneRestoreSelectionTest, medialibrary_backup_clone_restore_no_data_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_no_data_test_001");
    CloneRestoreSelectionSource selectionSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(selectionSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreSelection = make_unique<CloneRestoreSelection>();
    cloneRestoreSelection->Init(CLONE_RESTORE_ID, "", newRdbStore->GetRaw(),
        selectionSource.cloneStorePtr_, {}, false);
    cloneRestoreSelection->totalSelectionNumber_ = 0;
    cloneRestoreSelection->totalAtomEventNumber_ = 0;
    cloneRestoreSelection->RestoreSelectionData();
    cloneRestoreSelection->RestoreAtomEventData();
    cloneRestoreSelection = nullptr;
    ClearCloneSource(selectionSource, TEST_BACKUP_DB_PATH);
}

}
}