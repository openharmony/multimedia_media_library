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
#define MLOG_TAG "CloneRestoreAnalysisDataTest"

#include "clone_restore_analysis_data_test.h"

#include "vision_column.h"
#include "vision_db_sqls.h"
#include "clone_restore_analysis_data.h"
#include "clone_restore_analysis_total.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "userfile_manager_types.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "backup_const.h"
#include "backup_database_utils.h"
#include "media_log.h"
#include "media_upgrade.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static const string TEST_BACKUP_PATH = "/data/test/backup/db";
static const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
static const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
static shared_ptr<MediaLibraryRdbStore> newRdbStore = nullptr;
static shared_ptr<MediaLibraryRdbStore> backupRdbStore = nullptr;
static unique_ptr<CloneRestoreAnalysisData> cloneRestoreAnalysisData = nullptr;

static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_TAB_ANALYSIS_TOTAL,
    CREATE_TAB_ANALYSIS_AESTHETICS_SCORE,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    ANALYSIS_TOTAL_TABLE,
    VISION_AESTHETICS_TABLE,
};

void CloneRestoreAnalysisDataTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisDataTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
    cloneRestoreAnalysisData = make_unique<CloneRestoreAnalysisData>();
}

void CloneRestoreAnalysisDataTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("CloneRestoreAnalysisDataTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    cloneRestoreAnalysisData = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void CloneRestoreAnalysisDataTest::SetUp()
{
    MEDIA_INFO_LOG("enter CloneRestoreAnalysisDataTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);
}

void CloneRestoreAnalysisDataTest::TearDown() {}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_Init_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_Init_001");
    int32_t sceneCode = 1001;
    std::string taskId = "test_task_001";
    std::string totalTableName = ANALYSIS_TOTAL_TABLE;

    cloneRestoreAnalysisData->Init(sceneCode, taskId, backupRdbStore, newRdbStore, totalTableName);

    EXPECT_EQ(cloneRestoreAnalysisData->sceneCode_, sceneCode);
    EXPECT_EQ(cloneRestoreAnalysisData->taskId_, taskId);
    EXPECT_EQ(cloneRestoreAnalysisData->mediaRdb_, backupRdbStore);
    EXPECT_EQ(cloneRestoreAnalysisData->mediaLibraryRdb_, newRdbStore);
    EXPECT_EQ(cloneRestoreAnalysisData->totalTableName_, totalTableName);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_Init_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetTableCommonColumns_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_GetTableCommonColumns_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    std::unordered_set<std::string> excludedColumns = {"id", "rowid"};
    std::unordered_map<std::string, std::string> result =
cloneRestoreAnalysisData->GetTableCommonColumns(excludedColumns);

    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_GetTableCommonColumns_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_BatchInsertWithRetry_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_BatchInsertWithRetry_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;
    int32_t errCode = cloneRestoreAnalysisData->BatchInsertWithRetry(VISION_AESTHETICS_TABLE, values, rowNum);

    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(rowNum, 0);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_BatchInsertWithRetry_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_RemoveDuplicateInfos_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_RemoveDuplicateInfos_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::unordered_set<int32_t> existingFileIds = {101, 102, 103};
    size_t originalSize = cloneRestoreAnalysisData->analysisDataInfos_.size();

    cloneRestoreAnalysisData->RemoveDuplicateInfos(existingFileIds);

    EXPECT_EQ(cloneRestoreAnalysisData->analysisDataInfos_.size(), originalSize);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_RemoveDuplicateInfos_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetExistingFileIds_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_GetExistingFileIds_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    std::unordered_set<int32_t> result = cloneRestoreAnalysisData->GetExistingFileIds();

    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_GetExistingFileIds_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_DeleteDuplicateInfos_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_DeleteDuplicateInfos_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    cloneRestoreAnalysisData->DeleteDuplicateInfos();

    EXPECT_TRUE(cloneRestoreAnalysisData->analysisDataInfos_.empty());
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_DeleteDuplicateInfos_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_InsertIntoAnalysisTable_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_InsertIntoAnalysisTable_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    cloneRestoreAnalysisData->InsertIntoAnalysisTable();

    EXPECT_TRUE(cloneRestoreAnalysisData->analysisDataInfos_.empty());
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_InsertIntoAnalysisTable_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_RestoreAnalysisDataMaps_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_RestoreAnalysisDataMaps_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    cloneRestoreAnalysisData->RestoreAnalysisDataMaps();

    EXPECT_TRUE(cloneRestoreAnalysisData->analysisDataInfos_.empty());
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_RestoreAnalysisDataMaps_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_ReportRestoreTaskOfTotal_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_ReportRestoreTaskOfTotal_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->analysisType_ = "aesthetics";
    cloneRestoreAnalysisData->restoreTimeCost_ = 1000;

    cloneRestoreAnalysisData->ReportRestoreTaskOfTotal();

    EXPECT_EQ(cloneRestoreAnalysisData->restoreTimeCost_, 1000);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_ReportRestoreTaskOfTotal_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_ReportRestoreTaskofData_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_ReportRestoreTaskofData_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->analysisType_ = "aesthetics";
    cloneRestoreAnalysisData->successCnt_ = 10;
    cloneRestoreAnalysisData->failCnt_ = 2;
    cloneRestoreAnalysisData->duplicateCnt_ = 1;
    cloneRestoreAnalysisData->maxId_ = 100;

    cloneRestoreAnalysisData->ReportRestoreTaskofData();

    EXPECT_EQ(cloneRestoreAnalysisData->successCnt_, 10);
    EXPECT_EQ(cloneRestoreAnalysisData->failCnt_, 2);
    EXPECT_EQ(cloneRestoreAnalysisData->duplicateCnt_, 1);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_ReportRestoreTaskofData_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_ReportAnalysisTableRestoreTask_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_ReportAnalysisTableRestoreTask_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->analysisType_ = "aesthetics";
    cloneRestoreAnalysisData->restoreTimeCost_ = 1000;
    cloneRestoreAnalysisData->successCnt_ = 10;
    cloneRestoreAnalysisData->failCnt_ = 2;
    cloneRestoreAnalysisData->duplicateCnt_ = 1;
    cloneRestoreAnalysisData->maxId_ = 100;

    cloneRestoreAnalysisData->ReportAnalysisTableRestoreTask();

    EXPECT_EQ(cloneRestoreAnalysisData->successCnt_, 10);
    EXPECT_EQ(cloneRestoreAnalysisData->failCnt_, 2);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_ReportAnalysisTableRestoreTask_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetMaxIds_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_GetMaxIds_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    cloneRestoreAnalysisData->GetMaxIds();

    EXPECT_EQ(cloneRestoreAnalysisData->maxId_, 0);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_GetMaxIds_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_CloneAnalysisData_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisData_CloneAnalysisData_001");
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::string table = VISION_AESTHETICS_TABLE;
    std::string type = "aesthetics";
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    std::unordered_set<std::string> excludedColumns = {"id", "rowid"};

    cloneRestoreAnalysisData->CloneAnalysisData(table, type, photoInfoMap, excludedColumns);

    EXPECT_EQ(cloneRestoreAnalysisData->totalCnt_, 0);
    EXPECT_EQ(cloneRestoreAnalysisData->successCnt_, 0);
    MEDIA_INFO_LOG("End CloneRestoreAnalysisData_CloneAnalysisData_001");
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_TYPE_INT32_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "INT"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, test_col) VALUES (1, 100)";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 1";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "INT");

    EXPECT_TRUE(info.columnValMap.find("test_col") != info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_TYPE_INT64_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "BIGINT"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, test_col) VALUES (2, 1000000)";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 2";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "BIGINT");

    EXPECT_TRUE(info.columnValMap.find("test_col") != info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_TYPE_DOUBLE_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "DOUBLE"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, test_col) VALUES (3, 99.5)";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 3";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "DOUBLE");

    EXPECT_TRUE(info.columnValMap.find("test_col") != info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_TYPE_BLOB_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "BLOB"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, test_col) VALUES (4, X'010203')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 4";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "BLOB");

    EXPECT_TRUE(info.columnValMap.find("test_col") != info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_TYPE_STRING_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "TEXT"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, test_col) VALUES (5, 'test_string')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 5";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "TEXT");

    EXPECT_TRUE(info.columnValMap.find("test_col") != info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_GetValFromResultSet_NULL_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;
    cloneRestoreAnalysisData->tableCommonColumns_ = {{"test_col", "INT"}};

    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id) VALUES (6)";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 6";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisDataInfo info;
    cloneRestoreAnalysisData->GetValFromResultSet(resultSet, info, "test_col", "INT");

    EXPECT_TRUE(info.columnValMap.find("test_col") == info.columnValMap.end());
    resultSet->Close();
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_PrepareCommonColumnVal_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    NativeRdb::ValuesBucket value;
    std::string columnName = "test_col";
    std::string columnType = "INT";
    std::variant<int32_t, int64_t, double, std::string, std::vector<uint8_t>> columnVal = 42;

    cloneRestoreAnalysisData->PrepareCommonColumnVal(value, columnName, columnType, columnVal);

    EXPECT_GT(value.GetSize(), 0);
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_PrepareCommonColumnVal_STRING_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    NativeRdb::ValuesBucket value;
    std::string columnName = "test_col";
    std::string columnType = "TEXT";
    std::variant<int32_t, int64_t, double, std::string, std::vector<uint8_t>> columnVal = std::string("hello");

    cloneRestoreAnalysisData->PrepareCommonColumnVal(value, columnName, columnType, columnVal);

    EXPECT_GT(value.GetSize(), 0);
}

HWTEST_F(CloneRestoreAnalysisDataTest, CloneRestoreAnalysisData_AnalysisDataRestoreBatch_001, TestSize.Level0)
{
    cloneRestoreAnalysisData->Init(1001, "test_task", backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);
    cloneRestoreAnalysisData->table_ = VISION_AESTHETICS_TABLE;

    std::unordered_map<int32_t, PhotoInfo> emptyPhotoInfoMap;
    cloneRestoreAnalysisData->photoInfoMap_ = emptyPhotoInfoMap;

    cloneRestoreAnalysisData->AnalysisDataRestoreBatch();

    EXPECT_TRUE(cloneRestoreAnalysisData->analysisDataInfos_.empty());
}
} // namespace Media
} // namespace OHOS
