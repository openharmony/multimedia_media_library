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
#define MLOG_TAG "BeautyScoreCloneTest"

#include "beauty_score_clone_test.h"

#include "vision_column.h"
#include "vision_db_sqls.h"
#include "beauty_score_clone.h"
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
static constexpr int32_t MOCK_FILE_ID_BEAUTY_SCORE_TEST = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
static const string TEST_BACKUP_PATH = "/data/test/backup/db";
static const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
static const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
static shared_ptr<MediaLibraryRdbStore> newRdbStore = nullptr;
static shared_ptr<MediaLibraryRdbStore> backupRdbStore = nullptr;
static unique_ptr<BeautyScoreClone> beautyScoreClone = nullptr;

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

void BeautyScoreCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start BeautyScoreCloneTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
}

void BeautyScoreCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("BeautyScoreCloneTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    beautyScoreClone = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void BeautyScoreCloneTest::SetUp()
{
    MEDIA_INFO_LOG("enter BeautyScoreCloneTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;

    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);
}

void BeautyScoreCloneTest::TearDown() {}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CloneBeautyScoreInBatches_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds;
    std::vector<std::string> commonColumns = {"file_id", "aesthetics_score"};

    bool result = beautyScoreClone->CloneBeautyScoreInBatches(oldFileIds, commonColumns);

    EXPECT_TRUE(result);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CloneBeautyScoreInBatches_SingleBatch_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds = {1};
    std::vector<std::string> commonColumns = {"file_id", "aesthetics_score"};

    bool result = beautyScoreClone->CloneBeautyScoreInBatches(oldFileIds, commonColumns);

    EXPECT_TRUE(result);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CloneBeautyScoreInBatches_MultipleBatches_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds;
    for (int i = 1; i <= 300; i++) {
        oldFileIds.push_back(i);
    }
    std::vector<std::string> commonColumns = {"file_id", "aesthetics_score"};

    bool result = beautyScoreClone->CloneBeautyScoreInBatches(oldFileIds, commonColumns);

    EXPECT_TRUE(result);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CloneBeautyScoreInfo_Empty_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> emptyPhotoInfoMap;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, emptyPhotoInfoMap, 0);

    bool result = beautyScoreClone->CloneBeautyScoreInfo();

    EXPECT_TRUE(result);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CloneBeautyScoreInfo_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, aesthetics_score) VALUES (1, 85)";
    newRdbStore->ExecuteSql(insertSql);

    bool result = beautyScoreClone->CloneBeautyScoreInfo();

    EXPECT_TRUE(result);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryBeautyScoreTbl_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, aesthetics_score) VALUES (1, 85)";
    newRdbStore->ExecuteSql(insertSql);

    std::string fileIdClause = "(1)";
    std::vector<std::string> commonColumns = {"file_id", "aesthetics_score"};

    std::vector<BeautyScoreTbl> result = beautyScoreClone->QueryBeautyScoreTbl(fileIdClause, commonColumns);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ParseBeautyScoreResultSet_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_AESTHETICS_TABLE + " (file_id, aesthetics_score) VALUES (1, 85)";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_AESTHETICS_TABLE + " WHERE file_id = 1";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    BeautyScoreTbl beautyScoreTbl;
    beautyScoreClone->ParseBeautyScoreResultSet(resultSet, beautyScoreTbl);

    EXPECT_TRUE(beautyScoreTbl.fileId.has_value());
    resultSet->Close();
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ProcessBeautyScoreTbls_Empty_001, TestSize.Level0)
{
    std::vector<BeautyScoreTbl> beautyScoreTbls;

    std::vector<BeautyScoreTbl> result = beautyScoreClone->ProcessBeautyScoreTbls(beautyScoreTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ProcessBeautyScoreTbls_Success_001, TestSize.Level0)
{
    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = 1;
    beautyScoreTbls.push_back(tbl);

    std::vector<BeautyScoreTbl> result = beautyScoreClone->ProcessBeautyScoreTbls(beautyScoreTbls);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ProcessBeautyScoreTbls_NotFound_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[2] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = 1;
    beautyScoreTbls.push_back(tbl);

    std::vector<BeautyScoreTbl> result = beautyScoreClone->ProcessBeautyScoreTbls(beautyScoreTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_BatchInsertBeautyScores_Empty_001, TestSize.Level0)
{
    std::vector<BeautyScoreTbl> beautyScoreTbls;

    beautyScoreClone->BatchInsertBeautyScores(beautyScoreTbls);

    EXPECT_EQ(beautyScoreClone->migrateScoreNum_, 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_BatchInsertBeautyScores_Filtered_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 200);

    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = 1;
    beautyScoreTbls.push_back(tbl);

    beautyScoreClone->BatchInsertBeautyScores(beautyScoreTbls);

    EXPECT_EQ(beautyScoreClone->migrateScoreNum_, 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_BatchInsertBeautyScores_Success_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = 1;
    tbl.aestheticsScore = 85;
    beautyScoreTbls.push_back(tbl);

    beautyScoreClone->BatchInsertBeautyScores(beautyScoreTbls);

    EXPECT_EQ(beautyScoreClone->migrateScoreNum_, 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CreateValuesBucketFromBeautyScoreTbl_001, TestSize.Level0)
{
    BeautyScoreTbl beautyScoreTbl;
    beautyScoreTbl.fileId = 1;
    beautyScoreTbl.aestheticsScore = 85;

    NativeRdb::ValuesBucket result = beautyScoreClone->CreateValuesBucketFromBeautyScoreTbl(beautyScoreTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_BatchInsertWithRetry_Empty_001, TestSize.Level0)
{
    std::vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;

    int32_t result = beautyScoreClone->BatchInsertWithRetry(VISION_AESTHETICS_TABLE, values, rowNum);

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateTotalTblBeautyScoreStatus_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> newFileIds;

    beautyScoreClone->UpdateTotalTblBeautyScoreStatus(newRdbStore, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateTotalTblBeautyScoreStatus_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE +
        " (file_id, aesthetics) VALUES (MOCK_FILE_ID_BEAUTY_SCORE_TEST, 0)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> newFileIds = {MOCK_FILE_ID_BEAUTY_SCORE_TEST};

    beautyScoreClone->UpdateTotalTblBeautyScoreStatus(newRdbStore, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateTotalTblBeautyScoreAllStatus_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> newFileIds;

    beautyScoreClone->UpdateTotalTblBeautyScoreAllStatus(newRdbStore, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateTotalTblBeautyScoreAllStatus_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE +
        " (file_id, aesthetics_all) VALUES (MOCK_FILE_ID_BEAUTY_SCORE_TEST, 0)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> newFileIds = {MOCK_FILE_ID_BEAUTY_SCORE_TEST};

    beautyScoreClone->UpdateTotalTblBeautyScoreAllStatus(newRdbStore, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryBeautyScoreMap_NullRdbStore_001, TestSize.Level0)
{
    std::string sql = "SELECT file_id, aesthetics FROM " + ANALYSIS_TOTAL_TABLE;

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryBeautyScoreMap(nullptr, sql, "file_id",
"aesthetics");

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryBeautyScoreMap_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, 85)";
    newRdbStore->ExecuteSql(insertSql);

    std::string sql = "SELECT file_id, aesthetics FROM " + ANALYSIS_TOTAL_TABLE;

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryBeautyScoreMap(newRdbStore, sql, "file_id",
"aesthetics");

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryScoresForColumnInBatches_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> fileIdOld;

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryScoresForColumnInBatches(newRdbStore,
fileIdOld, "aesthetics");

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryScoresForColumnInBatches_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> fileIdOld = {1};

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryScoresForColumnInBatches(newRdbStore,
fileIdOld, "aesthetics");

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ApplyScoreUpdatesToNewDb_Empty_001, TestSize.Level0)
{
    std::unordered_map<int32_t, int32_t> oldFileIdToScoreMap;

    beautyScoreClone->ApplyScoreUpdatesToNewDb(newRdbStore, oldFileIdToScoreMap, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ApplyScoreUpdatesToNewDb_Success_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::unordered_map<int32_t, int32_t> oldFileIdToScoreMap;
    oldFileIdToScoreMap[1] = 85;

    beautyScoreClone->ApplyScoreUpdatesToNewDb(newRdbStore, oldFileIdToScoreMap, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblForScoreColumn_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> fileIdOld;

    beautyScoreClone->UpdateAnalysisTotalTblForScoreColumn(newRdbStore, backupRdbStore, fileIdOld, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblForScoreColumn_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> fileIdOld = {1};

    beautyScoreClone->UpdateAnalysisTotalTblForScoreColumn(newRdbStore, backupRdbStore, fileIdOld, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblBeautyScore_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> fileIdNew;
    std::vector<int32_t> fileIdOld;

    beautyScoreClone->UpdateAnalysisTotalTblBeautyScore(newRdbStore, backupRdbStore, fileIdNew, fileIdOld);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreCloneUpdateAnalysisTotalTblBeautyScore_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> fileIdNew = {MOCK_FILE_ID_BEAUTY_SCORE_TEST};
    std::vector<int32_t> fileIdOld = {1};

    beautyScoreClone->UpdateAnalysisTotalTblBeautyScore(newRdbStore, backupRdbStore, fileIdNew, fileIdOld);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblBeautyScoreAll_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> fileIdNew;
    std::vector<int32_t> fileIdOld;

    beautyScoreClone->UpdateAnalysisTotalTblBeautyScoreAll(newRdbStore, backupRdbStore, fileIdNew, fileIdOld);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ProcessBeautyScoreTbls_NoFileId_001, TestSize.Level0)
{
    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = std::nullopt;
    beautyScoreTbls.push_back(tbl);

    std::vector<BeautyScoreTbl> result = beautyScoreClone->ProcessBeautyScoreTbls(beautyScoreTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ProcessBeautyScoreTbls_HasBlobValue_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<BeautyScoreTbl> beautyScoreTbls;
    BeautyScoreTbl tbl;
    tbl.fileId = 1;
    tbl.aestheticsScore = 85;
    tbl.features = std::vector<uint8_t>{1, 2, 3};
    beautyScoreTbls.push_back(tbl);

    std::vector<BeautyScoreTbl> result = beautyScoreClone->ProcessBeautyScoreTbls(beautyScoreTbls);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CreateValuesBucketFromBeautyScoreTbl_AllFields_001, TestSize.Level0)
{
    BeautyScoreTbl beautyScoreTbl;
    beautyScoreTbl.fileId = 1;
    beautyScoreTbl.aestheticsScore = 85;
    beautyScoreTbl.aestheticsVersion = "1.0";
    beautyScoreTbl.prob = 0.95;
    beautyScoreTbl.analysisVersion = "2.0";
    beautyScoreTbl.selectedFlag = 1;
    beautyScoreTbl.selectedAlgoVersion = "1.0";
    beautyScoreTbl.selectedStatus = 1;
    beautyScoreTbl.negativeFlag = 0;
    beautyScoreTbl.negativeAlgoVersion = "1.0";
    beautyScoreTbl.aestheticsAllVersion = "1.0";
    beautyScoreTbl.aestheticsScoreAll = 90;
    beautyScoreTbl.isFilteredHard = 0;
    beautyScoreTbl.clarityScoreAll = 0.85;
    beautyScoreTbl.saturationScoreAll = 0.75;
    beautyScoreTbl.luminanceScoreAll = 0.65;
    beautyScoreTbl.semanticsScore = 0.80;
    beautyScoreTbl.isBlackWhiteStripe = 0;
    beautyScoreTbl.isBlurry = 0;
    beautyScoreTbl.isMosaic = 0;

    NativeRdb::ValuesBucket result = = beautyScoreClone->CreateValuesBucketFromBeautyScoreTbl(beautyScoreTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_CreateValuesBucketFromBeautyScoreTbl_OptionalFields_001,
TestSize.Level0)
{
    BeautyScoreTbl beautyScoreTbl;
    beautyScoreTbl.fileId = 1;
    beautyScoreTbl.aestheticsScore = std::nullopt;
    beautyScoreTbl.aestheticsVersion = std::nullopt;
    beautyScoreTbl.prob = std::nullopt;
    beautyScoreTbl.analysisVersion = std::nullopt;
    beautyScoreTbl.selectedFlag = std::nullopt;
    beautyScoreTbl.selectedAlgoVersion = std::nullopt;
    beautyScoreTbl.selectedStatus = std::nullopt;
    beautyScoreTbl.negativeFlag = std::nullopt;
    beautyScoreTbl.negativeAlgoVersion = std::nullopt;
    beautyScoreTbl.aestheticsAllVersion = std::nullopt;
    beautyScoreTbl.aestheticsScoreAll = std::nullopt;
    beautyScoreTbl.isFilteredHard = std::nullopt;
    beautyScoreTbl.clarityScoreAll = std::nullopt;
    beautyScoreTbl.saturationScoreAll = std::nullopt;
    beautyScoreTbl.luminanceScoreAll = std::nullopt;
    beautyScoreTbl.semanticsScore = std::nullopt;
    beautyScoreTbl.isBlackWhiteStripe = std::nullopt;
    beautyScoreTbl.isBlurry = std::nullopt;
    beautyScoreTbl.isMosaic = std::nullopt;

    NativeRdb::ValuesBucket result = beautyScoreClone->CreateValuesBucketFromBeautyScoreTbl(beautyScoreTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_BatchInsertWithRetry_SingleValue_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("file_id", 1);
    value.PutInt("aesthetics_score", 85);
    values.push_back(value);
    int64_t rowNum = 0;

    int32_t result = beautyScoreClone->BatchInsertWithRetry(VISION_AESTHETICS_TABLE, values, rowNum);

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryBeautyScoreMap_NullResultSet_001, TestSize.Level0)
{
    std::string sql = "SELECT file_id, aesthetics FROM " + ANALYSIS_TOTAL_TABLE + " WHERE 1=0";

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryBeautyScoreMap(newRdbStore, sql, "file_id",
"aesthetics");

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryBeautyScoreMap_InvalidColumn_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, 85)";
    newRdbStore->ExecuteSql(insertSql);

    std::string sql = "SELECT file_id, aesthetics FROM " + ANALYSIS_TOTAL_TABLE;

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryBeautyScoreMap(newRdbStore, sql,
"invalid_column", "aesthetics");

    EXPECT_TRUE(result.empty());
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_QueryScoresForColumnInBatches_MultipleBatches_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1), (2, -2), (3,
-3)";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> fileIdOld = {1, 2, 3};

    std::unordered_map<int32_t, int32_t> result = beautyScoreClone->QueryScoresForColumnInBatches(newRdbStore,
fileIdOld, "aesthetics");

    EXPECT_EQ(result.size(), 3);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_ApplyScoreUpdatesToNewDb_NotFound_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[2] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::unordered_map<nt32_t, int32_t> oldFileIdToScoreMap;
    oldFileIdToScoreMap[1] = 85;

    beautyScoreClone->ApplyScoreUpdatesToNewDb(newRdbStore, oldFileIdToScoreMap, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblForScoreColumn_EmptyMap_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<int32_t> fileIdOld;

    beautyScoreClone->UpdateAnalysisTotalTblForScoreColumn(newRdbStore, backupRdbStore, fileIdOld, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblForScoreColumn_NotFound_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[2] = photoInfo;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<int32_t> fileIdOld = {1};

    beautyScoreClone->UpdateAnalysisTotalTblForScoreColumn(newRdbStore, backupRdbStore, fileIdOld, "aesthetics");

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblBeautyScore_MultipleFiles_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1), (2, -2)";
    newRdbStore->->ExecuteSql(insertSql);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo1;
    photoInfo1.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo1;
    PhotoInfo photoInfo2;
    photoInfo2.fileIdNew = 102;
    photoInfoMap[2] = photoInfo2;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<int32_t> fileIdNew = {MOCK_FILE_ID_BEAUTY_SCORE_TEST, 102};
    std::vector<int32_t> fileIdOld = {1, 2};

    beautyScoreClone->UpdateAnalysisTotalTblBeautyScore(newRdbStore, backupRdbStore, fileIdNew, fileIdOld);

    EXPECT_TRUE(true);
}

HWTEST_F(BeautyScoreCloneTest, BeautyScoreClone_UpdateAnalysisTotalTblBeautyScoreAll_MultipleFiles_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics_all) VALUES (1, -1), (2,
-2)";
    newRdbStore->ExecuteSql(insertSql);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo1;
    photoInfo1.fileIdNew = MOCK_FILE_ID_BEAUTY_SCORE_TEST;
    photoInfoMap[1] = photoInfo1;
    PhotoInfo photoInfo2;
    photoInfo2.fileIdNew = 102;
    photoInfoMap[2] = photoInfo2;
    beautyScoreClone = make_unique<BeautyScoreClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<int32_t> fileIdNew = {MOCK_FILE_ID_BEAUTY_SCORE_TEST, 102};
    std::vector<int32_t> fileIdOld = {1, 2};

    beautyScoreClone->UpdateAnalysisTotalTblBeautyScoreAll(newRdbStore, backupRdbStore, fileIdNew, fileIdOld);

    EXPECT_TRUE(true);
}
} // namespace Media
} // namespace OHOS
