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
#define MLOG_TAG "CloneRestoreAnalysisTotalTest"

#include "clone_restore_analysis_total_test.h"

#include "vision_column.h"
#include "vision_db_sqls.h"
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
static unique_ptr<CloneRestoreAnalysisTotal> cloneRestoreAnalysisTotal = nullptr;

static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_TAB_ANALYSIS_TOTAL,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    ANALYSIS_TOTAL_TABLE,
};

void CloneRestoreAnalysisTotalTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start CloneRestoreAnalysisTotalTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
    cloneRestoreAnalysisTotal = make_unique<CloneRestoreAnalysisTotal>();
}

void CloneRestoreAnalysisTotalTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("CloneRestoreAnalysisTotalTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    cloneRestoreAnalysisTotal = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void CloneRestoreAnalysisTotalTest::SetUp()
{
    MEDIA_INFO_LOG("enter CloneRestoreAnalysisTotalTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);
}

void CloneRestoreAnalysisTotalTest::TearDown() {}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_Init_001, TestSize.Level0)
{
    std::string type = "aesthetics";
    int32_t pageSize = 200;
    std::string totalTableName = ANALYSIS_TOTAL_TABLE;

    cloneRestoreAnalysisTotal->Init(type, pageSize, backupRdbStore, newRdbStore, totalTableName);

    EXPECT_EQ(cloneRestoreAnalysisTotal->type_, type);
    EXPECT_EQ(cloneRestoreAnalysisTotal->pageSize_, pageSize);
    EXPECT_EQ(cloneRestoreAnalysisTotal->mediaRdb_, backupRdbStore);
    EXPECT_EQ(cloneRestoreAnalysisTotal->mediaLibraryRdb_, newRdbStore);
    EXPECT_EQ(cloneRestoreAnalysisTotal->totalTableName_, totalTableName);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetTotalNumber_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    int32_t result = cloneRestoreAnalysisTotal->GetTotalNumber();

    EXPECT_EQ(result, 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetInfos_Success_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, 1)";
    newRdbStore->ExecuteSql(insertSql);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = 101;
    photoInfoMap[1] = photoInfo;

    cloneRestoreAnalysisTotal->GetInfos(photoInfoMap);

    EXPECT_GT(cloneRestoreAnalysisTotal->analysisTotalInfos_.size(), 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetInfos_EmptyPhotoInfoMap_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (2, 1)";
    newRdbStore->ExecuteSql(insertSql);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    photoInfoMap.clear();

    cloneRestoreAnalysisTotal->GetInfos(photoInfoMap);

    EXPECT_EQ(cloneRestoreAnalysisTotal->analysisTotalInfos_.size(), 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_SetPlaceHoldersAndParamsByFileIdOld_001,
TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    std::string placeHolders;
    std::vector<NativeRdb::ValueObject> params;

    cloneRestoreAnalysisTotal->SetPlaceHoldersAndParamsByFileIdOld(placeHolders, params);

    EXPECT_GT(placeHolders.length(), 0);
    EXPECT_EQ(params.size(), 2);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_SetPlaceHoldersAndParamsByFileIdOld_ZeroFileId_001,
TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 0;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    std::string placeHolders;
    std::vector<NativeRdb::ValueObject> params;

    cloneRestoreAnalysisTotal->SetPlaceHoldersAndParamsByFileIdOld(placeHolders, params);

    EXPECT_GT(placeHolders.length(), 0);
    EXPECT_EQ(params.size(), 1);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_SetPlaceHoldersAndParamsByFileIdNew_001,
TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    std::string placeHolders;
    std::vector<NativeRdb::ValueObject> params;

    cloneRestoreAnalysisTotal->SetPlaceHoldersAndParamsByFileIdNew(placeHolders, params);

    EXPECT_GT(placeHolders.length(), 0);
    EXPECT_EQ(params.size(), 2);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_FindIndexByFileIdOld_Found_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    size_t index = cloneRestoreAnalysisTotal->FindIndexByFileIdOld(1);

    EXPECT_EQ(index, 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_FindIndexByFileIdOld_NotFound_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    size_t index = cloneRestoreAnalysisTotal->FindIndexByFileIdOld(999);

    EXPECT_EQ(index, std::string::npos);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetFileIdNewByIndex_Valid_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    int32_t fileIdNew = cloneRestoreAnalysisTotal->GetFileIdNewByIndex(0);

    EXPECT_EQ(fileIdNew, 101);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetFileIdNewByIndex_Invalid_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    int32_t fileIdNew = cloneRestoreAnalysisTotal->GetFileIdNewByIndex(999);

    EXPECT_EQ(fileIdNew, -1);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_UpdateRestoreStatusAsDuplicateByIndex_001,
TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    cloneRestoreAnalysisTotal->UpdateRestoreStatusAsDuplicateByIndex(0);

    EXPECT_EQ(cloneRestoreAnalysisTotal->duplicateCnt_, 1);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_UpdateRestoreStatusAsFailed_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 1;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    cloneRestoreAnalysisTotal->UpdateRestoreStatusAsFailed();

    EXPECT_EQ(cloneRestoreAnalysisTotal->failedCnt_, 2);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetStatusFileIdsMap_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    info1.restoreStatus = RestoreStatus::SUCCESS;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    AnalysisTotalInfo info2;
    info2.fileIdOld = 2;
    info2.fileIdNew = 102;
    info2.status = 2;
    info2.restoreStatus = RestoreStatus::SUCCESS;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info2);

    std::unordered_map<int32_t, std::vector<std::string>> result = cloneRestoreAnalysisTotal->GetStatusFileIdsMap();

    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetStatusFileIdsMap_NotSuccess_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 101;
    info1.status = 1;
    info1.restoreStatus = RestoreStatus::FAILED;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    std::unordered_map<int32_t, std::vector<std::string>> result = cloneRestoreAnalysisTotal->GetStatusFileIdsMap();

    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_UpdateDatabaseByStatus_Empty_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::vector<std::string> fileIds;

    int32_t result = cloneRestoreAnalysisTotal->UpdateDatabaseByStatus(1, fileIds);

    EXPECT_EQ(result, 0);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_UpdateDatabase_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::string insertSql = "INSERT INTO " + ANALYSIS_TOTAL_TABLE + " (file_id, aesthetics) VALUES (1, -1)";
    newRdbStore->ExecuteSql(insertSql);

    AnalysisTotalInfo info1;
    info1.fileIdOld = 1;
    info1.fileIdNew = 1;
    info1.status = 1;
    info1.restoreStatus = RestoreStatus::SUCCESS;
    cloneRestoreAnalysisTotal->analysisTotalInfos_.push_back(info1);

    cloneRestoreAnalysisTotal->UpdateDatabase();

    EXPECT_EQ(cloneRestoreAnalysisTotal->successCnt_, 1);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_SetRestoreTaskInfo_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    cloneRestoreAnalysisTotal->successCnt_ = 10;
    cloneRestoreAnalysisTotal->failedCnt_ = 2;
    cloneRestoreAnalysisTotal->duplicateCnt_ = 1;

    RestoreTaskInfo info;
    cloneRestoreAnalysisTotal->SetRestoreTaskInfo(info);

    EXPECT_EQ(info.successCount, 10);
    EXPECT_EQ(info.failedCount, 2);
    EXPECT_EQ(info.duplicateCount, 1);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_AddSuccessVideoFileIds_Empty_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    cloneRestoreAnalysisTotal->AddSuccessVideoFileIds();

    EXPECT_TRUE(cloneRestoreAnalysisTotal->successVideoFileIds_.empty());
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_GetSuccessVideoFileIds_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    cloneRestoreAnalysisTotal->successVideoFileIds_.push_back(101);
    cloneRestoreAnalysisTotal->successVideoFileIds_.push_back(102);

    std::vector<int32_t> result = cloneRestoreAnalysisTotal->GetSuccessVideoFileIds();

    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(CloneRestoreAnalysisTotalTest, CloneRestoreAnalysisTotal_QueryBeautyScoreMap_NullRdbStore_001, TestSize.Level0)
{
    cloneRestoreAnalysisTotal->Init("aesthetics", 200, backupRdbStore, newRdbStore, ANALYSIS_TOTAL_TABLE);

    std::string sql = "SELECT file_id, aesthetics FROM " + ANALYSIS_TOTAL_TABLE;
    std::unordered_map<int32_t, int32_t> result = cloneRestoreAnalysisTotal->QueryBeautyScoreMap(nullptr, sql,
"file_id", "aesthetics");

    EXPECT_TRUE(result.empty());
}
} // namespace Media
} // namespace OHOS
