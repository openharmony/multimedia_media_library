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
#define MLOG_TAG "SearchIndexCloneTest"

#include "search_index_clone_test.h"

#include "vision_column.h"
#include "vision_db_sqls.h"
#include "search_index_clone.h"
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
static constexpr int32_t MOCK_FILE_ID_SEARCH_INDEX_TEST = MOCK_FILE_ID_SEARCH_INDEX_TEST;
static const string TEST_BACKUP_PATH = "/data/test/backup/db";
static const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
static const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
static shared_ptr<MediaLibraryRdbStore> newRdbStore = nullptr;
static shared_ptr<MediaLibraryRdbStore> backupRdbStore = nullptr;
static unique_ptr<SearchIndexClone> searchIndexClone = nullptr;

static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_TAB_ANALYSIS_SEARCH_INDEX,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    ANALYSIS_SEARCH_INDEX_TABLE,
};

void SearchIndexCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start SearchIndexCloneTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
}

void SearchIndexCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("SearchIndexCloneTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    searchIndexClone = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void SearchIndexCloneTest::SetUp()
{
    MEDIA_INFO_LOG("enter SearchIndexCloneTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[1] = photoInfo;

    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);
}

void SearchIndexCloneTest::TearDown() {}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_Clone_Empty_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> emptyPhotoInfoMap;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, emptyPhotoInfoMap, 0);

    bool result = searchIndexClone->Clone();

    EXPECT_TRUE(result);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_Clone_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data) VALUES (1, 'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    bool result = searchIndexClone->Clone();

    EXPECT_TRUE(result);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_Empty_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_Success_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    searchIndexTbls.push_back(tbl);

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_NotFound_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[2] = photoInfo;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 0);

    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    searchIndexTbls.push_back(tbl);

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_QueryAnalysisSearchIndexTbl_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data) VALUES (1, 'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::string fileIdClause = "(1)";
    std::vector<std::string> commonColumns = {"file_id", "data"};

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->QueryAnalysisSearchIndexTbl(fileIdClause,
commonColumns);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ParseAnalysisSearchIndexResultSet_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data) VALUES (1, 'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + ANALYSIS_SEARCH_INDEX_TABLE + " WHERE file_id = 1";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisSearchIndexTbl analysisSearchIndexTbl;
    searchIndexClone->ParseAnalysisSearchIndexResultSet(resultSet, analysisSearchIndexTbl);

    EXPECT_TRUE(analysisSearchIndexTbl.fileId.has_value());
    resultSet->Close();
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertAnalysisSearchIndex_Empty_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;

    searchIndexClone->InsertAnalysisSearchIndex(analysisSearchIndexTbl);

    EXPECT_EQ(searchIndexClone->migratedCount_, 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertAnalysisSearchIndex_Success_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    analysisSearchIndexTbl.push_back(tbl);

    searchIndexClone->InsertAnalysisSearchIndex(analysisSearchIndexTbl);

    EXPECT_EQ(searchIndexClone->migratedCount_, 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_QueryExistingIdsWithStrategy_001, TestSize.Level0)
{
    std::vector<int32_t> fileIds = {1};

    auto [protectedIds, overrideIds] = searchIndexClone->QueryExistingIdsWithStrategy(fileIds);

    EXPECT_TRUE(protectedIds.empty());
    EXPECT_TRUE(overrideIds.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ExecuteIdQuery_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data) VALUES (1, 'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT file_id FROM " + ANALYSIS_SEARCH_INDEX_TABLE + " WHERE file_id = 1";

    std::unordered_set<int32_t> result = searchIndexClone->ExecuteIdQuery(querySql);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ExecuteIdQuery_Empty_001, TestSize.Level0)
{
    std::string querySql = "SELECT file_id FROM " + ANALYSIS_SEARCH_INDEX_TABLE + " WHERE file_id = 999";

    std::unordered_set<int32_t> result = searchIndexClone->ExecuteIdQuery(querySql);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_DeleteOverrideRecords_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> fileIds;

    searchIndexClone->DeleteOverrideRecords(fileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_DeleteOverrideRecords_Success_001, TestSize.Level0)
{
    std::vector<int32_t> fileIds = {1};

    searchIndexClone->DeleteOverrideRecords(fileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertSearchIndexByTable_Empty_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;

    int32_t result = searchIndexClone->InsertSearchIndexByTable(analysisSearchIndexTbl);

    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertSearchIndexByTable_Success_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    analysisSearchIndexTbl.push_back(tbl);

    int32_t result = searchIndexClone->InsertSearchIndexByTable(analysisSearchIndexTbl);

    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_GetInsertSearchIndexValues_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    analysisSearchIndexTbl.push_back(tbl);

    std::vector<NativeRdb::ValuesBucket> result = searchIndexClone->GetInsertSearchIndexValues(analysisSearchIndexTbl);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_GetInsertSearchIndexValue_001, TestSize.Level0)
{
    AnalysisSearchIndexTbl analysisSearchIndexTbl;
    analysisSearchIndexTbl.fileId = 1;
    analysisSearchIndexTbl.data = "test_data";

    NativeRdb::ValuesBucket result = searchIndexClone->GetInsertSearchIndexValue(analysisSearchIndexTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_BatchInsertWithRetry_Empty_001, TestSize.Level0)
{
    std::vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;

    int32_t result = searchIndexClone->BatchInsertWithRetry(ANALYSIS_SEARCH_INDEX_TABLE, values, rowNum);

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_NoFileId_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = std::nullopt;
    searchIndexTbls.push_back(tbl);

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_ProtectedId_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[1] = photoInfo;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 100);

    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (50, 1,
'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    searchIndexTbls.push_back(tbl);

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ProcessSearchIndexTbls_OverrideId_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[1] = photoInfo;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 50);

    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (150, 1,
'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<AnalysisSearchIndexTbl> searchIndexTbls;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    searchIndexTbls.push_back(tbl);

    std::vector<AnalysisSearchIndexTbl> result = searchIndexClone->ProcessSearchIndexTbls(searchIndexTbls);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ParseAnalysisSearchIndexResultSet_AllFields_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data, display_name, latitude,
longitude, date_modified, version, system_language) VALUES (1, 'test_data', 'test.jpg', 39.9, 116.4, 1234567890, 1,
'en')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + ANALYSIS_SEARCH_INDEX_TABLE + " WHERE file_id = 1";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    AnalysisSearchIndexTbl analysisSearchIndexTbl;
    searchIndexClone->ParseAnalysisSearchIndexResultSet(resultSet, analysisSearchIndexTbl);

    EXPECT_TRUE(analysisSearchIndexTbl.fileId.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.data.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.displayName.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.latitude.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.longitude.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.dateModified.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.version.has_value());
    EXPECT_TRUE(analysisSearchIndexTbl.systemLanguage.has_value());
    resultSet->Close();
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertAnalysisSearchIndex_ProtectedId_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[1] = photoInfo;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 100);

    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (50, 1,
'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    analysisSearchIndexTbl.push_back(tbl);

    searchIndexClone->InsertAnalysisSearchIndex(analysisSearchIndexTbl);

    EXPECT_EQ(searchIndexClone->migratedCount_, 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertAnalysisSearchIndex_OverrideId_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_SEARCH_INDEX_TEST;
    photoInfoMap[1] = photoInfo;
    searchIndexClone = make_unique<SearchIndexClone>(backupRdbStore, newRdbStore, photoInfoMap, 50);

    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (150, 1,
'test_data')";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl;
    tbl.fileId = 1;
    tbl.data = "test_data";
    analysisSearchIndexTbl.push_back(tbl);

    searchIndexClone->InsertAnalysisSearchIndex(analysisSearchIndexTbl);

    EXPECT_EQ(searchIndexClone->migratedCount_, 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_QueryExistingIdsWithStrategy_MultipleIds_001, TestSize.Level0)
{
    std::string insertSql1 = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (50, 1,
'test_data1')";
    newRdbStore->ExecuteSql(insertSql1);
    std::string insertSql2 = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (150, 2,
'test_data2')";
    newRdbStore->ExecuteSql(insertSql2);

    std::vector<int32_t> fileIds = {1, 2};

    auto [protectedIds, overrideIds] = searchIndexClone->QueryExistingIdsWithStrategy(fileIds);

    EXPECT_EQ(protectedIds.size(), 1);
    EXPECT_EQ(overrideIds.size(), 1);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_ExecuteIdQuery_MultipleRows_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (file_id, data) VALUES (1, 'test_data1'),
(2, 'test_data2')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT file_id FROM " + ANALYSIS_SEARCH_INDEX_TABLE + " WHERE file_id IN (1, 2)";

    std::unordered_set<int32_t> result = searchIndexClone->ExecuteIdQuery(querySql);

    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_DeleteOverrideRecords_MultipleIds_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + ANALYSIS_SEARCH_INDEX_TABLE + " (id, file_id, data) VALUES (150, 1,
'test_data1'), (151, 2, 'test_data2')";
    newRdbStore->ExecuteSql(insertSql);

    std::vector<int32_t> fileIds = {1, 2};

    searchIndexClone->DeleteOverrideRecords(fileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_InsertSearchIndexByTable_MultipleValues_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl1;
    tbl1.fileId = 1;
    tbl1.data = "test_data1";
    analysisSearchIndexTbl.push_back(tbl1);
    AnalysisSearchIndexTbl tbl2;
    tbl2.fileId = 2;
    tbl2.data = "test_data2";
    analysisSearchIndexTbl.push_back(tbl2);

    int32_t result = searchIndexClone->InsertSearchIndexByTable(analysisSearchIndexTbl);

    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_GetInsertSearchIndexValues_Multiple_001, TestSize.Level0)
{
    std::vector<AnalysisSearchIndexTbl> analysisSearchIndexTbl;
    AnalysisSearchIndexTbl tbl1;
    tbl1.fileId = 1;
    tbl1.data = "test_data1";
    analysisSearchIndexTbl.push_back(tbl1);
    AnalysisSearchIndexTbl tbl2;
    tbl2.fileId = 2;
    tbl2.data = "test_data2";
    analysisSearchIndexTbl.push_back(tbl2);

    std::vector<NativeRdb::ValuesBucket> result = searchIndexClone->GetInsertSearchIndexValues(analysisSearchIndexTbl);

    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_GetInsertSearchIndexValue_AllFields_WithDefaults_001, TestSize.Level0)
{
    AnalysisSearchIndexTbl analysisSearchIndexTbl;
    analysisSearchIndexTbl.fileId = 1;
    analysisSearchIndexTbl.data = "test_data";
    analysisSearchIndexTbl.displayName = "test.jpg";
    analysisSearchIndexTbl.latitude = 39.9;
    analysisSearchIndexTbl.longitude = 116.4;
    analysisSearchIndexTbl.dateModified = 1234567890;
    analysisSearchIndexTbl.version = 1;
    analysisSearchIndexTbl.systemLanguage = "en";

    NativeRdb::ValuesBucket result = searchIndexClone->GetInsertSearchIndexValue(analysisSearchIndexTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(SearchIndexCloneTest, SearchIndexClone_BatchInsertWithRetry_MultipleValues_001, TestSize.Level0)
{
    std::vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value1;
    value1.PutInt("file_id", 1);
    value1.PutString("data", "test_data1");
    values.push_back(value1);
    NativeRdb::ValuesBucket value2;
    value2.PutInt("file_id", 2);
    value2.PutString("data", "test_data2");
    values.push_back(value2);
    int64_t rowNum = 0;

    int32_t result = searchIndexClone->BatchInsertWithRetry(ANALYSIS_SEARCH_INDEX_TABLE, values, rowNum);

    EXPECT_EQ(result, E_OK);
}
} // namespace Media
} // namespace OHOS
