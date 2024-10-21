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

#define MLOG_TAG "BackupCloneTest"

#include "medialibrary_backup_clone_test.h"

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "clone_source.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_column.h"
#include "media_log.h"
#include "media_file_utils.h"
#define private public
#define protected public
#include "backup_restore_service.h"
#include "base_restore.h"
#include "clone_restore.h"
#undef private
#undef protected
#include "burst_key_generator.h"
#include "backup_const.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
enum class TestAlbumType {
    SOURCE = 0,
    USER,
    SHOOTING_MODE_PORTRAIT,
};
string TEST_BACKUP_PATH = "/data/test/backup/db";
string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
string TEST_FAKE_FILE_DIR = "/fake/fake/fake.fake";
const string SHOOTING_MODE_PORTRAIT_ALBUM_NAME = "1";
const string WHERE_CLAUSE_SHOOTING_MODE = "shooting_mode = '1'";
const string WHERE_CLAUSE_TRASHED = "date_trashed > 0";
const string WHERE_CLAUSE_IS_FAVORITE = "is_favorite > 0";
const string WHERE_CLAUSE_HIDDEN = "hidden > 0";
const string WHERE_CLAUSE_EDIT = "edit_time > 0";
const string INVALID_STR = "-1";
const string EMPTY_STR = "";
const string TEST_FILE_PATH_PHOTO = "test_file_path_photo";
const string TEST_FILE_PATH_VIDEO = "test_file_path_video";
const string TEST_FILE_PATH_AUDIO = "test_file_path_audio";
const vector<string> CLEAR_SQLS = {
    "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
    "DELETE FROM " + PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_TYPE + " != " +
        to_string(PhotoAlbumType::SYSTEM),
    "DELETE FROM " + PhotoMap::TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_SUBTYPE + " != " +
        to_string(PhotoAlbumSubType::SHOOTING_MODE),
    "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE,
    "DELETE FROM " + AudioColumn::AUDIOS_TABLE,
};
const vector<string> WHERE_CLAUSE_LIST_PHOTO = { WHERE_CLAUSE_SHOOTING_MODE, WHERE_CLAUSE_TRASHED,
    WHERE_CLAUSE_IS_FAVORITE, WHERE_CLAUSE_HIDDEN, WHERE_CLAUSE_EDIT,
};
const vector<string> WHERE_CLAUSE_LIST_AUDIO = { WHERE_CLAUSE_TRASHED, WHERE_CLAUSE_IS_FAVORITE };
const unordered_map<TestAlbumType, pair<string, string>> ALBUM_TABLE_MAP = {
    { TestAlbumType::SOURCE, { PhotoAlbumColumns::TABLE, PhotoMap::TABLE } },
    { TestAlbumType::USER, { PhotoAlbumColumns::TABLE, PhotoMap::TABLE } },
    { TestAlbumType::SHOOTING_MODE_PORTRAIT, { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE } },
};
const unordered_map<TestAlbumType, pair<PhotoAlbumSubType, string>> ALBUM_CONDITION_MAP = {
    { TestAlbumType::SOURCE, { PhotoAlbumSubType::SOURCE_GENERIC, "" } },
    { TestAlbumType::USER, { PhotoAlbumSubType::USER_GENERIC, "" } },
    { TestAlbumType::SHOOTING_MODE_PORTRAIT, { PhotoAlbumSubType::SHOOTING_MODE, SHOOTING_MODE_PORTRAIT_ALBUM_NAME } },
};
const int32_t INVALID_COUNT = -1;
const int32_t EXPECTED_SOURCE_ALBUM_COUNT = 2;
const int32_t EXPECTED_USER_ALBUM_COUNT = 1;
const int32_t EXPECTED_SHOOTING_MODE_ALBUM_COUNT = 1;
const int32_t EXPECTED_PHOTO_COUNT = 5;
const int32_t EXPECTED_PHOTO_MAP_COUNT = 7;
const int32_t EXPECTED_ANALYSIS_PHOTO_MAP_COUNT = 1;
const int32_t EXPECTED_COUNT_1 = 1;
const int32_t EXPECTED_COUNT_0 = 0;
const int32_t EXPECTED_ALBUM_TOTAL_COUNT = 4;
const int32_t EXPECTED_AUDIO_COUNT = 3;
const int32_t INVALID_ERROR_CODE = -1;

shared_ptr<MediaLibraryRdbStore> g_rdbStore;
unique_ptr<CloneRestore> restoreService = nullptr;

void ExecuteSqls(shared_ptr<NativeRdb::RdbStore> store, const vector<string> &sqls)
{
    for (const auto &sql : sqls) {
        int32_t errCode = store->ExecuteSql(sql);
        if (errCode == E_OK) {
            continue;
        }
        MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
    }
}

void ClearData()
{
    MEDIA_INFO_LOG("Start clear data");
    ExecuteSqls(g_rdbStore->GetRaw(), CLEAR_SQLS);
    MediaLibraryRdbUtils::UpdateAllAlbums(g_rdbStore->GetRaw());
    MEDIA_INFO_LOG("End clear data");
}

void ClearCloneSource(CloneSource &cloneSource, const string &dbPath)
{
    cloneSource.cloneStorePtr_ = nullptr;
    NativeRdb::RdbHelper::DeleteRdbStore(dbPath);
}

void Init(CloneSource &cloneSource, const string &path, const vector<string> &tableList)
{
    MEDIA_INFO_LOG("Start init clone source database");
    cloneSource.Init(path, tableList);
}

shared_ptr<ResultSet> GetResultSet(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &querySql)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return nullptr;
    }
    return rdbStore->QuerySql(querySql);
}

void QueryInt(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &querySql, const string &columnName,
    int32_t &result)
{
    ASSERT_NE(rdbStore, nullptr);
    auto resultSet = rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    result = GetInt32Val(columnName, resultSet);
    MEDIA_INFO_LOG("Query %{public}s result: %{public}d", querySql.c_str(), result);
}

void MediaLibraryBackupCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    ASSERT_NE(g_rdbStore, nullptr);
    MEDIA_INFO_LOG("Start init restoreService");
    restoreService = make_unique<CloneRestore>();
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw(); // destination database
}

void MediaLibraryBackupCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearData();
    restoreService->mediaLibraryRdb_ = nullptr;
}

void MediaLibraryBackupCloneTest::SetUp() {}

void MediaLibraryBackupCloneTest::TearDown(void) {}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_restore_test_001");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    EXPECT_EQ(restoreService->IsReadyForRestore(PhotoColumn::PHOTOS_TABLE), true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_table_column_status_test_002");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    for (const auto &tableName : tableList) {
        EXPECT_EQ(restoreService->IsReadyForRestore(tableName), true);
    }
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

int32_t GetAlbumCountByCondition(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &tableName,
    PhotoAlbumSubType albumSubType, const string &albumName = "")
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " +
        "album_subtype = " + to_string(static_cast<int32_t>(albumSubType));
    querySql += albumName.empty() ? "" : " AND album_name = '" + albumName + "'";
    int32_t result = INVALID_COUNT;
    QueryInt(rdbStore, querySql, MEDIA_COLUMN_COUNT_1, result);
    return result;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_album_test_002 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    restoreService->RestoreAlbum();
    int32_t shootingModeAlbumCount = GetAlbumCountByCondition(g_rdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE,
        PhotoAlbumSubType::SHOOTING_MODE, SHOOTING_MODE_PORTRAIT_ALBUM_NAME);
    EXPECT_EQ(shootingModeAlbumCount, EXPECTED_SHOOTING_MODE_ALBUM_COUNT);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

int32_t GetCountByWhereClause(const string &tableName, shared_ptr<NativeRdb::RdbStore> rdbStore,
    const string &whereClause = "")
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName;
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    int32_t result = INVALID_COUNT;
    QueryInt(rdbStore, querySql, MEDIA_COLUMN_COUNT_1, result);
    return result;
}

bool HasZeroSizeFile(const vector<FileInfo> &fileInfos)
{
    for (const auto &fileInfo : fileInfos) {
        if (fileInfo.fileSize <= 0) {
            return true;
        }
    }
    return false;
}

vector<NativeRdb::ValuesBucket> GetInsertValues(vector<FileInfo> &fileInfos, int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (auto &fileInfo : fileInfos) {
        fileInfo.cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfo.relativePath);
        if (restoreService->IsSameFileForClone(PhotoColumn::PHOTOS_TABLE, fileInfo)) {
            MEDIA_INFO_LOG("Has same file, skip");
            continue;
        }
        NativeRdb::ValuesBucket value = restoreService->GetInsertValue(fileInfo, fileInfo.cloudPath, sourceType);
        fileInfo.isNew = true;
        values.emplace_back(value);
    }
    return values;
}

void InsertPhoto(vector<FileInfo> &fileInfos)
{
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(fileInfos, SourceType::PHOTOS);
    int64_t photoRowNum = 0;
    int32_t errCode = restoreService->BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, photoRowNum);
    EXPECT_EQ(errCode, E_OK);
    restoreService->BatchQueryPhoto(fileInfos);
    int64_t mapRowNum = 0;
    restoreService->BatchInsertMap(fileInfos, mapRowNum);
}

void RestorePhoto()
{
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(restoreService->mediaRdb_,
        PhotoColumn::PHOTOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(
        restoreService->mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE);
    if (!restoreService->PrepareCommonColumnInfoMap(PhotoColumn::PHOTOS_TABLE, srcColumnInfoMap, dstColumnInfoMap)) {
        MEDIA_ERR_LOG("Prepare common column info failed");
        return;
    }
    vector<FileInfo> fileInfos = restoreService->QueryFileInfos(0);
    InsertPhoto(fileInfos);
}

int32_t GetMapCountByTable(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &tableName)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName;
    int32_t result = INVALID_COUNT;
    QueryInt(rdbStore, querySql, MEDIA_COLUMN_COUNT_1, result);
    return result;
}

int32_t GetAlbumOrMapTotalCount(shared_ptr<NativeRdb::RdbStore> rdbStore,
    const unordered_map<TestAlbumType, pair<string, string>> &albumTableMap, bool isAlbum)
{
    int32_t totalCount = 0;
    for (auto it = albumTableMap.begin(); it != albumTableMap.end(); ++it) {
        TestAlbumType albumType = it->first;
        auto tablePair = it->second;
        string tableName = isAlbum ? tablePair.first : tablePair.second;
        if (!isAlbum) {
            totalCount += GetMapCountByTable(rdbStore, tableName);
            continue;
        }
        if (ALBUM_CONDITION_MAP.count(albumType) == 0) {
            MEDIA_ERR_LOG("Get album condition failed: %{public}d", albumType);
            continue;
        }
        auto conditionPair = ALBUM_CONDITION_MAP.at(albumType);
        totalCount += GetAlbumCountByCondition(rdbStore, tableName, conditionPair.first, conditionPair.second);
    }
    return totalCount;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_table_column_status_test_003");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(restoreService->IsReadyForRestore(AudioColumn::AUDIOS_TABLE), true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_001 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    vector<FileInfo> fileInfos = restoreService->QueryFileInfos(AudioColumn::AUDIOS_TABLE, 0);
    int32_t audioCount = static_cast<int32_t>(fileInfos.size());
    EXPECT_EQ(audioCount, EXPECTED_AUDIO_COUNT);
    EXPECT_EQ(HasZeroSizeFile(fileInfos), false);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

void PrepareFileInfos(const string &tableName, vector<FileInfo> &fileInfos)
{
    for (auto &fileInfo : fileInfos) {
        fileInfo.cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfo.relativePath);
        fileInfo.isNew = !restoreService->HasSameAudioFile(restoreService->mediaLibraryRdb_, tableName, fileInfo);
    }
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_002 start");
    int32_t count = 3;
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(count, EXPECTED_AUDIO_COUNT);
    // need judge file count later
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_003 start");
    int32_t audioCountBefore = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw());
    int32_t count = 3;
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(count, EXPECTED_AUDIO_COUNT);
    // need judge file count later
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_file_valid_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_file_valid_test_001 start");
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_DB_PATH, CLONE_RESTORE_ID), true);
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_BACKUP_PATH, CLONE_RESTORE_ID), false); // directory
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_FAKE_FILE_DIR, CLONE_RESTORE_ID), false); // not exist
}

void ClearRestoreExInfo()
{
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->errorInfo_.clear();
    restoreService->failedFilesMap_.clear();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_001 start");
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx({ UPGRADE_RESTORE_ID, EMPTY_STR, EMPTY_STR, EMPTY_STR,
        EMPTY_STR }, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR); // upgrade is now supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_002 start");
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx({ DUAL_FRAME_CLONE_RESTORE_ID, EMPTY_STR, EMPTY_STR, EMPTY_STR,
        EMPTY_STR }, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR); // dual clone is now supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_003 start");
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx({ CLONE_RESTORE_ID, EMPTY_STR, EMPTY_STR, EMPTY_STR,
        EMPTY_STR }, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR); // single clone is now supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_get_backup_info_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_get_backup_info_001 start");
    string backupInfo = INVALID_STR;
    BackupRestoreService::GetInstance().GetBackupInfo(UPGRADE_RESTORE_ID, backupInfo);
    MEDIA_INFO_LOG("Get backupInfo: %{public}s", backupInfo.c_str());
    EXPECT_EQ(backupInfo, EMPTY_STR); // upgrade is not supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_get_restore_ex_info_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_get_restore_ex_info_001 start");
    ClearRestoreExInfo();
    string restoreExInfo = restoreService->GetRestoreExInfo();
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_GT(restoreExInfo.size(), 0);
    nlohmann::json jsonObject = nlohmann::json::parse(restoreExInfo);
    EXPECT_EQ(jsonObject.empty(), false);
    EXPECT_EQ(jsonObject.is_discarded(), false);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_set_error_code_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_set_error_code_001 start");
    ClearRestoreExInfo();
    restoreService->SetErrorCode(RestoreError::INIT_FAILED);
    MEDIA_INFO_LOG("Get errorCode: %{public}d, errorInfo: %{public}s", restoreService->errorCode_,
        restoreService->errorInfo_.c_str());
    EXPECT_GT(restoreService->errorInfo_.size(), 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_set_error_code_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_set_error_code_002 start");
    ClearRestoreExInfo();
    restoreService->SetErrorCode(INVALID_ERROR_CODE);
    MEDIA_INFO_LOG("Get errorCode: %{public}d, errorInfo: %{public}s", restoreService->errorCode_,
        restoreService->errorInfo_.c_str());
    EXPECT_EQ(restoreService->errorInfo_.size(), 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_update_failed_files_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_update_failed_files_001 start");
    ClearRestoreExInfo();
    FileInfo fileInfo;
    fileInfo.oldPath = TEST_FILE_PATH_PHOTO;
    restoreService->UpdateFailedFiles(static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE), fileInfo,
        RestoreError::FILE_INVALID);
    fileInfo.oldPath = TEST_FILE_PATH_VIDEO;
    restoreService->UpdateFailedFiles(static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO), fileInfo,
        RestoreError::MOVE_FAILED);
    fileInfo.oldPath = TEST_FILE_PATH_AUDIO;
    restoreService->UpdateFailedFiles(static_cast<int32_t>(MediaType::MEDIA_TYPE_AUDIO), fileInfo,
        RestoreError::PATH_INVALID);
    MEDIA_INFO_LOG("Get failedFilesMap size: %{public}zu", restoreService->failedFilesMap_.size());
    EXPECT_GT(restoreService->failedFilesMap_.size(), 0);
    EXPECT_GT(restoreService->failedFilesMap_.count(STAT_TYPE_PHOTO), 0);
    EXPECT_GT(restoreService->failedFilesMap_.count(STAT_TYPE_VIDEO), 0);
    EXPECT_GT(restoreService->failedFilesMap_.count(STAT_TYPE_AUDIO), 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_backup_info_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_get_backup_info_001 start");
    string backupInfo = restoreService->GetBackupInfo();
    MEDIA_INFO_LOG("Get backupInfo: %{public}s", backupInfo.c_str());
    EXPECT_GT(backupInfo.size(), 0);
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_EQ(jsonObject.empty(), false);
    EXPECT_EQ(jsonObject.is_discarded(), false);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_get_failed_files_str_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_file_get_failed_files_str_001 start");
    FileInfo fileInfo;
    unordered_map<string, FailedFileInfo> failedFiles = {
        { TEST_FILE_PATH_PHOTO, FailedFileInfo(CLONE_RESTORE_ID, fileInfo, RestoreError::FILE_INVALID) },
        { TEST_FILE_PATH_VIDEO, FailedFileInfo(CLONE_RESTORE_ID, fileInfo, RestoreError::MOVE_FAILED) },
        { TEST_FILE_PATH_AUDIO, FailedFileInfo(CLONE_RESTORE_ID, fileInfo, RestoreError::PATH_INVALID) },
    };
    string failedFilesStr = BackupFileUtils::GetFailedFilesStr(CLONE_RESTORE_ID, failedFiles, MAX_FAILED_FILES_LIMIT);
    MEDIA_INFO_LOG("Get failedFilesStr: %{public}s", failedFilesStr.c_str());
    EXPECT_GT(failedFilesStr.size(), 0);
}

/**
 * @brief BurstKeyGenerator should give the same uuid for diffirent FileInfo in one Bucket
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_001 start");
    BurstKeyGenerator burstKeyGenerator;
    std::vector<FileInfo> fileInfos;
    std::vector<std::string> hashs = {
        "374c3cacde794191acd933529e860997",
        "fe02dx0ea6115ce236151a1a11d144c8",
        "3e3a7bf47a15aec4ac10f4fa08dc8b99",
        "d18a6a01bd430b2bb91d8f3d0a9b4bee",
        "1cdde93b419c574ef39e5893179743c5"
    };
    for (int i = 0; i < 5; i++) {
        FileInfo item;
        item.title = "IMG_20240619_022412_BURST00" + std::to_string(i);
        item.relativeBucketId = "2064266562";
        item.recycleFlag = 0;
        item.isBurst = 2;
        item.hashCode = hashs[i];
        fileInfos.push_back(item);
    }
    fileInfos[0].isBurst = 1;
    string burstKey;
    for (int i = 0; i < fileInfos.size(); i++) {
        if (burstKey.empty()) {
            burstKey = burstKeyGenerator.FindBurstKey(fileInfos[i]);
        }
        else {
            EXPECT_EQ(burstKey, burstKeyGenerator.FindBurstKey(fileInfos[i]));
        }
    }
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_001 end");
}

/**
 * @brief BurstKeyGenerator should give the different uuid for same FileInfo in Recycle Bin
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_002 start");
    BurstKeyGenerator burstKeyGenerator;
    std::vector<FileInfo> fileInfos;
    for (int i = 0; i < 5; i++) {
        FileInfo item;
        item.title = "IMG_20240619_022412_BURST001";
        item.relativeBucketId = "2064266562";
        item.recycleFlag = 2;
        item.isBurst = 2;
        item.hashCode = "374c3cacde794191acd933529e860997";
        fileInfos.push_back(item);
    }
    string burstKey;
    for (int i = 0; i < fileInfos.size(); i++) {
        if (burstKey.empty()) {
            burstKey = burstKeyGenerator.FindBurstKey(fileInfos[i]);
        }
        else {
            EXPECT_NE(burstKey, burstKeyGenerator.FindBurstKey(fileInfos[i]));
        }
    }
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_002 end");
}

/**
 * @brief BurstKeyGenerator should give the different uuid for same FileInfo in different Bucket
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_003 start");
    BurstKeyGenerator burstKeyGenerator;
    std::vector<FileInfo> fileInfos;
    for (int i = 0; i < 5; i++) {
        FileInfo item;
        item.title = "IMG_20240619_022412_BURST001";
        item.relativeBucketId = "2064266562" + std::to_string(i);
        item.recycleFlag = 0;
        item.isBurst = 2;
        item.hashCode = "374c3cacde794191acd933529e860997";
        fileInfos.push_back(item);
    }
    string burstKey;
    for (int i = 0; i < fileInfos.size(); i++) {
        if (burstKey.empty()) {
            burstKey = burstKeyGenerator.FindBurstKey(fileInfos[i]);
        }
        else {
            EXPECT_NE(burstKey, burstKeyGenerator.FindBurstKey(fileInfos[i]));
        }
    }
    MEDIA_INFO_LOG("medialibrary_backup_file_burst_key_generator_003 end");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_portrait_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_portrait_album_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);

    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->RestoreFromGalleryPortraitAlbum();

    VerifyPortraitAlbumRestore(restoreService->mediaLibraryRdb_);
}

void MediaLibraryBackupCloneTest::VerifyPortraitAlbumRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE album_type = " + std::to_string(SMART) +
        " AND album_subtype = " + std::to_string(PORTRAIT);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    std::string columnValue;

    (void)resultSet->GetColumnIndex("album_name", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "Test Portrait Album");

    (void)resultSet->GetColumnIndex("tag_id", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "test_tag_id");

    (void)resultSet->GetColumnIndex("cover_uri", index);
    resultSet->GetString(index, columnValue);
    EXPECT_EQ(columnValue, "test_cover_uri");

    (void)resultSet->GetColumnIndex("is_cover_satisfied", index);
    int isCoverSatisfied;
    resultSet->GetInt(index, isCoverSatisfied);
    EXPECT_EQ(isCoverSatisfied, 1);

    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_portrait_clustering_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_portrait_clustering_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_FACE_TAG_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);

    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->RestorePortraitClusteringInfo();

    VerifyPortraitClusteringRestore(restoreService->mediaLibraryRdb_);
}

void MediaLibraryBackupCloneTest::VerifyPortraitClusteringRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + VISION_FACE_TAG_TABLE;

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    std::string stringValue;
    int intValue;

    (void)resultSet->GetColumnIndex(FACE_TAG_COL_TAG_ID, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "test_tag_id");

    (void)resultSet->GetColumnIndex(FACE_TAG_COL_TAG_NAME, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "Test Face Tag");

    (void)resultSet->GetColumnIndex(FACE_TAG_COL_CENTER_FEATURES, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "test_center_features");

    (void)resultSet->GetColumnIndex(FACE_TAG_COL_TAG_VERSION, index);
    resultSet->GetInt(index, intValue);
    EXPECT_EQ(intValue, 1);

    (void)resultSet->GetColumnIndex(FACE_TAG_COL_ANALYSIS_VERSION, index);
    resultSet->GetInt(index, intValue);
    EXPECT_EQ(intValue, 1);
    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_image_face_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_image_face_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_IMAGE_FACE_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);

    std::vector<FileInfo> fileInfos;
    SetupMockImgFaceData(fileInfos);

    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restoreService->RestoreImageFaceInfo(fileInfos);

    VerifyImageFaceRestore(restoreService->mediaLibraryRdb_, fileInfos);

    ClearCloneSource(cloneSource, TEST_DB_PATH);
}

void MediaLibraryBackupCloneTest::SetupMockImgFaceData(std::vector<FileInfo>& fileInfos)
{
    FileInfo fileInfo;
    fileInfo.fileIdOld = 1;
    fileInfo.fileIdNew = FILE_INFO_NEW_ID;
    fileInfos.push_back(fileInfo);
}

void MediaLibraryBackupCloneTest::VerifyImageFaceRestore(const std::shared_ptr<NativeRdb::RdbStore>& db,
    const std::vector<FileInfo>& fileInfos)
{
    std::string querySql = "SELECT * FROM " + VISION_IMAGE_FACE_TABLE +
        " WHERE " + IMAGE_FACE_COL_FILE_ID + " = " + std::to_string(fileInfos[0].fileIdNew);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);

    int index;
    int intValue;
    std::string stringValue;
    double doubleValue;

    (void)resultSet->GetColumnIndex(IMAGE_FACE_COL_FILE_ID, index);
    resultSet->GetInt(index, intValue);
    EXPECT_EQ(intValue, fileInfos[0].fileIdNew);

    (void)resultSet->GetColumnIndex(IMAGE_FACE_COL_FACE_ID, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "test_face_id");

    (void)resultSet->GetColumnIndex(IMAGE_FACE_COL_TAG_ID, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "test_tag_id");

    (void)resultSet->GetColumnIndex(IMAGE_FACE_COL_SCALE_X, index);
    resultSet->GetDouble(index, doubleValue);
    EXPECT_DOUBLE_EQ(doubleValue, 1.0);

    (void)resultSet->GetColumnIndex(IMAGE_FACE_COL_SCALE_Y, index);
    resultSet->GetDouble(index, doubleValue);
    EXPECT_DOUBLE_EQ(doubleValue, 1.0);
    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
}
} // namespace Media
} // namespace OHOS