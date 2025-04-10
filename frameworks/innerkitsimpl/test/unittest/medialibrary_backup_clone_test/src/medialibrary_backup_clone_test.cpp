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

#define private public
#define protected public
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "clone_source.h"
#include "media_column.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "backup_restore_service.h"
#include "base_restore.h"
#include "clone_restore.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "others_clone_restore.h"
#include "photos_dao.h"
#include "photos_data_handler.h"
#include "burst_key_generator.h"
#include "backup_const.h"
#include "clone_restore_geo.h"
#undef protected
#undef private

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
const string TEST_PATH = "/data/test";
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
const string TASK_ID = "1";
const string TEST_DIR_PATH = "test";
const int32_t TEST_ORIENTATION_ZERO = 0;
const int32_t TEST_ORIENTATION_NINETY = 90;
const vector<string> CLEAR_SQLS = {
    "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
    "DELETE FROM " + PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_TYPE + " != " +
        to_string(PhotoAlbumType::SYSTEM),
    "DELETE FROM " + PhotoMap::TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_SUBTYPE + " != " +
        to_string(PhotoAlbumSubType::SHOOTING_MODE),
    "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE,
    "DELETE FROM " + AudioColumn::AUDIOS_TABLE,
    "DELETE FROM " + GEO_DICTIONARY_TABLE,
    "DELETE FROM " + VISION_LABEL_TABLE,
    "DELETE FROM " + VISION_VIDEO_LABEL_TABLE,
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

const int PHONE_FIRST_NUMBER = 105;
const int PHONE_SECOND_NUMBER = 80;
const int PHONE_THIRD_NUMBER = 104;
const int PHONE_FOURTH_NUMBER = 111;
const int PHONE_FIFTH_NUMBER = 110;
const int PHONE_SIXTH_NUMBER = 101;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

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
    MediaLibraryRdbUtils::UpdateAllAlbums(g_rdbStore);
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
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
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
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
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
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
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
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_file_valid_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_file_valid_test_001 start");
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_DB_PATH, CLONE_RESTORE_ID), E_OK);
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_BACKUP_PATH, CLONE_RESTORE_ID), E_FAIL); // directory
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_FAKE_FILE_DIR, CLONE_RESTORE_ID), E_NO_SUCH_FILE); // not exist
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
    RestoreInfo info;
    info.sceneCode = UPGRADE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR); // upgrade is now supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_002 start");
    RestoreInfo info;
    info.sceneCode = DUAL_FRAME_CLONE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR); // dual clone is now supported
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_003 start");
    RestoreInfo info;
    info.sceneCode = CLONE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
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

static std::string GetPhoneName()
{
    int arr[] = { PHONE_FIRST_NUMBER, PHONE_SECOND_NUMBER, PHONE_THIRD_NUMBER, PHONE_FOURTH_NUMBER, PHONE_FIFTH_NUMBER,
        PHONE_SIXTH_NUMBER };
    int len = sizeof(arr) / sizeof(arr[0]);
    std::string phoneName = "";
    for (int i = 0; i < len; i++) {
        phoneName += static_cast<char>(arr[i]);
    }
    return phoneName;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_restore_OthersCloneRestore_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "");
    EXPECT_EQ(othersClone->clonePhoneName_, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "[\n\t\t\"type\":\t\"backupInfo\"]");
    EXPECT_EQ(othersClone->clonePhoneName_, GetPhoneName());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_003");

    std::string json = string("[{\n\t\t\"type\":\t\"deviceType\",\n\t\t\"detail\":\t\"test\"\n\t},") +
        " {\n\t\t\"type\":\t\"userId\",\n\t\t\"detail\":\t\"100\"\n\t}]";
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", json);
    EXPECT_EQ(othersClone->clonePhoneName_, "test");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_004");

    std::string json = string("[{\n\t\t\"type\":\t\"device\",\n\t\t\"detail\":\t\"test\"\n\t},") +
        " {\n\t\t\"type\":\t\"userId\",\n\t\t\"detail\":\t\"100\"\n\t}]";
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", json);
    EXPECT_EQ(othersClone->clonePhoneName_, GetPhoneName());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetCloneDbInfos_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetCloneDbInfos_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<CloneDbInfo> vec;
    othersClone->GetCloneDbInfos("aaa", vec);
    EXPECT_TRUE(vec.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetCloneDbInfos_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetCloneDbInfos_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());

    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    store->ExecuteSql(string("CREATE TABLE IF NOT EXISTS mediaInfo ") +
        "(_data TEXT, latitude DOUBLE, longitude DOUBLE, datetaken DOUBLE, date_modified DOUBLE, primaryStr TEXT)");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/emulated', 0, 0, 1726123123, 1726123.123, '1234563.jpg')");
    std::vector<CloneDbInfo> vec;
    othersClone->GetCloneDbInfos("photo_MediaInfo.db", vec);
    EXPECT_FALSE(vec.empty());
    store->ExecuteSql("DROP TABLE IF EXISTS mediaInfo");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    EXPECT_NE(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    othersClone->mediaLibraryRdb_ = store;
    EXPECT_NE(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    othersClone->mediaLibraryRdb_ = store;
    othersClone->backupRestoreDir_ = "/storage/media/100/local/files/";
    EXPECT_EQ(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetInsertValue_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetInsertValue_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.dateTaken = 1;
    fileInfo.dateModified = 1;
    auto value = othersClone->GetInsertValue(fileInfo, "/data", 1);
    int64_t taken;
    int64_t modified;
    value.values_[MediaColumn::MEDIA_DATE_TAKEN].GetLong(taken);
    value.values_[MediaColumn::MEDIA_DATE_MODIFIED].GetLong(modified);
    EXPECT_EQ(taken, 1);
    EXPECT_EQ(modified, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetInsertValue_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetInsertValue_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    auto value = othersClone->GetInsertValue(fileInfo, "/data", 1);
    int64_t taken;
    int64_t modified;
    value.values_[MediaColumn::MEDIA_DATE_TAKEN].GetLong(taken);
    value.values_[MediaColumn::MEDIA_DATE_MODIFIED].GetLong(modified);
    EXPECT_EQ(taken, 0);
    EXPECT_EQ(modified, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.gif", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.gif");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.mp4", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.mp4");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.mp3", st);
    EXPECT_EQ(othersClone->audioInfos_[0].filePath, "filePath/test.mp3");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.ief", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.ief");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_005");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.txt", st);
    EXPECT_TRUE(othersClone->photoInfos_.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 1000);
    EXPECT_EQ(fileInfo.dateTaken, 1000);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 0);
    EXPECT_EQ(fileInfo.dateTaken, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->photoDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 1000);
    EXPECT_EQ(fileInfo.dateTaken, 1000);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloneDbInfo cloneDbInfoPh;
    cloneDbInfoPh.displayName = "";
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->photoDbInfo_.push_back(cloneDbInfoPh);
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 1000);
    EXPECT_EQ(fileInfo.dateTaken, 1000);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_005");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloneDbInfo cloneDbInfoPh;
    cloneDbInfoPh.displayName = "";
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "";
    othersClone->photoDbInfo_.push_back(cloneDbInfoPh);
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 0);
    EXPECT_EQ(fileInfo.dateTaken, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_006");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    CloneDbInfo cloneDbInfoPh;
    cloneDbInfoPh.displayName = "";
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "";
    othersClone->photoDbInfo_.push_back(cloneDbInfoPh);
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 0);
    EXPECT_EQ(fileInfo.dateTaken, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_007");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_FILE;
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 0);
    EXPECT_EQ(fileInfo.dateTaken, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_008");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1.5e10;
    cloneDbInfo.dateTaken = 1.5e10;
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 15000000000);
    EXPECT_EQ(fileInfo.dateTaken, 15000000000);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_009");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.filePath = "/data/photo";
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CloneDbInfo cloneDbInfo;
    othersClone->audioDbInfo_.push_back(cloneDbInfo);
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(fileInfo.dateModified, 0);
    EXPECT_EQ(fileInfo.dateTaken, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetAllfilesInCurrentDir_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetAllfilesInCurrentDir_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    auto err = othersClone->GetAllfilesInCurrentDir("/storage/media/100/local/test/test");
    EXPECT_EQ(err, ERR_NOT_ACCESSIBLE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetAllfilesInCurrentDir_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetAllfilesInCurrentDir_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    auto err = othersClone->GetAllfilesInCurrentDir("/storage/media/100/local/files/");
    EXPECT_EQ(err, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestorePhoto_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestorePhoto();
    EXPECT_EQ(othersClone->totalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestorePhoto_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_FILE;
    othersClone->photoInfos_.push_back(fileInfo);
    othersClone->RestorePhoto();
    EXPECT_EQ(othersClone->totalNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestorePhoto_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    for (int i = 0;i < 200;i ++) {
        othersClone->photoInfos_.push_back(fileInfo);
    }
    othersClone->RestorePhoto();
    EXPECT_EQ(othersClone->totalNumber_, 200);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestorePhoto_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    othersClone->photoInfos_.push_back(fileInfo);
    othersClone->RestorePhoto();
    EXPECT_EQ(othersClone->totalNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_InsertPhoto_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_InsertPhoto_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<FileInfo> fileInfos;
    othersClone->InsertPhoto(fileInfos);
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_InsertPhoto_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_InsertPhoto_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    std::vector<FileInfo> fileInfos;
    FileInfo tmpInfo;
    struct stat statInfo;
    lstat("/vendor/etc/firmware/nvram_ap6275s.txt", &statInfo);
    tmpInfo.filePath = "/vendor/etc/firmware/nvram_ap6275s.txt";
    tmpInfo.displayName = "nvram_ap6275s.txt";
    tmpInfo.title = BackupFileUtils::GetFileTitle(tmpInfo.displayName);
    tmpInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    tmpInfo.fileSize = statInfo.st_size;
    tmpInfo.dateModified = MediaFileUtils::Timespec2Millisecond(statInfo.st_mtim);
    fileInfos.push_back(tmpInfo);
    othersClone->imageNumber_ = 1;
    othersClone->hasLowQualityImage_ = true;
    othersClone->InsertPhoto(fileInfos);
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    othersClone->audioInfos_.push_back(fileInfo);
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAlbum_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAlbum_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    std::vector<FileInfo> fileInfos;
    othersClone->RestoreAlbum(fileInfos);
    EXPECT_TRUE(othersClone->photoAlbumDao_.mediaLibraryRdb_ == nullptr);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAlbum_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAlbum_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    FileInfo fileInfo;
    std::vector<FileInfo> fileInfos;
    fileInfos.push_back(fileInfo);
    othersClone->RestoreAlbum(fileInfos);
    EXPECT_TRUE(othersClone->photoAlbumDao_.mediaLibraryRdb_ == nullptr);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HasSameFileForDualClone_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HasSameFileForDualClone_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());

    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);

    othersClone->photosRestore_.OnStart(store, store);

    EXPECT_FALSE(othersClone->HasSameFileForDualClone(fileInfo));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HasSameFileForDualClone_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HasSameFileForDualClone_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.fileType = MEDIA_TYPE_VIDEO;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileSize = 100;

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());

    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    store->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    store->ExecuteSql(string("INSERT INTO Photos (file_id, data, display_name, size, owner_album_id") +
        ") VALUES (1, 'test', 'test.jpg', 100, 0)");

    othersClone->photosRestore_.photosBasicInfo_.maxFileId = 100;
    othersClone->photosRestore_.OnStart(store, store);

    EXPECT_TRUE(othersClone->HasSameFileForDualClone(fileInfo));
    store->ExecuteSql("DROP TABLE IF EXISTS Photos");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpdateAlbumInfo_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpdateAlbumInfo_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    othersClone->clonePhoneName_ = "testPhone";
    othersClone->UpdateAlbumInfo(fileInfo);
    EXPECT_EQ(fileInfo.bundleName, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpdateAlbumInfo_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpdateAlbumInfo_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.lPath = "/data/test";
    PhotoAlbumDao::PhotoAlbumRowData photoAlbumRowData;
    photoAlbumRowData.albumId = 1;
    othersClone->photoAlbumDao_.photoAlbumCache_.Insert("/data/test", photoAlbumRowData);
    othersClone->UpdateAlbumInfo(fileInfo);
    EXPECT_EQ(fileInfo.ownerAlbumId, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_NeedBatchQueryPhotoForPortrait_001,
    TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_NeedBatchQueryPhotoForPortrait_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<FileInfo> fileInfos;
    NeedQueryMap needQueryMap;
    EXPECT_TRUE(othersClone->NeedBatchQueryPhotoForPortrait(fileInfos, needQueryMap));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleRestData_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleRestData_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->HandleRestData();
    EXPECT_EQ(othersClone->otherProcessStatus_, ProcessStatus::STOP);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_ParseResultSet_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_ParseResultSet_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    FileInfo fileInfo;
    std::string dbName;
    EXPECT_TRUE(othersClone->ParseResultSet(resultSet, fileInfo, dbName));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_ParseResultSetForAudio_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_ParseResultSetForAudio_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    FileInfo fileInfo;
    EXPECT_TRUE(othersClone->ParseResultSetForAudio(resultSet, fileInfo));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_CloneInfoPushBack_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_CloneInfoPushBack_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    CloneDbInfo cloneDbInfo = {"test.jpg", "/data/photo", 100, 100};
    std::vector<CloneDbInfo> pushInfos;
    std::vector<CloneDbInfo> popInfos = {cloneDbInfo};
    othersClone->CloneInfoPushBack(pushInfos, popInfos);
    EXPECT_EQ(pushInfos[0].displayName, "test.jpg");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_CloneInfoPushBack_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_CloneInfoPushBack_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<CloneDbInfo> pushInfos;
    std::vector<CloneDbInfo> popInfos;
    othersClone->CloneInfoPushBack(pushInfos, popInfos);
    EXPECT_TRUE(pushInfos.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb = nullptr;
    int32_t offset = 1;
    int32_t sceneCode = I_PHONE_CLONE_RESTORE;
    std::vector<CloneDbInfo> mediaDbInfo;
    othersClone->HandleSelectBatch(mediaRdb, offset, sceneCode, mediaDbInfo);
    EXPECT_TRUE(mediaDbInfo.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);

    std::shared_ptr<NativeRdb::RdbStore> mediaRdb = store;
    int32_t offset = 1;
    int32_t sceneCode = I_PHONE_CLONE_RESTORE;
    std::vector<CloneDbInfo> mediaDbInfo;
    othersClone->HandleSelectBatch(mediaRdb, offset, sceneCode, mediaDbInfo);
    EXPECT_TRUE(mediaDbInfo.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    store->ExecuteSql(string("CREATE TABLE IF NOT EXISTS mediaInfo ") +
        "(_data TEXT, latitude DOUBLE, longitude DOUBLE, datetaken DOUBLE, date_modified DOUBLE, primaryStr TEXT)");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/medialib', 0, 0, 17283946, 17283.946, '123456789.jpg')");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/media', 0, 0, 17283946, 17283.946, '963852741.jpg')");

    std::shared_ptr<NativeRdb::RdbStore> mediaRdb = store;
    int32_t offset = 1;
    int32_t sceneCode = I_PHONE_CLONE_RESTORE;
    std::vector<CloneDbInfo> mediaDbInfo;
    othersClone->HandleSelectBatch(mediaRdb, offset, sceneCode, mediaDbInfo);
    EXPECT_EQ(mediaDbInfo[0].displayName, "963852741.jpg");
    store->ExecuteSql("DROP TABLE IF EXISTS mediaInfo");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    store->ExecuteSql(string("CREATE TABLE IF NOT EXISTS mediaInfo ") +
        "(_data TEXT, latitude DOUBLE, longitude DOUBLE, datetaken DOUBLE, date_modified DOUBLE, primaryStr TEXT)");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/medialib', 0, 0, 17283946, 17283.946, '123456789.jpg')");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/media', 0, 0, 17283946, 17283.946, '963852741.jpg')");

    std::shared_ptr<NativeRdb::RdbStore> mediaRdb = store;
    int32_t offset = 1;
    int32_t sceneCode = OTHERS_PHONE_CLONE_RESTORE;
    std::vector<CloneDbInfo> mediaDbInfo;
    othersClone->HandleSelectBatch(mediaRdb, offset, sceneCode, mediaDbInfo);
    EXPECT_EQ(mediaDbInfo[0].data, "/storage/media");
    store->ExecuteSql("DROP TABLE IF EXISTS mediaInfo");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleInsertBatch_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleInsertBatch_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    int32_t offset = 0;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    othersClone->photoInfos_.push_back(fileInfo);
    othersClone->HandleInsertBatch(offset);
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleInsertBatch_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleInsertBatch_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    int32_t offset = 0;
    FileInfo fileInfo;
    for (int i = 0;i < 200;i ++) {
        othersClone->photoInfos_.push_back(fileInfo);
    }
    othersClone->HandleInsertBatch(offset);
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_backup_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_rebackup_001 start");

    BackupRestoreService &instance = BackupRestoreService::GetInstance();
    ASSERT_NE(&instance, nullptr);
    instance.StartBackup(UPGRADE_RESTORE_ID, EMPTY_STR, EMPTY_STR);
    instance.StartBackup(CLONE_RESTORE_ID, EMPTY_STR, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_thumbnail_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_move_thumbnail_test_001");
    restoreService->hasCloneThumbnailDir_ = false;
    FileInfo testFileInfo;
    int32_t ret = restoreService->MoveThumbnail(testFileInfo);
    EXPECT_EQ(ret, E_NO_SUCH_FILE);

    restoreService->hasCloneThumbnailDir_ = true;
    testFileInfo.thumbnailReady = 0;
    testFileInfo.lcdVisitTime = 0;
    ret = restoreService->MoveThumbnail(testFileInfo);
    EXPECT_EQ(ret, E_NO_SUCH_FILE);

    restoreService->hasCloneThumbnailDir_ = true;
    testFileInfo.thumbnailReady = 4;
    testFileInfo.lcdVisitTime = 0;
    testFileInfo.relativePath = "";
    ret = restoreService->MoveThumbnail(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    restoreService->hasCloneThumbnailDir_ = true;
    testFileInfo.thumbnailReady = 0;
    testFileInfo.lcdVisitTime = 2;
    testFileInfo.relativePath = "";
    ret = restoreService->MoveThumbnail(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_thumbnail_dir_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_move_thumbnail_dir_test_001");
    FileInfo testFileInfo;
    testFileInfo.relativePath = "";
    int32_t ret = restoreService->MoveThumbnailDir(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.relativePath = "testPath";
    testFileInfo.cloudPath = "";
    ret = restoreService->MoveThumbnailDir(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.relativePath = "testPath";
    testFileInfo.cloudPath = "/storage/cloud/files/test";
    ret = restoreService->MoveThumbnailDir(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_move_astc_test_001");
    FileInfo testFileInfo;
    restoreService->oldMonthKvStorePtr_ = nullptr;
    int32_t ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    restoreService->oldMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->oldYearKvStorePtr_ = nullptr;
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    restoreService->oldYearKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newMonthKvStorePtr_ = nullptr;
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    restoreService->newMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newYearKvStorePtr_ = nullptr;
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_move_astc_test_002");
    FileInfo testFileInfo;
    restoreService->oldMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->oldYearKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newYearKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();

    testFileInfo.fileIdOld = -1;
    int32_t ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.fileIdOld = 1;
    testFileInfo.fileIdNew = -1;
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.fileIdOld = 1;
    testFileInfo.fileIdNew = 1;
    testFileInfo.oldAstcDateKey = "";
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.oldAstcDateKey = "0000000000000a";
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.oldAstcDateKey = "0000000000000";
    testFileInfo.newAstcDateKey = "";
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);

    testFileInfo.oldAstcDateKey = "0";
    testFileInfo.newAstcDateKey = "0000000000000a";
    ret = restoreService->MoveAstc(testFileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_move_astc_test_003");
    FileInfo testFileInfo;
    std::string testStoreId = "medialibrary_backup_clone_restore_move_astc_test_003";
    std::vector<uint8_t> testValue;
    testValue.assign(testStoreId.begin(), testStoreId.end());
    restoreService->oldMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->oldYearKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newMonthKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    restoreService->newYearKvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    int32_t testFileId = 1;
    std::string testAstcDateKey = "1";
    testFileInfo.fileIdOld = testFileId;
    testFileInfo.oldAstcDateKey = testAstcDateKey;
    testFileInfo.fileIdNew = testFileId;
    testFileInfo.newAstcDateKey = testAstcDateKey;
    testFileInfo.isRelatedToPhotoMap = 1;
    std::string testAstckey;
    EXPECT_EQ(MediaFileUtils::GenerateKvStoreKey(to_string(testFileId), testAstcDateKey, testAstckey), true);
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_FAIL);

    restoreService->oldMonthKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, testStoreId + "old_month", TEST_PATH);
    if (restoreService->oldMonthKvStorePtr_ == nullptr) {
        return;
    }
    EXPECT_EQ(restoreService->oldMonthKvStorePtr_->Insert(testAstckey, testValue), E_OK);
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_FAIL);

    restoreService->newMonthKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, testStoreId + "new_month", TEST_PATH);
    ASSERT_NE(restoreService->newMonthKvStorePtr_, nullptr);
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_FAIL);

    restoreService->oldYearKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, testStoreId + "old_year", TEST_PATH);
    ASSERT_NE(restoreService->oldYearKvStorePtr_, nullptr);
    EXPECT_EQ(restoreService->oldYearKvStorePtr_->Insert(testAstckey, testValue), E_OK);
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_FAIL);

    restoreService->newYearKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, testStoreId + "new_year", TEST_PATH);
    ASSERT_NE(restoreService->newYearKvStorePtr_, nullptr);
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_OK);

    testFileInfo.isRelatedToPhotoMap = 0;
    EXPECT_EQ(restoreService->MoveAstc(testFileInfo), E_OK);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_move_astc_test_003");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_geo_dictionary_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_DICTIONARY_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::shared_ptr<CloneRestoreGeoDictionary> cloneRestoreGeoDictionary = make_shared<CloneRestoreGeoDictionary>();
    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    EXPECT_EQ(cloneRestoreGeoDictionary->taskId_, TASK_ID);
    EXPECT_EQ(cloneRestoreGeoDictionary->sceneCode_, CLONE_RESTORE_ID);
    EXPECT_NE(cloneRestoreGeoDictionary->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreGeoDictionary->mediaLibraryRdb_, nullptr);

    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 1);
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 1);

    cloneRestoreGeoDictionary->successInsertCnt_ = 0;
    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 0);
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 0);
    VerifyGeoDictionaryRestore(cloneRestoreGeoDictionary->mediaLibraryRdb_);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

void MediaLibraryBackupCloneTest::VerifyGeoDictionaryRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + GEO_DICTIONARY_TABLE;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);
    int index;
    std::string stringValue;

    (void)resultSet->GetColumnIndex(CITY_ID, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "945032946426347352");

    (void)resultSet->GetColumnIndex(LANGUAGE, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "zh-Hans");

    (void)resultSet->GetColumnIndex(CITY_NAME, index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "武汉");

    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_geo_dictionary_test_002");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_DICTIONARY_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    shared_ptr<CloneRestoreGeoDictionary> cloneRestoreGeoDictionary = make_shared<CloneRestoreGeoDictionary>();
    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, nullptr, cloneSource.cloneStorePtr_);
    EXPECT_NE(cloneRestoreGeoDictionary->mediaRdb_, nullptr);
    EXPECT_EQ(cloneRestoreGeoDictionary->mediaLibraryRdb_, nullptr);
    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 0);

    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), nullptr);
    EXPECT_EQ(cloneRestoreGeoDictionary->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreGeoDictionary->mediaLibraryRdb_, nullptr);
    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 0);

    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, nullptr, nullptr);
    EXPECT_EQ(cloneRestoreGeoDictionary->mediaRdb_, nullptr);
    EXPECT_EQ(cloneRestoreGeoDictionary->mediaLibraryRdb_, nullptr);
    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_geo_dictionary_test_003");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_DICTIONARY_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::shared_ptr<CloneRestoreGeoDictionary> cloneRestoreGeoDictionary = make_shared<CloneRestoreGeoDictionary>();
    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    cloneRestoreGeoDictionary->GetGeoDictionaryInfos();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 1);
    cloneRestoreGeoDictionary->InsertIntoGeoDictionaryAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 1);

    cloneRestoreGeoDictionary->successInsertCnt_ = 0;
    cloneRestoreGeoDictionary->geoDictionaryInfos_.clear();
    cloneSource.Insert(tableList);
    cloneRestoreGeoDictionary->GetGeoDictionaryInfos();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 2);
    cloneRestoreGeoDictionary->InsertIntoGeoDictionaryAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->successInsertCnt_.load(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_geo_dictionary_test_004");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_DICTIONARY_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::shared_ptr<CloneRestoreGeoDictionary> cloneRestoreGeoDictionary = make_shared<CloneRestoreGeoDictionary>();
    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    cloneRestoreGeoDictionary->RestoreAlbums();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 1);

    cloneRestoreGeoDictionary->GeoDictionaryDeduplicate();
    EXPECT_EQ(cloneRestoreGeoDictionary->geoDictionaryInfos_.size(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_geo_dictionary_test_005");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_DICTIONARY_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::shared_ptr<CloneRestoreGeoDictionary> cloneRestoreGeoDictionary = make_shared<CloneRestoreGeoDictionary>();
    cloneRestoreGeoDictionary->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    std::unordered_map<std::string, std::string> columns;
    columns[CITY_ID] = "TEXT";
    columns[LANGUAGE] = "TEXT";
    columns[CITY_NAME] = "TEXT";
    EXPECT_TRUE(cloneRestoreGeoDictionary->CheckTableColumns(GEO_DICTIONARY_TABLE, columns));
    columns.clear();
    columns[FILE_ID] = "INT";
    EXPECT_FALSE(cloneRestoreGeoDictionary->CheckTableColumns(GEO_DICTIONARY_TABLE, columns));
    EXPECT_EQ(cloneRestoreGeoDictionary->GetCommonColumns(GEO_DICTIONARY_TABLE).size(), 3);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 1;
    fileInfo.fileIdNew = FILE_INFO_NEW_ID;
    fileInfos.push_back(fileInfo);

    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    EXPECT_EQ(cloneRestoreClassify->taskId_, TASK_ID);
    EXPECT_EQ(cloneRestoreClassify->sceneCode_, CLONE_RESTORE_ID);
    EXPECT_NE(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreClassify->mediaLibraryRdb_, nullptr);

    cloneRestoreClassify->RestoreMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_, 1);
    cloneRestoreClassify->RestoreVideoMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_, 1);
    VerifyClassifyRestore(cloneRestoreClassify->mediaLibraryRdb_);
    VerifyClassifyVideoRestore(cloneRestoreClassify->mediaLibraryRdb_);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

void MediaLibraryBackupCloneTest::VerifyClassifyRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + VISION_LABEL_TABLE;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);
    int index;
    int intValue;
    std::string stringValue;

    (void)resultSet->GetColumnIndex("file_id", index);
    resultSet->GetInt(index, intValue);
    EXPECT_EQ(intValue, FILE_INFO_NEW_ID);

    (void)resultSet->GetColumnIndex("sub_label", index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "44");

    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
}

void MediaLibraryBackupCloneTest::VerifyClassifyVideoRestore(const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    std::string querySql = "SELECT * FROM " + VISION_VIDEO_LABEL_TABLE;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = db->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);

    EXPECT_TRUE(resultSet->GoToFirstRow() == NativeRdb::E_OK);
    int index;
    int intValue;
    std::string stringValue;

    (void)resultSet->GetColumnIndex("file_id", index);
    resultSet->GetInt(index, intValue);
    EXPECT_EQ(intValue, FILE_INFO_NEW_ID);

    (void)resultSet->GetColumnIndex("sub_label", index);
    resultSet->GetString(index, stringValue);
    EXPECT_EQ(stringValue, "153");

    EXPECT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_002");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::vector<FileInfo> fileInfos {};
    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, nullptr, cloneSource.cloneStorePtr_);
    EXPECT_NE(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaLibraryRdb_, nullptr);
    cloneRestoreClassify->RestoreMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreClassify->mediaLibraryRdb_, nullptr);
    cloneRestoreClassify->RestoreMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, nullptr, nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaLibraryRdb_, nullptr);
    cloneRestoreClassify->RestoreMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps(fileInfos);
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_003");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    std::vector<CloneRestoreClassify::ClassifyCloneInfo> classifyInfo;
    std::vector<CloneRestoreClassify::ClassifyVideoCloneInfo> classifyVideoInfo;
    std::vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    cloneRestoreClassify->GetClassifyInfos(classifyInfo, fileInfos, 0);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo, fileInfos, 0);
    EXPECT_EQ(classifyInfo.size(), 0);
    EXPECT_EQ(classifyVideoInfo.size(), 0);

    fileInfo.fileIdOld = 1;
    fileInfo.fileIdNew = FILE_INFO_NEW_ID;
    fileInfos.push_back(fileInfo);
    cloneRestoreClassify->GetClassifyInfos(classifyInfo, fileInfos, 0);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo, fileInfos, 0);
    EXPECT_EQ(classifyInfo.size(), 1);
    EXPECT_EQ(classifyVideoInfo.size(), 1);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_004");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    std::vector<CloneRestoreClassify::ClassifyCloneInfo> classifyInfo;
    std::vector<CloneRestoreClassify::ClassifyVideoCloneInfo> classifyVideoInfo;
    std::vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 1;
    fileInfo.fileIdNew = FILE_INFO_NEW_ID;
    fileInfos.push_back(fileInfo);
    cloneRestoreClassify->GetClassifyInfos(classifyInfo, fileInfos, 0);
    cloneRestoreClassify->InsertClassifyAlbums(classifyInfo, fileInfos);
    EXPECT_EQ(classifyInfo.size(), 1);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo, fileInfos, 0);
    cloneRestoreClassify->InsertClassifyVideoAlbums(classifyVideoInfo, fileInfos);
    EXPECT_EQ(classifyVideoInfo.size(), 1);

    fileInfos.clear();
    cloneRestoreClassify->DeduplicateClassifyInfos(classifyInfo, fileInfos);
    EXPECT_EQ(classifyInfo.size(), 0);
    cloneRestoreClassify->DeduplicateClassifyVideoInfos(classifyVideoInfo, fileInfos);
    EXPECT_EQ(classifyVideoInfo.size(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_005");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    std::unordered_map<std::string, std::string> columns;
    columns[FILE_ID] = "INT";
    EXPECT_TRUE(cloneRestoreClassify->CheckTableColumns(VISION_LABEL_TABLE, columns));
    EXPECT_TRUE(cloneRestoreClassify->CheckTableColumns(VISION_VIDEO_LABEL_TABLE, columns));
    columns.clear();
    columns[LANGUAGE] = "TEXT";
    EXPECT_FALSE(cloneRestoreClassify->CheckTableColumns(VISION_LABEL_TABLE, columns));
    EXPECT_FALSE(cloneRestoreClassify->CheckTableColumns(VISION_VIDEO_LABEL_TABLE, columns));

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_dirty_count_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_dirty_count_test");
    PhotosDao photosDao_;
    photosDao_.SetMediaLibraryRdb(g_rdbStore->GetRaw());
    int32_t count = photosDao_.GetDirtyFilesCount();
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_dirty_files_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_dirty_files_test");
    PhotosDao photosDao_;
    photosDao_.SetMediaLibraryRdb(g_rdbStore->GetRaw());
    auto result = photosDao_.GetDirtyFiles(EXPECTED_COUNT_0);
    EXPECT_EQ(result.size(), EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_handle_dirty_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_handle_dirty_test");
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    photosDataHandler_.HandleDirtyFiles();
    EXPECT_EQ(photosDataHandler_.dirtyFileCleanNumber_, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_clean_dirty_files_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_clean_dirty_files_test");
    std::vector<PhotosDao::PhotosRowData> dirtyFiles;
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.CleanDirtyFiles(dirtyFiles);
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_delete_db_dirty_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_delete_db_dirty_test");
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.DeleteDirtyFilesInDb();
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_001");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = UPGRADE_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, UPGRADE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_002");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = DUAL_FRAME_CLONE_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, DUAL_FRAME_CLONE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_003");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = I_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, I_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_004");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = OTHERS_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, OTHERS_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_005");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = LITE_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, LITE_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_006");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = DEFAULT_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, CLONE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_backup_info_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_backup_info_test");
    BackupRestoreService backupRestoreService;
    std::string backupInfo;
    backupRestoreService.GetBackupInfo(CLONE_RESTORE_ID, backupInfo);
    EXPECT_EQ(backupInfo, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_account_valid_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_account_valid_test");
    restoreService->restoreInfo_ = R"([{"type":"singleAccountId", "detail":"test"}])";
    (void)restoreService->GetAccountValid();
    EXPECT_FALSE(restoreService->isAccountValid_);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_photo_test");
    restoreService->RestorePhoto();
    restoreService->RestorePhotoForCloud();
    EXPECT_EQ(restoreService->totalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_migrate_file_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_migrate_file_test");
    FileInfo fileInfo;
    fileInfo.needMove = true;
    fileInfo.filePath = TEST_DIR_PATH;
    fileInfo.cloudPath = TEST_DIR_PATH;
    fileInfo.specialFileType = LIVE_PHOTO_TYPE;
    std::vector<FileInfo> fileInfos = {fileInfo};
    int64_t fileMoveCount = 0;
    int64_t videoFileMoveCount = 0;
    restoreService->MoveMigrateFile(fileInfos, fileMoveCount, videoFileMoveCount);
    EXPECT_TRUE(fileInfos[0].needVisible);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_migrate_cloud_file_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_migrate_cloud_file_test");
    FileInfo fileInfo;
    fileInfo.needMove = true;
    fileInfo.filePath = TEST_DIR_PATH;
    fileInfo.specialFileType = LIVE_PHOTO_TYPE;
    std::vector<FileInfo> fileInfos = {fileInfo};
    int32_t fileMoveCount = 0;
    int32_t videoFileMoveCount = 0;
    int32_t sceneCode = 0;
    restoreService->MoveMigrateCloudFile(fileInfos, fileMoveCount, videoFileMoveCount, sceneCode);
    EXPECT_EQ(restoreService->migrateFileNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_cloud_photo_file_exist_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_cloud_photo_file_exist_test");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag resultExistFlag;
    restoreService->GetCloudPhotoFileExistFlag(fileInfo, resultExistFlag);
    EXPECT_FALSE(resultExistFlag.isLcdExist);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_cloud_photo_files_verify_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_cloud_photo_files_verify_test");
    FileInfo fileInfo1;
    fileInfo1.cloudPath = TEST_DIR_PATH;
    fileInfo1.orientation = TEST_ORIENTATION_NINETY;
    FileInfo fileInfo2;
    fileInfo2.cloudPath = TEST_DIR_PATH;
    fileInfo2.orientation = TEST_ORIENTATION_ZERO;
    std::vector<FileInfo> fileInfos = {fileInfo1, fileInfo2};
    std::vector<FileInfo> LCDNotFound;
    std::vector<FileInfo> THMNotFound;
    CloudPhotoFileExistFlag resultExistFlag;
    unordered_map<string, CloudPhotoFileExistFlag> resultExistMap = {
        {"test", resultExistFlag}
    };
    restoreService->CloudPhotoFilesVerify(fileInfos, LCDNotFound, THMNotFound, resultExistMap);
    EXPECT_EQ(LCDNotFound.size(), fileInfos.size());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_photo_test");
    FileInfo fileInfo;
    fileInfo.isNew = true;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertPhoto(fileInfos);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_cloud_photo_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_cloud_photo_test");
    FileInfo fileInfo;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertCloudPhoto(CLONE_RESTORE_ID, fileInfos, 0);
    EXPECT_EQ(restoreService->migrateCloudSuccessNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_batch_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_photo_batch_test");
    restoreService->RestorePhotoBatch(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
    restoreService->RestorePhotoBatch(0, 1);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_batch_for_cloud_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_for_cloud_test");
    restoreService->RestoreBatchForCloud(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
    restoreService->RestoreBatchForCloud(0, 1);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_asset_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_asset_test_001");
    FileInfo fileInfo;
    fileInfo.isRelatedToPhotoMap = 1;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_SUCCESS;
    int32_t ret = restoreService->MoveAsset(fileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_asset_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_asset_test_002");
    FileInfo fileInfo;
    fileInfo.isRelatedToPhotoMap = 0;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_NO_THUMBNAIL;
    int32_t ret = restoreService->MoveAsset(fileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_thumbnail_insert_value_test_001");
    FileInfo fileInfo;
    NativeRdb::ValuesBucket values;
    restoreService->hasCloneThumbnailDir_ = false;
    restoreService->GetThumbnailInsertValue(fileInfo, values);
    int lcdVisitTime;
    ValueObject valueObject;
    values.GetObject(PhotoColumn::PHOTO_LCD_VISIT_TIME, valueObject);
    valueObject.GetInt(lcdVisitTime);
    EXPECT_EQ(lcdVisitTime, RESTORE_LCD_VISIT_TIME_NO_LCD);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_thumbnail_insert_value_test_002");
    FileInfo fileInfo;
    NativeRdb::ValuesBucket values;
    restoreService->hasCloneThumbnailDir_ = true;
    restoreService->isInitKvstoreSuccess_ = false;
    restoreService->GetThumbnailInsertValue(fileInfo, values);
    int thumbnailReady;
    ValueObject valueObject;
    values.GetObject(PhotoColumn::PHOTO_THUMBNAIL_READY, valueObject);
    valueObject.GetInt(thumbnailReady);
    EXPECT_EQ(thumbnailReady, RESTORE_THUMBNAIL_READY_NO_THUMBNAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_thumbnail_insert_value_test_003");
    FileInfo fileInfo;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_NO_THUMBNAIL;
    NativeRdb::ValuesBucket values;
    restoreService->hasCloneThumbnailDir_ = true;
    restoreService->isInitKvstoreSuccess_ = true;
    restoreService->GetThumbnailInsertValue(fileInfo, values);
    int thumbnailReady;
    ValueObject valueObject;
    values.GetObject(PhotoColumn::PHOTO_THUMBNAIL_READY, valueObject);
    valueObject.GetInt(thumbnailReady);
    EXPECT_EQ(thumbnailReady, RESTORE_THUMBNAIL_READY_NO_THUMBNAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_gallery_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_gallery_test");
    restoreService->RestoreGallery();
    EXPECT_EQ(restoreService->isSyncSwitchOn_, false);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_cloud_path_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_prepare_cloud_path_test");
    FileInfo fileInfo1;
    fileInfo1.relativePath = TEST_DIR_PATH;
    fileInfo1.isNew = true;
    fileInfo1.isRelatedToPhotoMap = 1;
    std::string tableName = TEST_DIR_PATH;
    bool ret = restoreService->PrepareCloudPath(tableName, fileInfo1);
    EXPECT_EQ(ret, false);

    FileInfo fileInfo2;
    fileInfo2.relativePath = TEST_DIR_PATH;
    fileInfo2.isNew = false;
    ret = restoreService->PrepareCloudPath(tableName, fileInfo2);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_music_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_music_test");
    restoreService->RestoreMusic();
    EXPECT_EQ(restoreService->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_audio_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_audio_test");
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    FileInfo fileInfo;
    fileInfo.filePath = TEST_DIR_PATH;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertAudio(fileInfos);
    EXPECT_EQ(restoreService->migrateAudioFileNumber_, 0);
    restoreService->mediaLibraryRdb_ = nullptr;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_batch_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_test");
    restoreService->RestorePhotoBatch(0, 0);
    restoreService->RestoreBatchForCloud(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_related_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_photo_related_test");
    FileInfo fileInfo;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertPhotoRelated(fileInfos);
    EXPECT_EQ(restoreService->migrateDatabaseMapNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_batch_update_file_info_data_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_batch_update_file_info_data_test");
    FileInfo fileInfo1, fileInfo2;
    fileInfo1.cloudPath = TEST_DIR_PATH;
    fileInfo1.orientation = TEST_ORIENTATION_ZERO;
    fileInfo2.cloudPath = TEST_DIR_PATH;
    fileInfo2.orientation = TEST_ORIENTATION_NINETY;
    std::vector<FileInfo> fileInfos = {fileInfo1, fileInfo2};
    CloudPhotoFileExistFlag resultExistFlag;
    unordered_map<string, CloudPhotoFileExistFlag> resultExistMap;
    resultExistFlag.isThmExist = true;
    resultExistFlag.isLcdExist = true;
    resultExistMap[TEST_DIR_PATH] = resultExistFlag;
    restoreService->BatchUpdateFileInfoData(fileInfos, resultExistMap);
    EXPECT_EQ(restoreService->CheckThumbReady(fileInfos[0], resultExistFlag), RESTORE_THUMBNAIL_READY_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_001");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_ZERO;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isThmExist = true;
    resultExistFlag.isLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_ALL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_002");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_ZERO;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isThmExist = true;
    resultExistFlag.isLcdExist = false;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_003");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_ZERO;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isThmExist = false;
    resultExistFlag.isLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_004");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_ZERO;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isThmExist = false;
    resultExistFlag.isLcdExist = false;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_005");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = true;
    resultExistFlag.isExLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_ALL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_006");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = true;
    resultExistFlag.isExLcdExist = false;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_007");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = false;
    resultExistFlag.isExLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_008");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = false;
    resultExistFlag.isExLcdExist = false;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_start_backup_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_backup_test");
    bool ret = restoreService->BackupKvStore();
    restoreService->StartBackup();
    EXPECT_EQ(ret, MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test1, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test1 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_IMAGE_FACE_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();

    restoreService->cloneRestoreGeo_.GetGeoKnowledgeInfos();
    restoreService->cloneRestoreGeo_.GetAnalysisGeoInfos();
    EXPECT_EQ(restoreService->cloneRestoreGeo_.geoInfos_.size(), 0);
    EXPECT_EQ(restoreService->cloneRestoreGeo_.anaTotalfos_.size(), 0);
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test1 end");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test2, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test2 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_IMAGE_FACE_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    CloneRestoreGeo::GeoCloneInfo info;
    restoreService->cloneRestoreGeo_.geoInfos_.emplace_back(info);

    std::vector<FileInfo> fileInfos;
    restoreService->cloneRestoreGeo_.RestoreMaps(fileInfos);
    EXPECT_EQ(restoreService->cloneRestoreGeo_.successUpdateCnt_, 0);
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test2 end");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test3, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test3 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_IMAGE_FACE_TABLE };
    Init(cloneSource, TEST_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    CloneRestoreGeo::GeoCloneInfo info;
    restoreService->cloneRestoreGeo_.geoInfos_.emplace_back(info);

    constexpr double DOUBLE_EPSILON = 1e-15;
    std::vector<FileInfo> fileInfos;
    FileInfo info1;
    info1.fileIdNew = 0;
    fileInfos.push_back(info1);
    FileInfo info2;
    info2.fileIdNew = 1;
    info2.latitude = DOUBLE_EPSILON + 1.0;
    info2.longitude = DOUBLE_EPSILON + 1.0;
    fileInfos.push_back(info2);
    restoreService->cloneRestoreGeo_.RestoreMaps(fileInfos);
    EXPECT_EQ(restoreService->cloneRestoreGeo_.successUpdateCnt_, 0);
    MEDIA_INFO_LOG("medialibrary_backup_test_geo_knowledge_clone_test3 end");
}
} // namespace Media
} // namespace OHOS