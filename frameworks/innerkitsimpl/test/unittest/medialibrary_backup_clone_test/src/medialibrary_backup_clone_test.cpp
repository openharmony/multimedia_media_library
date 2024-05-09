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
#include "clone_restore.h"
#undef private
#undef protected

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
const string TEST_BACKUP_PATH = "/data/test/backup/db";
const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
const string TEST_FAKE_FILE_DIR = "/fake/fake/fake.fake";
const string SHOOTING_MODE_PORTRAIT_ALBUM_NAME = "1";
const string WHERE_CLAUSE_SHOOTING_MODE = "shooting_mode = '1'";
const string WHERE_CLAUSE_TRASHED = "date_trashed > 0";
const string WHERE_CLAUSE_IS_FAVORITE = "is_favorite > 0";
const string WHERE_CLAUSE_HIDDEN = "hidden > 0";
const string WHERE_CLAUSE_EDIT = "edit_time > 0";
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

shared_ptr<MediaLibraryRdbStore> g_rdbStore;
unique_ptr<CloneRestore> restoreService = nullptr;
unordered_map<int32_t, int32_t> updateResult;

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
    MediaLibraryRdbUtils::UpdateAllAlbums(g_rdbStore->GetRaw(), updateResult);
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
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
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
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_album_test_001 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
    restoreService->RestoreAlbum();
    int32_t sourceAlbumCount = GetAlbumCountByCondition(g_rdbStore->GetRaw(), PhotoAlbumColumns::TABLE,
        PhotoAlbumSubType::SOURCE_GENERIC);
    EXPECT_EQ(sourceAlbumCount, EXPECTED_SOURCE_ALBUM_COUNT);
    int32_t userAlbumCount = GetAlbumCountByCondition(g_rdbStore->GetRaw(), PhotoAlbumColumns::TABLE,
        PhotoAlbumSubType::USER_GENERIC);
    EXPECT_EQ(userAlbumCount, EXPECTED_USER_ALBUM_COUNT);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_album_test_002 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_photo_test_001 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
    restoreService->RestoreAlbum();
    vector<FileInfo> fileInfos = restoreService->QueryFileInfos(0);
    int32_t photoCount = static_cast<int32_t>(fileInfos.size());
    EXPECT_EQ(photoCount, EXPECTED_PHOTO_COUNT);
    EXPECT_EQ(HasZeroSizeFile(fileInfos), false);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

vector<NativeRdb::ValuesBucket> GetInsertValues(vector<FileInfo> &fileInfos, int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (auto &fileInfo : fileInfos) {
        fileInfo.cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfo.relativePath);
        if (restoreService->HasSameFile(restoreService->mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE, fileInfo)) {
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_photo_test_002 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
    restoreService->RestoreAlbum();
    RestorePhoto();
    int32_t photoCount = GetCountByWhereClause(PhotoColumn::PHOTOS_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(photoCount, EXPECTED_PHOTO_COUNT);
    int32_t photoMapCount = GetMapCountByTable(g_rdbStore->GetRaw(), PhotoMap::TABLE);
    EXPECT_EQ(photoMapCount, EXPECTED_PHOTO_MAP_COUNT);
    int32_t analysisPhotoMapCount = GetMapCountByTable(g_rdbStore->GetRaw(), ANALYSIS_PHOTO_MAP_TABLE);
    EXPECT_EQ(analysisPhotoMapCount, EXPECTED_ANALYSIS_PHOTO_MAP_COUNT);
    for (const auto &whereClause : WHERE_CLAUSE_LIST_PHOTO) {
        int32_t count = GetCountByWhereClause(PhotoColumn::PHOTOS_TABLE, g_rdbStore->GetRaw(), whereClause);
        int32_t expectedCount = whereClause == WHERE_CLAUSE_EDIT ? EXPECTED_COUNT_0 : EXPECTED_COUNT_1;
        EXPECT_EQ(count, expectedCount);
    }
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_photo_test_003 start");
    int32_t photoCountBefore = GetCountByWhereClause(PhotoColumn::PHOTOS_TABLE, g_rdbStore->GetRaw());
    int32_t albumCountBefore = GetAlbumOrMapTotalCount(g_rdbStore->GetRaw(), ALBUM_TABLE_MAP, true);
    int32_t mapCountBefore = GetAlbumOrMapTotalCount(g_rdbStore->GetRaw(), ALBUM_TABLE_MAP, false);
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_PHOTO);
    restoreService->RestoreAlbum();
    RestorePhoto();
    int32_t photoCountAfter = GetCountByWhereClause(PhotoColumn::PHOTOS_TABLE, g_rdbStore->GetRaw());
    int32_t albumCountAfter = GetAlbumOrMapTotalCount(g_rdbStore->GetRaw(), ALBUM_TABLE_MAP, true);
    int32_t mapCountAfter = GetAlbumOrMapTotalCount(g_rdbStore->GetRaw(), ALBUM_TABLE_MAP, false);
    EXPECT_EQ(photoCountBefore, photoCountAfter);
    EXPECT_EQ(albumCountBefore, albumCountAfter);
    EXPECT_EQ(mapCountBefore, mapCountAfter);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_table_column_status_test_003");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_AUDIO);
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
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_AUDIO);
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
        fileInfo.isNew = !restoreService->HasSameFile(restoreService->mediaLibraryRdb_, tableName, fileInfo);
    }
}

void InsertAudio(vector<FileInfo> &fileInfos, const unordered_set<int32_t> &excludedFileIdSet = {})
{
    PrepareFileInfos(AudioColumn::AUDIOS_TABLE, fileInfos);
    vector<NativeRdb::ValuesBucket> values = restoreService->GetInsertValues(AudioColumn::AUDIOS_TABLE,
        CLONE_RESTORE_ID, fileInfos, SourceType::AUDIOS, excludedFileIdSet);
    int64_t rowNum = 0;
    int32_t errCode = restoreService->BatchInsertWithRetry(AudioColumn::AUDIOS_TABLE, values, rowNum);
    EXPECT_EQ(errCode, E_OK);
}

void RestoreAudio()
{
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(restoreService->mediaRdb_,
        AudioColumn::AUDIOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(
        restoreService->mediaLibraryRdb_, AudioColumn::AUDIOS_TABLE);
    if (!restoreService->PrepareCommonColumnInfoMap(AudioColumn::AUDIOS_TABLE, srcColumnInfoMap, dstColumnInfoMap)) {
        MEDIA_ERR_LOG("Prepare common column info failed");
        return;
    }
    vector<FileInfo> fileInfos = restoreService->QueryFileInfos(AudioColumn::AUDIOS_TABLE, 0);
    InsertAudio(fileInfos);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_002 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_AUDIO);
    RestoreAudio();
    int32_t audioCount = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(audioCount, EXPECTED_AUDIO_COUNT);
    for (const auto &whereClause : WHERE_CLAUSE_LIST_AUDIO) {
        int32_t count = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw(), whereClause);
        EXPECT_EQ(count, EXPECTED_COUNT_1);
    }
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_003 start");
    int32_t audioCountBefore = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw());
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_; // source database
    restoreService->CheckTableColumnStatus(CLONE_TABLE_LISTS_AUDIO);
    RestoreAudio();
    int32_t audioCountAfter = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(audioCountBefore, audioCountAfter);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_file_valid_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_file_valid_test_001 start");
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_DB_PATH, CLONE_RESTORE_ID), true);
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_BACKUP_PATH, CLONE_RESTORE_ID), false); // directory
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_FAKE_FILE_DIR, CLONE_RESTORE_ID), false); // not exist
}
} // namespace Media
} // namespace OHOS