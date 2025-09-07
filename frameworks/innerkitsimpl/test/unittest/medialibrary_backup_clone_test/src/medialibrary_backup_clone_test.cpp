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
#include "clone_restore_analysis_data.h"
#include "clone_restore_geo.h"
#include "clone_restore_classify.h"
#include "clone_restore_portrait_album.h"
#include "video_face_clone.h"
#include "beauty_score_clone.h"
#include "search_index_clone.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "others_clone_restore.h"
#include "photos_dao.h"
#include "photos_data_handler.h"
#include "burst_key_generator.h"
#undef protected
#undef private
#include "parameters.h"
#include "media_config_info_column.h"

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
const string SEGMENTATION_ANALYSIS_TABLE = "tab_analysis_segmentation";
const string SEGMENTATION_TYPE = "segmentation";
const int32_t SEGMENTATION_TABLE_SIZE = 7;
const int32_t TEST_ORIENTATION_ZERO = 0;
const int32_t TEST_ORIENTATION_NINETY = 90;
const int32_t I_PHONE_DYNAMIC_VIDEO_TYPE = 13;
const int32_t PAGE_SIZE = 200;
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
    "DELETE FROM " + SEGMENTATION_ANALYSIS_TABLE,
    "DELETE FROM " + VISION_LABEL_TABLE,
    "DELETE FROM " + VISION_VIDEO_LABEL_TABLE,
    "DELETE FROM " + GEO_KNOWLEDGE_TABLE,
    "DELETE FROM " + VISION_TOTAL_TABLE,
    "DELETE FROM " + ANALYSIS_SEARCH_INDEX_TABLE,
    "DELETE FROM " + ANALYSIS_VIDEO_FACE_TABLE,
    "DELETE FROM " + ANALYSIS_BEAUTY_SCORE_TABLE,
    "DELETE FROM " + ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME,
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
const std::string DIRTY_FILE_ID = "1000";
const std::string DIRTY_FILE_PATH = "/storage/cloud/files/Documents/1.jpg";

const int PHONE_FIRST_NUMBER = 105;
const int PHONE_SECOND_NUMBER = 80;
const int PHONE_THIRD_NUMBER = 104;
const int PHONE_FOURTH_NUMBER = 111;
const int PHONE_FIFTH_NUMBER = 110;
const int PHONE_SIXTH_NUMBER = 101;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

const std::string DEFAULT_DEVICE_ID = "device_id";
const std::string CONFIG_INFO_INVALID_KEY = "invalid_key";
const std::string CONFIG_INFO_INVALID_VALUE = "invalid_value";

shared_ptr<MediaLibraryRdbStore> g_rdbStore;
unique_ptr<CloneRestore> restoreService = nullptr;

static const std::string CLOUDSYNC_SWITCH_STATUS_KEY = "persist.kernel.cloudsync.switch_status";
static constexpr int64_t RESTORE_OR_BACKUP_WAIT_FORCE_RETAIN_CLOUD_MEDIA_TIMEOUT_MILLISECOND = 60 * 60 * 1000;
static constexpr int64_t TIMEOUT_DELTA = 1;
static const std::string BACKUP_FLAG = "multimedia.medialibrary.backupFlag";
static const int64_t DEFAULT_TIME_STAMP = 0;
static const int RELEASE_SCENE_RESTORE = 2;
static const int RELEASE_SCENE_BACKUP = 1;

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
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
}

void MediaLibraryBackupCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearData();
    restoreService->mediaLibraryRdb_ = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaLibraryBackupCloneTest::SetUp()
{
    OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP));
    OHOS::system::SetParameter(BACKUP_FLAG, std::to_string(DEFAULT_TIME_STAMP));
    OHOS::system::SetParameter(BACKUP_FLAG, std::to_string(DEFAULT_TIME_STAMP));
}

void MediaLibraryBackupCloneTest::TearDown(void) {}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_restore_test_001");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    EXPECT_EQ(restoreService->IsReadyForRestore(PhotoColumn::PHOTOS_TABLE), true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_table_column_status_test_002");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_album_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_album_test_002 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_table_column_status_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_table_column_status_test_003");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(restoreService->IsReadyForRestore(AudioColumn::AUDIOS_TABLE), true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_001 start");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_002 start");
    int32_t count = 3;
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(count, EXPECTED_AUDIO_COUNT);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_audio_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_restore_audio_test_003 start");
    int32_t audioCountBefore = GetCountByWhereClause(AudioColumn::AUDIOS_TABLE, g_rdbStore->GetRaw());
    int32_t count = 3;
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    EXPECT_EQ(count, EXPECTED_AUDIO_COUNT);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_file_valid_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_file_valid_test_001 start");
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_DB_PATH, CLONE_RESTORE_ID), E_OK);
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_BACKUP_PATH, CLONE_RESTORE_ID), E_FAIL);
    EXPECT_EQ(BackupFileUtils::IsFileValid(TEST_FAKE_FILE_DIR, CLONE_RESTORE_ID), E_NO_SUCH_FILE);
}

void ClearRestoreExInfo()
{
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->errorInfo_.clear();
    restoreService->failedFilesMap_.clear();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_001 start");
    RestoreInfo info;
    info.sceneCode = UPGRADE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    BackupRestoreService::GetInstance().restoreService_ = nullptr;
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_002 start");
    RestoreInfo info;
    info.sceneCode = DUAL_FRAME_CLONE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().restoreService_ = nullptr;
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_restore_ex_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_restore_ex_003 start");
    RestoreInfo info;
    info.sceneCode = CLONE_RESTORE_ID;
    info.galleryAppName = EMPTY_STR;
    info.mediaAppName = EMPTY_STR;
    info.backupDir = EMPTY_STR;
    info.bundleInfo = EMPTY_STR;
    string restoreExInfo = INVALID_STR;
    BackupRestoreService::GetInstance().restoreService_ = nullptr;
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    BackupRestoreService::GetInstance().StartRestoreEx(nullptr, info, restoreExInfo);
    MEDIA_INFO_LOG("Get restoreExInfo: %{public}s", restoreExInfo.c_str());
    EXPECT_NE(restoreExInfo, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_get_backup_info_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_get_backup_info_001 start");
    string backupInfo = INVALID_STR;
    BackupRestoreService::GetInstance().GetBackupInfo(UPGRADE_RESTORE_ID, backupInfo);
    MEDIA_INFO_LOG("Get backupInfo: %{public}s", backupInfo.c_str());
    EXPECT_EQ(backupInfo, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_get_restore_ex_info_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_set_error_code_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_set_error_code_001 start");
    ClearRestoreExInfo();
    restoreService->SetErrorCode(RestoreError::INIT_FAILED);
    MEDIA_INFO_LOG("Get errorCode: %{public}d, errorInfo: %{public}s", restoreService->errorCode_,
        restoreService->errorInfo_.c_str());
    EXPECT_GT(restoreService->errorInfo_.size(), 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_set_error_code_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_set_error_code_002 start");
    ClearRestoreExInfo();
    restoreService->SetErrorCode(INVALID_ERROR_CODE);
    MEDIA_INFO_LOG("Get errorCode: %{public}d, errorInfo: %{public}s", restoreService->errorCode_,
        restoreService->errorInfo_.c_str());
    EXPECT_EQ(restoreService->errorInfo_.size(), 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_base_update_failed_files_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_backup_info_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_base_get_backup_info_001 start");
    string backupInfo = restoreService->GetBackupInfo();
    MEDIA_INFO_LOG("Get backupInfo: %{public}s", backupInfo.c_str());
    EXPECT_GT(backupInfo.size(), 0);
    nlohmann::json jsonObject = nlohmann::json::parse(backupInfo);
    EXPECT_EQ(jsonObject.empty(), false);
    EXPECT_EQ(jsonObject.is_discarded(), false);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_get_failed_files_str_001, TestSize.Level2)
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
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_001, TestSize.Level2)
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
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_002, TestSize.Level2)
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
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_file_burst_key_generator_003, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_restore_OthersCloneRestore_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "");
    EXPECT_EQ(othersClone->clonePhoneName_, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "[\n\t\t\"type\":\t\"backupInfo\"]");
    EXPECT_EQ(othersClone->clonePhoneName_, GetPhoneName());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_003");

    std::string json = string("[{\n\t\t\"type\":\t\"deviceType\",\n\t\t\"detail\":\t\"test\"\n\t},") +
        " {\n\t\t\"type\":\t\"userId\",\n\t\t\"detail\":\t\"100\"\n\t}]";
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", json);
    EXPECT_EQ(othersClone->clonePhoneName_, "test");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_OthersCloneRestore_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_OthersCloneRestore_004");

    std::string json = string("[{\n\t\t\"type\":\t\"device\",\n\t\t\"detail\":\t\"test\"\n\t},") +
        " {\n\t\t\"type\":\t\"userId\",\n\t\t\"detail\":\t\"100\"\n\t}]";
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", json);
    EXPECT_EQ(othersClone->clonePhoneName_, GetPhoneName());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetCloneDbInfos_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetCloneDbInfos_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<CloneDbInfo> vec;
    othersClone->GetCloneDbInfos("aaa", vec);
    EXPECT_TRUE(vec.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetCloneDbInfos_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetCloneDbInfos_002");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    store->ExecuteSql(string("CREATE TABLE IF NOT EXISTS mediaInfo ") +
        "(_data TEXT, latitude DOUBLE, longitude DOUBLE, datetaken DOUBLE, date_modified DOUBLE, primaryStr TEXT)");
    store->ExecuteSql(string("INSERT INTO mediaInfo (_data, latitude, longitude, datetaken,") +
        " date_modified, primaryStr) VALUES ('/storage/emulated', 0, 0, 1726123123, 1726123.123, '1234563.jpg')");
    std::vector<CloneDbInfo> vec;
    othersClone->GetCloneDbInfos("photo_MediaInfo.db", vec);
    EXPECT_FALSE(vec.empty());
    store->ExecuteSql("DROP TABLE IF EXISTS mediaInfo");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    EXPECT_NE(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_002");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;

    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    othersClone->mediaLibraryRdb_ = store;
    EXPECT_NE(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_Init_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_Init_003");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;

    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    othersClone->mediaLibraryRdb_ = store;
    othersClone->backupRestoreDir_ = "/storage/media/100/local/files/";
    EXPECT_EQ(othersClone->Init("/data/photo", "/data/test", true), E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetInsertValue_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetInsertValue_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.gif", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.gif");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.mp4", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.mp4");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.mp3", st);
    EXPECT_EQ(othersClone->audioInfos_[0].filePath, "filePath/test.mp3");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.ief", st);
    EXPECT_EQ(othersClone->photoInfos_[0].filePath, "filePath/test.ief");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_005");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/test.txt", st);
    EXPECT_TRUE(othersClone->photoInfos_.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_006");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/0000000000000000000_BURST000_COVER.jpg", st);
    EXPECT_EQ(othersClone->photoInfos_[0].isBurst, static_cast<int32_t>(BurstCoverLevelType::COVER));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_SetFileInfosInCurrentDir_007, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_SetFileInfosInCurrentDir_007");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    struct stat st;
    othersClone->SetFileInfosInCurrentDir("filePath/0000000000000000000_BURST000.jpg", st);
    EXPECT_EQ(othersClone->photoInfos_[0].isBurst, static_cast<int32_t>(BurstCoverLevelType::MEMBER));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_001");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "TddTest", "");
    EXPECT_EQ(othersClone->mediaAppName_, "TddTest");

    FileInfo fileInfo;
    fileInfo.displayName = "test.mp3";
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.mp3";

    othersClone->UpDateFileModifiedTime(fileInfo);
    othersClone->audioDbMap_.insert(std::make_pair("test.mp3", &cloneDbInfo));
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(othersClone->audioDbMap_["test.mp3"]->fileExists, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_lite, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_lite");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(LITE_PHONE_CLONE_RESTORE,
        "TDDTest", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    EXPECT_EQ(othersClone->mediaAppName_, "TDDTest");
    FileInfo fileInfo;
    fileInfo.filePath = "/storage/media/local/files/.backup/restore/test.jpg";
    fileInfo.displayName = "/test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;

    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "/test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;

    othersClone->UpDateFileModifiedTime(fileInfo);
    othersClone->photoDbMap_.insert(std::make_pair("/test.jpg", &cloneDbInfo));
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(othersClone->photoDbMap_["/test.jpg"]->fileExists, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_003");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "TestDT", "[{\"type\":\"deviceType\",\"detail\":\"IKUNI\"}]");
    EXPECT_EQ(othersClone->clonePhoneName_, "IKUNI");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;

    othersClone->UpDateFileModifiedTime(fileInfo);
    othersClone->photoDbMap_.insert(std::make_pair("test.jpg", &cloneDbInfo));
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(othersClone->photoDbMap_["test.jpg"]->fileExists, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_004");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "TDDTest", "[{\"type\":\"deviceType\",\"detail\":\"IKUNI\"}]");
    EXPECT_EQ(othersClone->mediaAppName_, "TDDTest");
    FileInfo fileInfo;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;

    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.jpg";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->photoDbMap_.insert(std::make_pair("test.jpg", &cloneDbInfo));
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(othersClone->photoDbMap_["test.jpg"]->fileExists, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_005, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_006, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_007, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_008, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpDateFileModifiedTime_008");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "TestTDD", "[{\"type\":\"deviceType\",\"detail\":\"\"}]");
    EXPECT_EQ(othersClone->clonePhoneName_.empty(), false);
    FileInfo fileInfo;
    fileInfo.displayName = "test.mov";
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;

    CloneDbInfo cloneDbInfo;
    cloneDbInfo.displayName = "test.mov";
    cloneDbInfo.dateModified = 1;
    cloneDbInfo.dateTaken = 1;
    othersClone->UpDateFileModifiedTime(fileInfo);

    othersClone->photoDbMap_.insert(std::make_pair("test.mov", &cloneDbInfo));
    othersClone->UpDateFileModifiedTime(fileInfo);
    EXPECT_EQ(othersClone->photoDbMap_["test.mov"]->fileExists, true);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpDateFileModifiedTime_009, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetAllfilesInCurrentDir_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetAllfilesInCurrentDir_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    auto err = othersClone->GetAllfilesInCurrentDir("/storage/media/100/local/test/test");
    EXPECT_EQ(err, ERR_NOT_ACCESSIBLE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_GetAllfilesInCurrentDir_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_GetAllfilesInCurrentDir_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    auto err = othersClone->GetAllfilesInCurrentDir("/storage/media/100/local/files/");
    EXPECT_EQ(err, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestorePhoto_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestorePhoto();
    EXPECT_EQ(othersClone->totalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_003, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestorePhoto_004, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_InsertPhoto_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_InsertPhoto_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<FileInfo> fileInfos;
    othersClone->InsertPhoto(fileInfos);
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_InsertPhoto_002, TestSize.Level2)
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
    EXPECT_EQ(othersClone->migrateDatabaseNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAudio_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAudio_003");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    othersClone->audioInfos_.push_back(fileInfo);
    othersClone->RestoreAudio();
    EXPECT_EQ(othersClone->audioTotalNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAlbum_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_RestoreAlbum_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");

    std::vector<FileInfo> fileInfos;
    othersClone->RestoreAlbum(fileInfos);
    EXPECT_TRUE(othersClone->photoAlbumDao_.mediaLibraryRdb_ == nullptr);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_RestoreAlbum_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HasSameFileForDualClone_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HasSameFileForDualClone_001");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;

    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    othersClone->photosRestore_.OnStart(store, store);
    EXPECT_FALSE(othersClone->HasSameFileForDualClone(fileInfo));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HasSameFileForDualClone_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HasSameFileForDualClone_002");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.fileType = MEDIA_TYPE_VIDEO;
    fileInfo.displayName = "test.jpg";
    fileInfo.fileSize = 100;

    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;

    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    store->ExecuteSql(string("INSERT INTO Photos (file_id, data, display_name, size, owner_album_id") +
        ") VALUES (1, 'test', 'test.jpg', 100, 0)");

    othersClone->photosRestore_.photosBasicInfo_.maxFileId = 100;
    othersClone->photosRestore_.OnStart(store, store);
    EXPECT_TRUE(othersClone->HasSameFileForDualClone(fileInfo));
    store->ExecuteSql("DROP TABLE IF EXISTS Photos");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpdateAlbumInfo_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_UpdateAlbumInfo_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    othersClone->clonePhoneName_ = "testPhone";
    othersClone->UpdateAlbumInfo(fileInfo);
    EXPECT_EQ(fileInfo.bundleName, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_UpdateAlbumInfo_002, TestSize.Level2)
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
    TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_NeedBatchQueryPhotoForPortrait_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<FileInfo> fileInfos;
    NeedQueryMap needQueryMap;
    EXPECT_TRUE(othersClone->NeedBatchQueryPhotoForPortrait(fileInfos, needQueryMap));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleRestData_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleRestData_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    othersClone->HandleRestData();
    EXPECT_EQ(othersClone->otherProcessStatus_, ProcessStatus::STOP);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_ParseResultSet_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_ParseResultSet_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    FileInfo fileInfo;
    std::string dbName;
    EXPECT_TRUE(othersClone->ParseResultSet(resultSet, fileInfo, dbName));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_ParseResultSetForAudio_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_ParseResultSetForAudio_001");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    FileInfo fileInfo;
    EXPECT_TRUE(othersClone->ParseResultSetForAudio(resultSet, fileInfo));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_CloneInfoPushBack_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_CloneInfoPushBack_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_CloneInfoPushBack_002");

    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    std::vector<CloneDbInfo> pushInfos;
    std::vector<CloneDbInfo> popInfos;
    othersClone->CloneInfoPushBack(pushInfos, popInfos);
    EXPECT_TRUE(pushInfos.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_002");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    std::shared_ptr<NativeRdb::RdbStore> mediaRdb = store;
    int32_t offset = 1;
    int32_t sceneCode = I_PHONE_CLONE_RESTORE;
    std::vector<CloneDbInfo> mediaDbInfo;
    othersClone->HandleSelectBatch(mediaRdb, offset, sceneCode, mediaDbInfo);
    EXPECT_TRUE(mediaDbInfo.empty());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_003");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleSelectBatch_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_HandleSelectBatch_004");
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(OTHERS_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    string cmdMkdir = string("mkdir -p ") + "/storage/media/local/files/.backup/restore/storage/emulated/0";
    ::system(cmdMkdir.c_str());
    std::string path = "/storage/media/local/files/.backup/restore/storage/emulated/0/photo_MediaInfo.db";
    NativeRdb::RdbStoreConfig config(path);
    CloneOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleInsertBatch_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_HandleInsertBatch_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_backup_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_rebackup_001 start");
    BackupRestoreService &instance = BackupRestoreService::GetInstance();
    ASSERT_NE(&instance, nullptr);
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    instance.restoreService_ = nullptr;
    instance.StartBackup(UPGRADE_RESTORE_ID, EMPTY_STR, EMPTY_STR);
    instance.restoreService_ = nullptr;
    instance.StartBackup(CLONE_RESTORE_ID, EMPTY_STR, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_start_backup_ex_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_start_backup_ex_001 start");

    BackupRestoreService &instance = BackupRestoreService::GetInstance();
    ASSERT_NE(&instance, nullptr);
    std::string backupExResult = EMPTY_STR;
    instance.restoreService_ = nullptr;
    instance.StartBackupEx(UPGRADE_RESTORE_ID, EMPTY_STR, EMPTY_STR, EMPTY_STR, backupExResult);
    EXPECT_NE(backupExResult, EMPTY_STR);
    instance.restoreService_ = nullptr;
    instance.StartBackupEx(CLONE_RESTORE_ID, EMPTY_STR, EMPTY_STR, EMPTY_STR, backupExResult);
    EXPECT_NE(backupExResult, EMPTY_STR);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_service_release_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_service_release_001 start");
    BackupRestoreService &instance = BackupRestoreService::GetInstance();
    instance.restoreService_ = nullptr;
    instance.Release(nullptr, UPGRADE_RESTORE_ID, RELEASE_SCENE_RESTORE);

    instance.restoreService_ = nullptr;
    instance.Release(nullptr, CLONE_RESTORE_ID, RELEASE_SCENE_RESTORE);

    instance.restoreService_ = nullptr;
    instance.Release(nullptr, CLONE_RESTORE_ID, RELEASE_SCENE_BACKUP);

    instance.restoreService_ = nullptr;
    instance.Release(nullptr, CLONE_RESTORE_ID, -1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_thumbnail_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_thumbnail_dir_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_move_astc_test_003, TestSize.Level2)
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
    ASSERT_NE(restoreService->oldMonthKvStorePtr_, nullptr);

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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_003, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_004, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_geo_dictionary_test_005, TestSize.Level2)
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

void InitCloneRestoreAnalysisTotal(shared_ptr<CloneRestoreClassify> cloneRestoreClassify, int32_t fileIdNew)
{
    CloneRestoreAnalysisTotal::AnalysisTotalInfo info;
    info.fileIdOld = 1;
    info.fileIdNew = fileIdNew;
    cloneRestoreClassify->cloneRestoreAnalysisTotal_.analysisTotalInfos_.push_back(info);
}

void InitPhotoInfoMap(unique_ptr<CloneRestore> &cloneRestoreService, int32_t fileIdNew)
{
    PhotoInfo info;
    info.fileIdNew = fileIdNew;
    cloneRestoreService->photoInfoMap_.insert({ 1, info });
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    shared_ptr<CloneRestoreClassify> cloneRestoreClassify = make_shared<CloneRestoreClassify>();
    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), cloneSource.cloneStorePtr_);
    EXPECT_EQ(cloneRestoreClassify->taskId_, TASK_ID);
    EXPECT_EQ(cloneRestoreClassify->sceneCode_, CLONE_RESTORE_ID);
    EXPECT_NE(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreClassify->mediaLibraryRdb_, nullptr);

    InitCloneRestoreAnalysisTotal(cloneRestoreClassify, FILE_INFO_NEW_ID);
    cloneRestoreClassify->RestoreMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_, 1);
    cloneRestoreClassify->RestoreVideoMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_, 1);
    VerifyClassifyRestore(cloneRestoreClassify->mediaLibraryRdb_);
    VerifyClassifyVideoRestore(cloneRestoreClassify->mediaLibraryRdb_);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_001");
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_002, TestSize.Level2)
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
    cloneRestoreClassify->RestoreMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, g_rdbStore->GetRaw(), nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_NE(cloneRestoreClassify->mediaLibraryRdb_, nullptr);
    cloneRestoreClassify->RestoreMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    cloneRestoreClassify->Init(CLONE_RESTORE_ID, TASK_ID, nullptr, nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaRdb_, nullptr);
    EXPECT_EQ(cloneRestoreClassify->mediaLibraryRdb_, nullptr);
    cloneRestoreClassify->RestoreMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertLabelCnt_.load(), 0);
    cloneRestoreClassify->RestoreVideoMaps();
    EXPECT_EQ(cloneRestoreClassify->successInsertVideoLabelCnt_.load(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_002");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_003, TestSize.Level2)
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
    cloneRestoreClassify->GetClassifyInfos(classifyInfo);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo);
    EXPECT_EQ(classifyInfo.size(), 0);
    EXPECT_EQ(classifyVideoInfo.size(), 0);

    InitCloneRestoreAnalysisTotal(cloneRestoreClassify, FILE_INFO_NEW_ID);
    cloneRestoreClassify->GetClassifyInfos(classifyInfo);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo);
    EXPECT_EQ(classifyInfo.size(), 1);
    EXPECT_EQ(classifyVideoInfo.size(), 1);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_003");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_004, TestSize.Level2)
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
    InitCloneRestoreAnalysisTotal(cloneRestoreClassify, FILE_INFO_NEW_ID);
    cloneRestoreClassify->GetClassifyInfos(classifyInfo);
    cloneRestoreClassify->InsertClassifyAlbums(classifyInfo);
    EXPECT_EQ(classifyInfo.size(), 1);
    cloneRestoreClassify->GetClassifyVideoInfos(classifyVideoInfo);
    cloneRestoreClassify->InsertClassifyVideoAlbums(classifyVideoInfo);
    EXPECT_EQ(classifyVideoInfo.size(), 1);

    cloneRestoreClassify->cloneRestoreAnalysisTotal_.analysisTotalInfos_.clear();
    cloneRestoreClassify->DeduplicateClassifyInfos(classifyInfo);
    EXPECT_EQ(classifyInfo.size(), 0);
    cloneRestoreClassify->DeduplicateClassifyVideoInfos(classifyVideoInfo);
    EXPECT_EQ(classifyVideoInfo.size(), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_004");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_005, TestSize.Level2)
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
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_005");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_006");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();

    cloneRestoreService->RestoreAnalysisClassify();
    int32_t count = GetCountByWhereClause(VISION_LABEL_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_006");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_007, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_007");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisClassify();
    int32_t count = GetCountByWhereClause(VISION_LABEL_TABLE, g_rdbStore->GetRaw());
    EXPECT_GT(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_007");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_008, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_008");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList;
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisClassify();
    int32_t count = GetCountByWhereClause(VISION_VIDEO_LABEL_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_008");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_classify_test_009, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_classify_test_009");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_LABEL_TABLE, VISION_VIDEO_LABEL_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisClassify();
    int32_t countBefore = GetCountByWhereClause(VISION_LABEL_TABLE, g_rdbStore->GetRaw());
    cloneRestoreService->RestoreAnalysisClassify();
    int32_t countAfter = GetCountByWhereClause(VISION_LABEL_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(countBefore, countAfter);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_classify_test_009");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_dirty_count_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_dirty_count_test");
    PhotosDao photosDao_;
    photosDao_.SetMediaLibraryRdb(g_rdbStore->GetRaw());
    int32_t count = photosDao_.GetDirtyFilesCount();
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_dirty_files_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_dirty_files_test");
    PhotosDao photosDao_;
    photosDao_.SetMediaLibraryRdb(g_rdbStore->GetRaw());
    auto result = photosDao_.GetDirtyFiles(EXPECTED_COUNT_0);
    EXPECT_EQ(result.size(), EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_handle_dirty_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_handle_dirty_test");
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    photosDataHandler_.HandleDirtyFiles();
    EXPECT_EQ(photosDataHandler_.dirtyFileCleanNumber_, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_clean_dirty_files_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_clean_dirty_files_test");
    std::vector<PhotosDao::PhotosRowData> dirtyFiles;
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.CleanDirtyFiles(dirtyFiles);
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_delete_db_dirty_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_delete_db_dirty_test");
    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(EXPECTED_COUNT_0, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.DeleteDirtyFilesInDb();
    EXPECT_EQ(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_001");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = UPGRADE_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, UPGRADE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_002");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = DUAL_FRAME_CLONE_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, DUAL_FRAME_CLONE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_003");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = I_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, I_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_004");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = OTHERS_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, OTHERS_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_005");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = LITE_PHONE_CLONE_RESTORE;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, LITE_PHONE_CLONE_RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_006");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = DEFAULT_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, CLONE_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_service_init_test_007, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_service_init_test_007");
    BackupRestoreService backupRestoreService;
    RestoreInfo info;
    info.sceneCode = CLOUD_BACKUP_RESTORE_ID;
    backupRestoreService.Init(info);
    EXPECT_EQ(backupRestoreService.restoreService_->sceneCode_, CLOUD_BACKUP_RESTORE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_backup_info_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_backup_info_test");
    BackupRestoreService backupRestoreService;
    std::string backupInfo;
    backupRestoreService.GetBackupInfo(CLONE_RESTORE_ID, backupInfo);
    EXPECT_EQ(backupInfo, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_account_valid_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_account_valid_test");
    restoreService->restoreInfo_ = R"([{"type":"singleAccountId", "detail":"test"}])";
    (void)restoreService->GetAccountValid();
    EXPECT_FALSE(restoreService->isAccountValid_);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_photo_test");
    restoreService->RestorePhoto();
    restoreService->RestorePhotoForCloud();
    EXPECT_EQ(restoreService->totalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_migrate_file_test, TestSize.Level2)
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
    EXPECT_FALSE(fileInfos[0].needVisible);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_migrate_cloud_file_test, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_cloud_photo_file_exist_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_cloud_photo_file_exist_test");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag resultExistFlag;
    restoreService->GetCloudPhotoFileExistFlag(fileInfo, resultExistFlag);
    EXPECT_FALSE(resultExistFlag.isLcdExist);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_cloud_photo_files_verify_test, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_photo_test");
    FileInfo fileInfo;
    fileInfo.isNew = true;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertPhoto(fileInfos);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_cloud_photo_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_cloud_photo_test");
    FileInfo fileInfo;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertCloudPhoto(CLONE_RESTORE_ID, fileInfos, 0);
    EXPECT_EQ(restoreService->migrateCloudSuccessNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_photo_batch_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_photo_batch_test");
    restoreService->RestorePhotoBatch(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 1);
    restoreService->RestorePhotoBatch(0, 1);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_batch_for_cloud_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_for_cloud_test");
    restoreService->RestoreBatchForCloud(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 1);
    restoreService->RestoreBatchForCloud(0, 1);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_asset_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_asset_test_001");
    FileInfo fileInfo;
    fileInfo.isRelatedToPhotoMap = 1;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_SUCCESS;
    int32_t ret = restoreService->MoveAsset(fileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_move_asset_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_move_asset_test_002");
    FileInfo fileInfo;
    fileInfo.isRelatedToPhotoMap = 0;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_NO_THUMBNAIL;
    int32_t ret = restoreService->MoveAsset(fileInfo);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_003, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_gallery_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_gallery_test");
    restoreService->RestoreGallery();
    EXPECT_EQ(restoreService->isSyncSwitchOn_, false);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_cloud_path_test, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_music_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_music_test");
    restoreService->RestoreMusic();
    EXPECT_EQ(restoreService->audioTotalNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_audio_test, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_batch_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_batch_test");
    restoreService->RestorePhotoBatch(0, 0);
    restoreService->RestoreBatchForCloud(0, 0);
    EXPECT_EQ(restoreService->migrateDatabaseNumber_, 1);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_related_test, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_insert_photo_related_test");
    FileInfo fileInfo;
    std::vector<FileInfo> fileInfos = {fileInfo};
    restoreService->InsertPhotoRelated(fileInfos, SourceType::PHOTOS);
    EXPECT_EQ(restoreService->migrateDatabaseMapNumber_, 0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_batch_update_file_info_data_test, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_001, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_002, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_003, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_004, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_005");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = true;
    resultExistFlag.isExLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_ALL);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_006");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = true;
    resultExistFlag.isExLcdExist = false;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_007, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_check_thumb_status_test_007");
    FileInfo fileInfo;
    fileInfo.orientation = TEST_ORIENTATION_NINETY;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    CloudPhotoFileExistFlag resultExistFlag;
    resultExistFlag.isExThmExist = false;
    resultExistFlag.isExLcdExist = true;
    int32_t ret = restoreService->CheckThumbStatus(fileInfo, resultExistFlag);
    EXPECT_EQ(ret, RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_008, TestSize.Level2)
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

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_start_backup_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_backup_test_001");
    bool ret = restoreService->BackupKvStore();
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->StartBackup();
    EXPECT_NE(restoreService->errorCode_, RestoreError::SUCCESS);
    EXPECT_EQ(ret, MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR));
}


HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_start_backup_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_backup_test_002");
    bool ret = restoreService->BackupKvStore();
    int64_t triggerTimeoutStartTime = MediaFileUtils::UTCTimeMilliSeconds() - \
                RESTORE_OR_BACKUP_WAIT_FORCE_RETAIN_CLOUD_MEDIA_TIMEOUT_MILLISECOND - TIMEOUT_DELTA;
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(triggerTimeoutStartTime)));
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->StartBackup();
    EXPECT_NE(restoreService->errorCode_, RestoreError::SUCCESS);
    EXPECT_EQ(ret, MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_start_backup_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_backup_test_003");
    bool ret = restoreService->BackupKvStore();
    CloneSource cloneSource;
    std::vector<std::string> tableList = {PhotoColumn::PHOTOS_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaLibraryRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->StartBackup();
    EXPECT_NE(restoreService->errorCode_, RestoreError::SUCCESS);
    EXPECT_EQ(ret, MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR));
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_start_backup_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_start_backup_test_004");
    bool ret = restoreService->BackupKvStore();
    CloneSource cloneSource;
    std::vector<std::string> tableList = {PhotoColumn::PHOTOS_TABLE, ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaLibraryRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, std::to_string(DEFAULT_TIME_STAMP)));
    restoreService->errorCode_ = RestoreError::SUCCESS;
    restoreService->StartBackup();
    EXPECT_EQ(restoreService->errorCode_, RestoreError::SUCCESS);
    EXPECT_EQ(ret, MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR));
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_test_geo_knowledge_clone_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_KNOWLEDGE_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();

    cloneRestoreService->RestoreAnalysisGeo();
    int32_t count = GetCountByWhereClause(GEO_KNOWLEDGE_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_test_geo_knowledge_clone_test_001");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_test_geo_knowledge_clone_test_002");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_KNOWLEDGE_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisGeo();
    int32_t count = GetCountByWhereClause(GEO_KNOWLEDGE_TABLE, g_rdbStore->GetRaw());
    EXPECT_GT(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_test_geo_knowledge_clone_test_002");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_test_geo_knowledge_clone_test_003");
    ClearData();
    CloneSource cloneSource;
    vector<string> tableList;
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisGeo();
    int32_t count = GetCountByWhereClause(GEO_KNOWLEDGE_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(count, 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_test_geo_knowledge_clone_test_003");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_test_geo_knowledge_clone_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_test_geo_knowledge_clone_test_004");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { GEO_KNOWLEDGE_TABLE, VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    cloneRestoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneRestoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    InitPhotoInfoMap(cloneRestoreService, FILE_INFO_NEW_ID);

    cloneRestoreService->RestoreAnalysisGeo();
    int32_t countBefore = GetCountByWhereClause(GEO_KNOWLEDGE_TABLE, g_rdbStore->GetRaw());
    cloneRestoreService->RestoreAnalysisGeo();
    int32_t countAfter = GetCountByWhereClause(GEO_KNOWLEDGE_TABLE, g_rdbStore->GetRaw());
    EXPECT_EQ(countBefore, countAfter);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_test_geo_knowledge_clone_test_004");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_001");
    ClearData();
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.filePath = "/storage/media/100/local/test/test.jpg";
    bool isDynamic = othersClone->IsIosMovingPhotoVideo(fileInfo, I_PHONE_CLONE_RESTORE);
    EXPECT_FALSE(isDynamic);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_002");
    ClearData();
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.filePath = "/storage/media/100/local/test/test_DYNAMIC.jpg";
    othersClone->IsIosMovingPhotoVideo(fileInfo, I_PHONE_CLONE_RESTORE);
    EXPECT_EQ(fileInfo.subtype, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_others_clone_IsIosMovingPhotoVideo_test_003");
    ClearData();
    unique_ptr<OthersCloneRestore> othersClone = std::make_unique<OthersCloneRestore>(I_PHONE_CLONE_RESTORE,
        "", "{\"type\":\"unicast\",\"details\":[{\"type\":\"iosDeviceType\",\"detail\":\"test\"}]}");
    FileInfo fileInfo;
    fileInfo.filePath = "/storage/media/100/local/test/test_DYNAMIC.MOV";
    othersClone->IsIosMovingPhotoVideo(fileInfo, I_PHONE_CLONE_RESTORE);
    EXPECT_EQ(fileInfo.otherSubtype, I_PHONE_DYNAMIC_VIDEO_TYPE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clean_dirty_files_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clean_dirty_files_test_001");
    PhotosDao::PhotosRowData dirtyFileNotLocal;
    dirtyFileNotLocal.position = static_cast<int32_t>(PhotoPositionType::CLOUD);

    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(UPGRADE_RESTORE_ID, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.CleanDirtyFiles({ dirtyFileNotLocal });
    EXPECT_EQ(photosDataHandler_.setVisibleFiles_.size(), EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clean_dirty_files_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clean_dirty_files_test_002");
    PhotosDao::PhotosRowData dirtyFileNotExist;
    dirtyFileNotExist.data = "";
    dirtyFileNotExist.position = static_cast<int32_t>(PhotoPositionType::LOCAL);

    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(UPGRADE_RESTORE_ID, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.CleanDirtyFiles({ dirtyFileNotExist });
    EXPECT_EQ(photosDataHandler_.setVisibleFiles_.size(), EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clean_dirty_files_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clean_dirty_files_test_003");
    PhotosDao::PhotosRowData dirtyFileNotSameSize;
    dirtyFileNotSameSize.data = DIRTY_FILE_PATH;
    dirtyFileNotSameSize.position = static_cast<int32_t>(PhotoPositionType::LOCAL);

    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(UPGRADE_RESTORE_ID, "", g_rdbStore->GetRaw());
    int32_t count = photosDataHandler_.CleanDirtyFiles({ dirtyFileNotSameSize });
    EXPECT_EQ(photosDataHandler_.setVisibleFiles_.size(), EXPECTED_COUNT_0);
}

void ClearPhotosData()
{
    MEDIA_INFO_LOG("Start clear Photos data");
    ExecuteSqls(g_rdbStore->GetRaw(), { "DELETE FROM Photos" });
}

void InsertDirtyFile(const std::string &path)
{
    ClearPhotosData();
    const std::string INSERT_SQL = "INSERT INTO Photos (file_id, data, sync_status) VALUES (?, ?, -1)";
    int32_t errCode = g_rdbStore->GetRaw()->ExecuteSql(INSERT_SQL, { DIRTY_FILE_ID, path });
    ASSERT_EQ(errCode, E_OK);
}

void QueryDirtyFileCount(int32_t &result)
{
    const std::string QUERY_SQL = "SELECT count(1) FROM Photos WHERE file_id = " + DIRTY_FILE_ID;
    QueryInt(g_rdbStore->GetRaw(), QUERY_SQL, "count(1)", result);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_set_visible_files_in_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_set_visible_files_in_db_test_001");
    InsertDirtyFile("path_with_invalid_prefix");

    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(UPGRADE_RESTORE_ID, "", g_rdbStore->GetRaw());
    photosDataHandler_.setVisibleFiles_.emplace_back(DIRTY_FILE_ID);
    int32_t count = photosDataHandler_.SetVisibleFilesInDb();
    EXPECT_GT(count, EXPECTED_COUNT_0);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_delete_dirty_files_in_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_delete_dirty_files_in_db_test_001");
    InsertDirtyFile("path_with_invalid_prefix");

    PhotosDataHandler photosDataHandler_;
    photosDataHandler_.OnStart(UPGRADE_RESTORE_ID, "", g_rdbStore->GetRaw());
    photosDataHandler_.HandleDirtyFiles();

    int32_t result = INVALID_COUNT;
    QueryDirtyFileCount(result);
    EXPECT_EQ(result, 0);
}

void MediaLibraryBackupCloneTest::InsertSampleSearchIndexData(const std::shared_ptr<NativeRdb::RdbStore>& db,
    int32_t fileId, const std::string& data, const std::string& displayName, double latitude, double longitude,
    int64_t dateModified, int32_t photoStatus, int32_t cvStatus, int32_t geoStatus, int32_t version,
    const std::string& systemLanguage)
{
    ValuesBucket values;
    values.PutInt(SEARCH_IDX_COL_FILE_ID, fileId);
    values.PutString(SEARCH_IDX_COL_DATA, data);
    values.PutString(SEARCH_IDX_COL_DISPLAY_NAME, displayName);
    values.PutDouble(SEARCH_IDX_COL_LATITUDE, latitude);
    values.PutDouble(SEARCH_IDX_COL_LONGITUDE, longitude);
    values.PutLong(SEARCH_IDX_COL_DATE_MODIFIED, dateModified);
    values.PutInt(SEARCH_IDX_COL_PHOTO_STATUS, photoStatus);
    values.PutInt(SEARCH_IDX_COL_CV_STATUS, cvStatus);
    values.PutInt(SEARCH_IDX_COL_GEO_STATUS, geoStatus);
    values.PutInt(SEARCH_IDX_COL_VERSION, version);
    values.PutString(SEARCH_IDX_COL_SYSTEM_LANGUAGE, systemLanguage);

    int64_t rowId;
    int ret = db->Insert(rowId, ANALYSIS_SEARCH_INDEX_TABLE, values);
    ASSERT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Inserted sample search index data: fileId=%{public}d", fileId);
}

void MediaLibraryBackupCloneTest::VerifySearchIndexRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap)
{
    if (!destRdb) {
        MEDIA_ERR_LOG("Destination RDB store is null for verification");
        return;
    }

    std::string querySql = "SELECT " + SEARCH_IDX_COL_FILE_ID + ", " + SEARCH_IDX_COL_ID +
                           " FROM " + ANALYSIS_SEARCH_INDEX_TABLE;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(destRdb, querySql);
    ASSERT_NE(resultSet, nullptr) << "Failed to query destination DB for verification";

    std::unordered_map<int32_t, int> fileIdCounts;
    std::unordered_map<int32_t, std::vector<int64_t>> fileIdToIds;

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = 0;
        int64_t id = 0;
        if (resultSet->GetInt(0, fileId) == NativeRdb::E_OK && resultSet->GetLong(1, id) == NativeRdb::E_OK) {
            fileIdCounts[fileId]++;
            fileIdToIds[fileId].push_back(id);
            MEDIA_DEBUG_LOG("Verify: Found entry fileId: %{public}d, id: %{public}" PRId64, fileId, id);
        }
    }
    resultSet->Close();

    for (const auto& pair : fileIdCounts) {
        int32_t fileId = pair.first;
        bool foundInMap = false;
        for (const auto& mapPair : photoInfoMap) {
            if (mapPair.second.fileIdNew == fileId) {
                foundInMap = true;
                break;
            }
        }
        ASSERT_TRUE(foundInMap) << "Unexpected fileId " << fileId << " found in destination DB";
    }
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_search_index_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_search_index_test_001");
    ClearData();

    CloneSource cloneSource;
    vector<string> tableList = { ANALYSIS_SEARCH_INDEX_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "Destination RDB store (g_rdbStore) is null");

    int32_t destInitialFileId = 500;
    InsertSampleSearchIndexData(g_rdbStore->GetRaw(), destInitialFileId,
        "initial dest data", "Initial Dest Photo.jpg",
        10.0, 20.0, 1600000000000, 0, 0, 0, 1, "en");

    int64_t maxSearchId = BackupDatabaseUtils::QueryMaxId(g_rdbStore->GetRaw(),
        ANALYSIS_SEARCH_INDEX_TABLE, SEARCH_IDX_COL_ID);
    MEDIA_INFO_LOG("Calculated maxSearchId_ from destination DB: %{public}" PRId64, maxSearchId);
    ASSERT_GE(maxSearchId, 1) << "maxSearchId_ should be at least 1 after inserting initial data";

    int32_t sourceOldFileId1 = 101;
    int32_t sourceOldFileId2 = 102;
    int32_t sourceOldFileId3 = 103;
    int32_t sourceOldFileId4 = 104;

    InsertSampleSearchIndexData(cloneSource.cloneStorePtr_, sourceOldFileId1,
        "source data 1", "Source Photo 1.jpg",
        34.0522, -118.2437, 1678886400000, 1, 2, 1, 1, "en");
    InsertSampleSearchIndexData(cloneSource.cloneStorePtr_, sourceOldFileId2,
        "source data 2", "Source Photo 2.jpg",
        40.7128, -74.0060, 1678886401000, 0, 1, 0, 1, "zh");
    InsertSampleSearchIndexData(cloneSource.cloneStorePtr_, sourceOldFileId3,
        "source data 3 (new)", "Source Photo 3.jpg",
        41.0, -75.0, 1678886402000, 0, 0, 0, 1, "fr");
    InsertSampleSearchIndexData(cloneSource.cloneStorePtr_, sourceOldFileId4,
        "source data 4 (maps to initial dest)", "Source Photo 4.jpg",
        10.0, 20.0, 1678886403000, 0, 0, 0, 1, "es");

    std::unordered_map<int32_t, OHOS::Media::PhotoInfo> photoInfoMap;
    int32_t newFileId1 = 601;
    int32_t newFileId2 = 602;
    int32_t newFileId3 = 603;
    int32_t newFileId4 = destInitialFileId;

    photoInfoMap[sourceOldFileId1] = {.fileIdNew = newFileId1 };
    photoInfoMap[sourceOldFileId2] = {.fileIdNew = newFileId2 };
    photoInfoMap[sourceOldFileId3] = {.fileIdNew = newFileId3 };
    photoInfoMap[sourceOldFileId4] = {.fileIdNew = newFileId4 };

    SearchIndexClone searchIndexClone(cloneSource.cloneStorePtr_, g_rdbStore->GetRaw(), photoInfoMap, maxSearchId);
    bool cloneSuccess = searchIndexClone.Clone();
    ASSERT_TRUE(cloneSuccess) << "SearchIndexClone::Clone failed";
    VerifySearchIndexRestore(g_rdbStore->GetRaw(), photoInfoMap);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_search_index_test_001");
}

void MediaLibraryBackupCloneTest::VerifyBeautyScoreRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, OHOS::Media::PhotoInfo>& photoInfoMap)
{
    if (!destRdb) {
        MEDIA_ERR_LOG("Destination RDB store is null for verification");
        return;
    }

    std::string querySql = "SELECT " + BEAUTY_SCORE_COL_AESTHETICS_VERSION +
                           " FROM " + ANALYSIS_BEAUTY_SCORE_TABLE;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(destRdb, querySql);
    ASSERT_NE(resultSet, nullptr) << "Failed to query destination DB for beauty score verification";

    int32_t aestheticsVersionIdx = -1;
    int32_t rowCount = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        rowCount++;
        std::string aestheticsVersionVal;
        resultSet->GetColumnIndex(BEAUTY_SCORE_COL_AESTHETICS_VERSION, aestheticsVersionIdx);
        ASSERT_NE(aestheticsVersionIdx, -1) << "Column " << BEAUTY_SCORE_COL_AESTHETICS_VERSION <<
            " not found in result set.";
        resultSet->GetString(aestheticsVersionIdx, aestheticsVersionVal);
        ASSERT_EQ(aestheticsVersionVal, "v1.1")
            << "Aesthetics version mismatch for row " << rowCount
            << ": expected 'v1.1', got '" << aestheticsVersionVal << "'";
    }
    resultSet->Close();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_beauty_score_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_beauty_score_test_001");
    ClearData();

    CloneSource cloneSource;
    vector<string> tableList = { ANALYSIS_BEAUTY_SCORE_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "Destination RDB store (g_rdbStore) is null");

    std::unordered_map<int32_t, OHOS::Media::PhotoInfo> photoInfoMap;
    int32_t sourceOldFileId = 10112;
    int32_t newFileId = 60005;
    photoInfoMap[sourceOldFileId] = { .fileIdNew = newFileId };

    BeautyScoreClone beautyScoreClone(cloneSource.cloneStorePtr_, g_rdbStore->GetRaw(), photoInfoMap, 0);
    bool cloneSuccess = beautyScoreClone.CloneBeautyScoreInfo();
    ASSERT_TRUE(cloneSuccess) << "BeautyScoreClone::CloneBeautyScoreInfo failed";

    VerifyBeautyScoreRestore(g_rdbStore->GetRaw(), photoInfoMap);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_beauty_score_test_001");
}

static void VerifyVideoFaceRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, OHOS::Media::PhotoInfo>& photoInfoMap)
{
    if (!destRdb) {
        MEDIA_ERR_LOG("Destination RDB store is null for verification");
        return;
    }

    std::string querySql = "SELECT * FROM " + ANALYSIS_VIDEO_FACE_TABLE;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(destRdb, querySql);
    ASSERT_NE(resultSet, nullptr) << "Failed to query destination DB for video face verification";

    std::unordered_map<int32_t, std::vector<VideoFaceTbl>> destVideoFaces;
    int32_t fileIdIdx = -1;

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        VideoFaceTbl face;
        int32_t currentFileId = -1;
        resultSet->GetColumnIndex(VIDEO_FACE_COL_FILE_ID, fileIdIdx);
        if (fileIdIdx != -1) {
            resultSet->GetInt(fileIdIdx, currentFileId);
            face.file_id = currentFileId;
        }

        if (currentFileId != -1) {
            destVideoFaces[currentFileId].push_back(face);
        }
    }
    resultSet->Close();

    ASSERT_GE(destVideoFaces.size(), photoInfoMap.size())
        << "The number of file IDs with video faces does not match the expected count.";

    for (const auto& pair : photoInfoMap) {
        int32_t sourceOldFileId = pair.first;
        int32_t newFileId = pair.second.fileIdNew;

        auto it = destVideoFaces.find(newFileId);
        ASSERT_TRUE(it != destVideoFaces.end()) << "Expected new fileId " << newFileId
                                                  << " not found in destination video face table.";
        ASSERT_FALSE(it->second.empty()) << "No video faces found for new fileId " << newFileId;
    }
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_video_face_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_video_face_test_001");
    ClearData();

    CloneSource cloneSource;
    vector<string> tableList = { ANALYSIS_VIDEO_FACE_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "Destination RDB store (g_rdbStore) is null");

    std::unordered_map<int32_t, OHOS::Media::PhotoInfo> photoInfoMap;
    int32_t sourceOldFileId = 10111;
    int32_t newFileId = 60005;
    photoInfoMap[sourceOldFileId] = { .fileIdNew = newFileId };

    VideoFaceClone videoFaceClone(cloneSource.cloneStorePtr_, g_rdbStore->GetRaw(), photoInfoMap);
    bool cloneSuccess = videoFaceClone.CloneVideoFaceInfo();
    ASSERT_TRUE(cloneSuccess) << "VideoFaceClone::CloneVideoFaceInfo failed";

    VerifyVideoFaceRestore(g_rdbStore->GetRaw(), photoInfoMap);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_video_face_test_001");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_analysis_data_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_analysis_data_test_001");
    ClearData();
    CloneSource cloneSource;
    vector<std::string> tableList = { SEGMENTATION_ANALYSIS_TABLE, VISION_TOTAL_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::shared_ptr<CloneRestoreAnalysisData> cloneAnalysisData = make_shared<CloneRestoreAnalysisData>();
    cloneAnalysisData->Init(CLONE_RESTORE_ID, TASK_ID, cloneSource.cloneStorePtr_, g_rdbStore->GetRaw());
    cloneAnalysisData->table_ = SEGMENTATION_ANALYSIS_TABLE;
    std::unordered_set<std::string> excludedColumns = {"id", "file_id"};
    auto commonColumns = cloneAnalysisData->GetTableCommonColumns(excludedColumns);
    EXPECT_EQ(commonColumns.size(), SEGMENTATION_TABLE_SIZE - excludedColumns.size());
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_analysis_data_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_analysis_data_test_002");
    ClearData();
    CloneSource cloneSource;
    vector<std::string> tableList = { SEGMENTATION_ANALYSIS_TABLE, VISION_TOTAL_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    std::shared_ptr<CloneRestoreAnalysisData> cloneAnalysisData = make_shared<CloneRestoreAnalysisData>();
    cloneAnalysisData->Init(CLONE_RESTORE_ID, TASK_ID, cloneSource.cloneStorePtr_, g_rdbStore->GetRaw());
    cloneAnalysisData->table_ = SEGMENTATION_ANALYSIS_TABLE;

    cloneSource.Insert(tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfoMap[1] = photoInfo;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.type_ = SEGMENTATION_TYPE;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.lastId_ = 0;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.pageSize_ = PAGE_SIZE;

    cloneAnalysisData->cloneRestoreAnalysisTotal_.GetInfos(photoInfoMap);
    cloneAnalysisData->GetAnalysisDataInfo();
    EXPECT_EQ(cloneAnalysisData->analysisDataInfos_.size(), 1);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_analysis_data_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_analysis_data_test_003");
    ClearData();
    CloneSource cloneSource;
    vector<std::string> tableList = { SEGMENTATION_ANALYSIS_TABLE, VISION_TOTAL_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    std::shared_ptr<CloneRestoreAnalysisData> cloneAnalysisData = make_shared<CloneRestoreAnalysisData>();
    cloneAnalysisData->Init(CLONE_RESTORE_ID, TASK_ID, cloneSource.cloneStorePtr_, g_rdbStore->GetRaw());
    cloneAnalysisData->table_ = SEGMENTATION_ANALYSIS_TABLE;

    cloneSource.Insert(tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfoMap[1] = photoInfo;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.mediaRdb_ = cloneSource.cloneStorePtr_;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.type_ = SEGMENTATION_TYPE;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.lastId_ = 0;
    cloneAnalysisData->cloneRestoreAnalysisTotal_.pageSize_ = PAGE_SIZE;

    cloneAnalysisData->cloneRestoreAnalysisTotal_.GetInfos(photoInfoMap);
    cloneAnalysisData->GetAnalysisDataInfo();
    std::unordered_set<int32_t> existingFileIds = cloneAnalysisData->GetExistingFileIds();
    EXPECT_EQ(existingFileIds.size(), 0);
    cloneAnalysisData->RemoveDuplicateInfos(existingFileIds);
    EXPECT_EQ(cloneAnalysisData->analysisDataInfos_.size(), 1);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_analysis_data_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_analysis_data_test_004");
    ClearData();
    CloneSource cloneSource;
    vector<std::string> tableList = { SEGMENTATION_ANALYSIS_TABLE, VISION_TOTAL_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    std::shared_ptr<CloneRestoreAnalysisData> cloneAnalysisData = make_shared<CloneRestoreAnalysisData>();
    cloneAnalysisData->Init(CLONE_RESTORE_ID, TASK_ID, cloneSource.cloneStorePtr_, g_rdbStore->GetRaw());
    cloneAnalysisData->table_ = SEGMENTATION_ANALYSIS_TABLE;

    cloneSource.Insert(tableList);
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfoMap[1] = photoInfo;
    std::unordered_set<std::string> excludedColumns = {"id", "file_id"};

    cloneAnalysisData->CloneAnalysisData(SEGMENTATION_ANALYSIS_TABLE, SEGMENTATION_TYPE, photoInfoMap,
        excludedColumns);
    EXPECT_EQ(cloneAnalysisData->successCnt_, 1);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_insert_value_from_val_map_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_insert_value_from_val_map_test_001");
    FileInfo fileInfo;
    fileInfo.valMap[PhotoColumn::PHOTO_EDIT_TIME] = int64_t(123456789);
    fileInfo.valMap[PhotoColumn::MEDIA_DATE_TAKEN] = int64_t(987654321);
    fileInfo.valMap[MediaColumn::MEDIA_MIME_TYPE] = string("image/jpeg");
    fileInfo.valMap[PhotoColumn::PHOTO_SHOOTING_MODE] = string("-1");
    fileInfo.valMap[PhotoColumn::PHOTO_SHOOTING_MODE_TAG] = string("23");
    NativeRdb::ValuesBucket values;
    restoreService->GetInsertValueFromValMap(fileInfo, values);
    string shootingMode;
    ValueObject valueObject;
    if (values.GetObject(PhotoColumn::PHOTO_SHOOTING_MODE, valueObject)) {
        valueObject.GetString(shootingMode);
    }
    EXPECT_EQ(shootingMode, "1");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_insert_value_from_val_map_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_insert_value_from_val_map_test_001");
    FileInfo fileInfo;
    fileInfo.valMap[PhotoColumn::PHOTO_EDIT_TIME] = int64_t(123456789);
    fileInfo.valMap[PhotoColumn::MEDIA_DATE_TAKEN] = int64_t(987654321);
    fileInfo.valMap[MediaColumn::MEDIA_MIME_TYPE] = string("image/jpeg");
    fileInfo.valMap[PhotoColumn::PHOTO_SHOOTING_MODE] = string("-1");
    NativeRdb::ValuesBucket values;
    restoreService->GetInsertValueFromValMap(fileInfo, values);
    string shootingMode;
    ValueObject valueObject;
    if (values.GetObject(PhotoColumn::PHOTO_SHOOTING_MODE, valueObject)) {
        valueObject.GetString(shootingMode);
    }
    EXPECT_EQ(shootingMode, "");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_wait_device_exit_timeout_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialib_backup_wait_south_device_exit_timeout_test_001");
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, "0"));
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    EXPECT_FALSE(cloneRestoreService->WaitSouthDeviceExitTimeout());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_wait_device_exit_timeout_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialib_backup_wait_south_device_exit_timeout_test_002");
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY,
        std::to_string(MediaFileUtils::UTCTimeMilliSeconds())));
    std::thread t([&]() -> void {
        EXPECT_FALSE(cloneRestoreService->WaitSouthDeviceExitTimeout());
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    EXPECT_TRUE(OHOS::system::SetParameter(CLOUDSYNC_SWITCH_STATUS_KEY, "0"));
    t.join();
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_parameter_for_backup_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialib_backup_set_parameter_for_backup_test_001");
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    EXPECT_TRUE(OHOS::system::SetParameter(BACKUP_FLAG, std::to_string(DEFAULT_TIME_STAMP)));
    cloneRestoreService->SetParameterForBackup();
    EXPECT_TRUE(OHOS::system::GetIntParameter(BACKUP_FLAG, DEFAULT_TIME_STAMP) != DEFAULT_TIME_STAMP);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_stop_parameter_for_backup_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialib_backup_set_parameter_for_backup_test_001");
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    EXPECT_TRUE(OHOS::system::SetParameter(BACKUP_FLAG, std::to_string(MediaFileUtils::UTCTimeSeconds())));
    cloneRestoreService->StopParameterForBackup();
    EXPECT_EQ(OHOS::system::GetIntParameter(BACKUP_FLAG, DEFAULT_TIME_STAMP), DEFAULT_TIME_STAMP);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_backup_errinfo_json_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_get_backup_errinfo_json_test_001");
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    ASSERT_NE(cloneRestoreService.get(), nullptr);
    cloneRestoreService->errorCode_ = RestoreError::SUCCESS;
    cloneRestoreService->errorInfo_ = "ERRORINFO";
    auto errorInfoJson = cloneRestoreService->GetBackupErrorInfoJson();
    EXPECT_EQ(errorInfoJson[STAT_KEY_ERROR_CODE], "0");

    cloneRestoreService->errorCode_ = RestoreError::RETAIN_FORCE_TIMEOUT;
    errorInfoJson = cloneRestoreService->GetBackupErrorInfoJson();
    EXPECT_EQ(errorInfoJson[STAT_KEY_ERROR_CODE], "13500099");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_release_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_release_001");
    unique_ptr<CloneRestore> cloneRestoreService = make_unique<CloneRestore>();
    ASSERT_NE(cloneRestoreService.get(), nullptr);
    cloneRestoreService->Release(ReleaseScene::BACKUP);
    cloneRestoreService->Release(ReleaseScene::RESTORE);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_old_no_face_status_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_query_old_no_face_status_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    auto oldRdbStore = cloneSource.cloneStorePtr_;
    ASSERT_NE(oldRdbStore, nullptr);

    ExecuteSqls(oldRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (101, -1)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (102, -2)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (103, 0)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (104, -3)"
    });

    vector<int32_t> oldFileIds = {101, 102, 103, 104, 105};

    auto result = BackupDatabaseUtils::QueryOldNoFaceStatus(oldRdbStore, oldFileIds);

    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[101], -1);
    EXPECT_EQ(result[102], -2);
    EXPECT_EQ(result[104], -3);
    EXPECT_EQ(result.count(103), 0);
    EXPECT_EQ(result.count(105), 0);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_old_no_face_status_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_query_old_no_face_status_test_002");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    auto oldRdbStore = cloneSource.cloneStorePtr_;
    ASSERT_NE(oldRdbStore, nullptr);

    vector<int32_t> oldFileIds = {};

    auto result = BackupDatabaseUtils::QueryOldNoFaceStatus(oldRdbStore, oldFileIds);

    EXPECT_TRUE(result.empty());

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_new_no_face_status_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_update_new_no_face_status_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    auto oldRdbStore = cloneSource.cloneStorePtr_;
    auto newRdbStore = g_rdbStore->GetRaw();
    ASSERT_NE(oldRdbStore, nullptr);
    ASSERT_NE(newRdbStore, nullptr);

    ExecuteSqls(oldRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (101, -1)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (102, -2)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (103, 0)"
    });

    ExecuteSqls(newRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (201, 5)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (202, 6)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (203, 7)"
    });

    unordered_map<int32_t, int32_t> oldFileIdToFaceMap = {
        {101, -1},
        {102, -2},
        {104, -4}
    };

    vector<FileIdPair> fileIdPair = {
        {101, 201},
        {102, 202},
        {103, 203},
        {104, 204}
    };

    BackupDatabaseUtils::UpdateNewNoFaceStatus(newRdbStore, oldFileIdToFaceMap, fileIdPair);

    auto verifyFaceValue = [&](int32_t fileId, int32_t expectedFace) {
        string querySql = "SELECT face FROM " + VISION_TOTAL_TABLE + " WHERE file_id = " + to_string(fileId);
        auto resultSet = newRdbStore->QuerySql(querySql);
        ASSERT_NE(resultSet, nullptr);
        if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
            int32_t faceValue;
            resultSet->GetInt(0, faceValue);
            EXPECT_EQ(faceValue, expectedFace);
        }
        resultSet->Close();
    };

    verifyFaceValue(201, -1);
    verifyFaceValue(202, -2);
    verifyFaceValue(203, 7);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_new_no_face_status_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_update_new_no_face_status_test_002");

    ClearData();
    auto newRdbStore = g_rdbStore->GetRaw();
    ASSERT_NE(newRdbStore, nullptr);

    unordered_map<int32_t, int32_t> oldFileIdToFaceMap = {};
    vector<FileIdPair> fileIdPair = {{101, 201}, {102, 202}};

    BackupDatabaseUtils::UpdateNewNoFaceStatus(newRdbStore, oldFileIdToFaceMap, fileIdPair);

    EXPECT_EQ(BackupDatabaseUtils::QueryOldNoFaceStatus(newRdbStore, {201, 202}).size(), 0);
    MEDIA_INFO_LOG("Empty old face status map test completed");
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_total_no_face_status_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_update_total_no_face_status_test_001");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    auto oldRdbStore = cloneSource.cloneStorePtr_;
    auto newRdbStore = g_rdbStore->GetRaw();
    ASSERT_NE(oldRdbStore, nullptr);
    ASSERT_NE(newRdbStore, nullptr);

    ExecuteSqls(oldRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (101, -1)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (102, -2)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (103, 0)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (104, -3)"
    });

    ExecuteSqls(newRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (201, 5)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (202, 6)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (203, 7)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (204, 8)"
    });

    vector<FileIdPair> fileIdPair = {
        {101, 201},
        {102, 202},
        {103, 203},
        {104, 204},
        {105, 205}
    };

    BackupDatabaseUtils::UpdateAnalysisTotalTblNoFaceStatus(newRdbStore, oldRdbStore, fileIdPair);

    auto verifyFaceValue = [&](int32_t fileId, int32_t expectedFace) {
        string querySql = "SELECT face FROM " + VISION_TOTAL_TABLE + " WHERE file_id = " + to_string(fileId);
        auto resultSet = newRdbStore->QuerySql(querySql);
        ASSERT_NE(resultSet, nullptr);
        if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
            int32_t faceValue;
            resultSet->GetInt(0, faceValue);
            EXPECT_EQ(faceValue, expectedFace);
        }
        resultSet->Close();
    };

    verifyFaceValue(201, -1);
    verifyFaceValue(202, -2);
    verifyFaceValue(203, 7);
    verifyFaceValue(204, -3);
    verifyFaceValue(205, 8);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_total_no_face_status_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_update_total_no_face_status_test_002");

    ClearData();
    CloneSource cloneSource;
    vector<string> tableList = { VISION_TOTAL_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    auto oldRdbStore = cloneSource.cloneStorePtr_;
    auto newRdbStore = g_rdbStore->GetRaw();
    ASSERT_NE(oldRdbStore, nullptr);
    ASSERT_NE(newRdbStore, nullptr);

    ExecuteSqls(oldRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (101, 1)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (102, 2)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (103, 3)"
    });

    ExecuteSqls(newRdbStore, {
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (201, 5)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (202, 6)",
        "INSERT INTO " + VISION_TOTAL_TABLE + " (file_id, face) VALUES (203, 7)"
    });

    vector<FileIdPair> fileIdPair = {
        {101, 201},
        {102, 202},
        {103, 203}
    };

    BackupDatabaseUtils::UpdateAnalysisTotalTblNoFaceStatus(newRdbStore, oldRdbStore, fileIdPair);
    auto verifyFaceValue = [&](int32_t fileId, int32_t expectedFace) {
        string querySql = "SELECT face FROM " + VISION_TOTAL_TABLE + " WHERE file_id = " + to_string(fileId);
        auto resultSet = newRdbStore->QuerySql(querySql);
        ASSERT_NE(resultSet, nullptr);
        if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
            int32_t faceValue;
            resultSet->GetInt(0, faceValue);
            EXPECT_EQ(faceValue, expectedFace);
        }
        resultSet->Close();
    };

    verifyFaceValue(201, 5);
    verifyFaceValue(202, 6);
    verifyFaceValue(203, 7);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_update_config_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_update_config_info_test_001");
    restoreService->mediaLibraryRdb_ = nullptr;
    EXPECT_FALSE(restoreService->UpdateConfigInfo());
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_update_config_info_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_update_config_info_test_002");
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    EXPECT_TRUE(restoreService->mediaLibraryRdb_ != nullptr);
    restoreService->srcCloneRestoreConfigInfo_ = {
        .deviceId = DEFAULT_DEVICE_ID,
        .isValid = true,
        .switchStatus = SwitchStatus::HDC,
    };
    EXPECT_TRUE(restoreService->UpdateConfigInfo());
    auto configInfo = BackupDatabaseUtils::QueryConfigInfo(restoreService->mediaLibraryRdb_);
    EXPECT_TRUE(configInfo.count(ConfigInfoSceneId::CLONE_RESTORE) &&
        configInfo[ConfigInfoSceneId::CLONE_RESTORE].count(CONFIG_INFO_CLONE_PHOTO_SYNC_OPTION_KEY) &&
        configInfo[ConfigInfoSceneId::CLONE_RESTORE].count(CONFIG_INFO_CLONE_HDC_DEVICE_ID_KEY));
    EXPECT_EQ(configInfo[ConfigInfoSceneId::CLONE_RESTORE][CONFIG_INFO_CLONE_PHOTO_SYNC_OPTION_KEY],
        std::to_string(static_cast<int>(SwitchStatus::HDC)));
    EXPECT_EQ(configInfo[ConfigInfoSceneId::CLONE_RESTORE][CONFIG_INFO_CLONE_HDC_DEVICE_ID_KEY],
        DEFAULT_DEVICE_ID);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_restore_asset_map_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_clone_restore_asset_map_test_001");
    ClearData();

    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);

    std::unordered_map<int32_t, OHOS::Media::PhotoInfo> photoInfoMap;
    int32_t sourceOldFileId = 1;
    int32_t newFileId = 60005;
    photoInfoMap[sourceOldFileId] = { .fileIdNew = newFileId };

    AssetMapClone assetMapClone(cloneSource.cloneStorePtr_, g_rdbStore->GetRaw(), photoInfoMap);
    bool cloneSuccess = assetMapClone.CloneAssetMapInfo();
    ASSERT_TRUE(cloneSuccess) << "AssetMapClone::CloneAssetMapInfo failed";

    VerifyAssetMapRestore(g_rdbStore->GetRaw(), photoInfoMap);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
    MEDIA_INFO_LOG("End medialibrary_backup_clone_restore_asset_map_test_001");
}

void MediaLibraryBackupCloneTest::VerifyAssetMapRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, OHOS::Media::PhotoInfo>& photoInfoMap)
{
    if (!destRdb) {
        MEDIA_ERR_LOG("Destination RDB store is null for asset map verification");
        return;
    }

    std::string querySql = "SELECT * FROM " + TAB_OLD_PHOTOS;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(destRdb, querySql);
    ASSERT_NE(resultSet, nullptr) << "Failed to query destination DB for asset map verification";

    int32_t rowCount = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        rowCount++;

        int32_t fileIdIdx = -1;
        int32_t fileIdVal = -1;
        resultSet->GetColumnIndex(ASSET_MAP_COL_FILE_ID, fileIdIdx);
        ASSERT_NE(fileIdIdx, -1) << "Column " << ASSET_MAP_COL_FILE_ID << " not found in result set.";
        resultSet->GetInt(fileIdIdx, fileIdVal);

        // Verify that the file ID has been mapped correctly
        bool found = false;
        for (const auto& pair : photoInfoMap) {
            if (pair.second.fileIdNew == fileIdVal) {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found) << "Expected fileId " << fileIdVal << " not found in photoInfoMap mapping";
    }

    ASSERT_GT(rowCount, 0) << "No asset map records found in destination database";
    resultSet->Close();
}

static bool InsertIntoConfigInfo(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    ConfigInfoSceneId sceneId, const std::string& key, const std::string& value)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore, false, "rdbStore is null");
    std::string sqlStr = "INSERT INTO " + ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME +
        " (" + ConfigInfoColumn::MEDIA_CONFIG_INFO_SCENE_ID + ", " +
        ConfigInfoColumn::MEDIA_CONFIG_INFO_KEY + ", " +
        ConfigInfoColumn::MEDIA_CONFIG_INFO_VALUE + ") " +
        "VALUES (" + std::to_string(static_cast<int>(sceneId)) + ", '" + key + "', '" + value + "')" +
        " ON CONFLICT(" + ConfigInfoColumn::MEDIA_CONFIG_INFO_SCENE_ID + ", " +
        ConfigInfoColumn::MEDIA_CONFIG_INFO_KEY + ") DO UPDATE SET " +
        ConfigInfoColumn::MEDIA_CONFIG_INFO_VALUE + " = excluded." + ConfigInfoColumn::MEDIA_CONFIG_INFO_VALUE + ";";
    MEDIA_INFO_LOG("InsertIntoConfigInfo sql:%{public}s", sqlStr.c_str());
    std::vector<NativeRdb::ValueObject> args;
    CHECK_AND_RETURN_RET_LOG(rdbStore->ExecuteSql(sqlStr, args) == NativeRdb::E_OK, false,
        "fail to execute sq;, sql:%{public}s", sqlStr.c_str());
    return true;
}

static bool ClearTable(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string& tableName)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore, false, "rdbStore is null");
    std::string sqlStr = "DELETE FROM " + tableName;
    MEDIA_INFO_LOG("ClearTable sql: %{public}s", sqlStr.c_str());
    std::vector<NativeRdb::ValueObject> args;
    CHECK_AND_RETURN_RET_LOG(rdbStore->ExecuteSql(sqlStr, args), false, "fail to execute sql:%{public}s",
        sqlStr.c_str());
    return true;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_001");
    CloneRestoreConfigInfo expectedConfigInfo;
    restoreService->mediaRdb_ = nullptr;
    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_002");
    CloneRestoreConfigInfo expectedConfigInfo = {
        .deviceId = EMPTY_STR,
        .switchStatus = SwitchStatus::CLOUD,
        .isValid = true
    };

    CloneSource cloneSource;
    Init(cloneSource, TEST_BACKUP_DB_PATH, {});
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_003");
    CloneRestoreConfigInfo expectedConfigInfo;

    CloneSource cloneSource;
    std::vector<std::string> tableList = {ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_004");
    CloneRestoreConfigInfo expectedConfigInfo;

    CloneSource cloneSource;
    std::vector<std::string> tableList = {ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_INVALID_KEY, CONFIG_INFO_INVALID_VALUE));

    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_005");
    CloneRestoreConfigInfo expectedConfigInfo;

    CloneSource cloneSource;
    std::vector<std::string> tableList = {ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_CLONE_PHOTO_SYNC_OPTION_KEY, CONFIG_INFO_INVALID_VALUE));

    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_006");
    CloneRestoreConfigInfo expectedConfigInfo;

    CloneSource cloneSource;
    std::vector<std::string> tableList = {ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_CLONE_PHOTO_SYNC_OPTION_KEY, CONFIG_INFO_INVALID_VALUE));
    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_CLONE_HDC_DEVICE_ID_KEY, CONFIG_INFO_INVALID_VALUE));

    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_clone_config_info_from_origin_db_test_008, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_clone_config_info_from_origin_db_test_008");
    CloneRestoreConfigInfo expectedConfigInfo = {
        .deviceId = DEFAULT_DEVICE_ID,
        .isValid = true,
        .switchStatus = SwitchStatus::HDC
    };

    CloneSource cloneSource;
    std::vector<std::string> tableList = {ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME, PhotoColumn::PHOTOS_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;

    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_CLONE_PHOTO_SYNC_OPTION_KEY, std::to_string(static_cast<int>(SwitchStatus::HDC))));
    EXPECT_TRUE(InsertIntoConfigInfo(restoreService->mediaRdb_, ConfigInfoSceneId::CLONE_RESTORE,
        CONFIG_INFO_CLONE_HDC_DEVICE_ID_KEY, DEFAULT_DEVICE_ID));


    CloneRestoreConfigInfo result = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_TRUE(expectedConfigInfo == result);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_check_src_dst_switch_status_match_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_check_src_dst_switch_status_match_test_001");
    restoreService->srcCloneRestoreConfigInfo_ = {
        .deviceId = DEFAULT_DEVICE_ID,
        .isValid = false,
        .switchStatus = SwitchStatus::CLOSE,
    };
    restoreService->dstCloneRestoreConfigInfo_ = {
        .deviceId = DEFAULT_DEVICE_ID,
        .isValid = false,
        .switchStatus = SwitchStatus::CLOSE,
    };

    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restoreService->isSrcDstSwitchStatusMatch_);

    restoreService->srcCloneRestoreConfigInfo_.isValid = true;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restoreService->isSrcDstSwitchStatusMatch_);

    restoreService->dstCloneRestoreConfigInfo_.isValid = true;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restoreService->isSrcDstSwitchStatusMatch_);

    restoreService->srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::HDC;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restoreService->isSrcDstSwitchStatusMatch_);

    restoreService->dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restoreService->isSrcDstSwitchStatusMatch_);

    restoreService->dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::HDC;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_TRUE(restoreService->isSrcDstSwitchStatusMatch_);
}

static std::string GenerateBackupInfo(const std::string& key, const std::string& value)
{
    std::string backupInfo = "[{"
        "\"type\":	\"compatibility_info\","
 		"\"detail\":\"{\\\"" + key + "\\\": " + value + "}\""
        "},{\"type\": \"other\", \"detail\":\"\"}]";
    MEDIA_INFO_LOG("backupInfo: %{public}s", backupInfo.c_str());
    return backupInfo;
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_parse_dst_device_backup_info_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_parse_dst_device_backup_info_001");

    restoreService->restoreInfo_ = EMPTY_STR;
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = "invalid json";
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = GenerateBackupInfo("invalid_key", "abc");
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = GenerateBackupInfo(BACKUP_DST_DEVICE_HDC_ENABLE_KEY, "\"invalid value\"");
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = GenerateBackupInfo(BACKUP_DST_DEVICE_HDC_ENABLE_KEY, "true");
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_TRUE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = GenerateBackupInfo(BACKUP_DST_DEVICE_HDC_ENABLE_KEY, "false");
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_preprocess_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_backup_preprocess_001");

    restoreService->restoreInfo_ = GenerateBackupInfo(BACKUP_DST_DEVICE_HDC_ENABLE_KEY, "false");
    CloneSource cloneSource;
    std::vector<std::string> tableList = {PhotoColumn::PHOTOS_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaLibraryRdb_ = cloneSource.cloneStorePtr_;
    restoreService->srcCloneRestoreConfigInfo_ = {
        .deviceId = DEFAULT_DEVICE_ID,
        .isValid = false,
        .switchStatus = SwitchStatus::HDC
    };

    EXPECT_TRUE(restoreService->BackupPreprocess());
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->mediaLibraryRdb_ = nullptr;
    EXPECT_FALSE(restoreService->BackupPreprocess());
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->srcCloneRestoreConfigInfo_.isValid = true;
    EXPECT_FALSE(restoreService->BackupPreprocess());
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    EXPECT_TRUE(restoreService->BackupPreprocess());
    EXPECT_FALSE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    restoreService->restoreInfo_ = GenerateBackupInfo(BACKUP_DST_DEVICE_HDC_ENABLE_KEY, "true");
    EXPECT_TRUE(restoreService->BackupPreprocess());
    EXPECT_TRUE(restoreService->dstDeviceBackupInfo_.hdcEnabled);

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_is_table_exist_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_is_table_exist_001");
    auto rdbStore = g_rdbStore->GetRaw();
    EXPECT_TRUE(rdbStore != nullptr);

    bool ret = false;
    EXPECT_TRUE(BackupDatabaseUtils::isTableExist(rdbStore,
        ConfigInfoColumn::MEDIA_CONFIG_INFO_TABLE_NAME, ret));
    EXPECT_TRUE(ret);

    ret = false;
    EXPECT_FALSE(BackupDatabaseUtils::isTableExist(nullptr, "invalid_table_name", ret));
    EXPECT_FALSE(ret);

    ret = false;
    EXPECT_TRUE(BackupDatabaseUtils::isTableExist(rdbStore,
        "invalid_table_name", ret));
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_invalidate_hdc_cloud_data_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_invalidate_hdc_cloud_data_001");

    restoreService->mediaLibraryRdb_ = nullptr;
    EXPECT_FALSE(restoreService->InvalidateHdcCloudData());

    CloneSource cloneSource;
    std::vector<std::string> tableList = {PhotoColumn::PHOTOS_TABLE};
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaLibraryRdb_ = cloneSource.cloneStorePtr_;
    EXPECT_TRUE(restoreService->InvalidateHdcCloudData());

    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_current_clone_config_info_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_current_clone_config_info_001");
    CloneRestoreConfigInfo expectedConfigInfo;
    auto config = restoreService->GetCurrentDeviceCloneConfigInfo();
    bool flag = !config.isValid || config.switchStatus != SwitchStatus::NONE;
    EXPECT_TRUE(flag);
}

HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_get_hdc_device_id_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("Start medialibrary_get_hdc_device_id_001");
    std::string deviceId;
    bool ret = SettingsDataManager::GetHdcDeviceId(deviceId);
    bool flag = ((ret && !deviceId.empty()) || (!ret && deviceId.empty()));
    EXPECT_TRUE(flag);
}
} // namespace Media
} // namespace OHOS