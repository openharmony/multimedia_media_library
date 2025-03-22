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

#define MLOG_TAG "AlbumsRefreshManagerTest"

#include "albums_refresh_manager_test.h"

#include <string>
#include <vector>

#include "albums_refresh_manager.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "media_refresh_album_column.h"
#include "photo_album_column.h"
#include "userfile_manager_types.h"
#include "vision_column.h"
#include "vision_db_sqls_more.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::string CREATE_ALBUM_REFRESH_TABLE = "CREATE TABLE IF NOT EXISTS " + ALBUM_REFRESH_TABLE + " ("
    + REFRESH_ALBUM_ID + " INT PRIMARY KEY, " + ALBUM_REFRESH_STATUS + " INT)";

static constexpr int32_t PHOTO_ALBUM_ID = 2;
static constexpr int32_t PHOTO_ALBUM_SUBTYPE = PhotoAlbumSubType::VIDEO;
static constexpr int32_t ANALYSIS_ALBUM_ID = 10;
static constexpr int32_t ANALYSIS_ALBUM_SUBTYPE = PhotoAlbumSubType::PORTRAIT;
static constexpr int32_t REFRESH_ALBUM_STATUS = 0;
static constexpr int32_t NOTIFY_ADD_URI_SIZE = 10;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

int32_t ExecSqls(const vector<string> &sqls)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t err = E_OK;
    for (const auto &sql : sqls) {
        err = g_rdbStore->ExecuteSql(sql);
        MEDIA_INFO_LOG("exec sql: %{public}s result: %{public}d", sql.c_str(), err);
        EXPECT_EQ(err, E_OK);
    }
    return E_OK;
}

void CleanAllTestTables()
{
    vector<string> dropTableList = {
        PhotoAlbumColumns::TABLE,
        ANALYSIS_ALBUM_TABLE,
        ALBUM_REFRESH_TABLE,
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void SetAllTestTables()
{
    vector<string> createTableSqlList = {
        PhotoAlbumColumns::CREATE_TABLE,
        CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
        CREATE_ALBUM_REFRESH_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void InsertPhotoAlbumTestData()
{
    ValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, PHOTO_ALBUM_ID);
    valuesBucket.Put(ALBUM_SUBTYPE, PHOTO_ALBUM_SUBTYPE);
    int64_t outRowId = 0;
    int ret = g_rdbStore->Insert(outRowId, PhotoAlbumColumns::TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
}

void InsertAnalysisAlbumTestData()
{
    ValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, ANALYSIS_ALBUM_ID);
    valuesBucket.Put(ALBUM_SUBTYPE, ANALYSIS_ALBUM_SUBTYPE);
    int64_t outRowId = 0;
    int ret = g_rdbStore->Insert(outRowId, ANALYSIS_ALBUM_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
}

void InsertRefreshAlbumTestData()
{
    // Insert photo album
    ValuesBucket photoValuesBucket;
    photoValuesBucket.Put(REFRESH_ALBUM_ID, PHOTO_ALBUM_ID);
    photoValuesBucket.Put(ALBUM_REFRESH_STATUS, REFRESH_ALBUM_STATUS);
    int64_t outRowId = 0;
    int ret = g_rdbStore->Insert(outRowId, ALBUM_REFRESH_TABLE, photoValuesBucket);
    EXPECT_EQ(ret, E_OK);

    // Insert analysis album
    ValuesBucket analysisValuesBucket;
    analysisValuesBucket.Put(REFRESH_ALBUM_ID, ANALYSIS_ALBUM_ID + ANALYSIS_ALBUM_OFFSET);
    analysisValuesBucket.Put(ALBUM_REFRESH_STATUS, REFRESH_ALBUM_STATUS);
    outRowId = 0;
    ret = g_rdbStore->Insert(outRowId, ALBUM_REFRESH_TABLE, analysisValuesBucket);
    EXPECT_EQ(ret, E_OK);
}

void InitAlbumsTestData()
{
    InsertPhotoAlbumTestData();
    InsertAnalysisAlbumTestData();
    InsertRefreshAlbumTestData();
}

void ClearAllTableData()
{
    string clearPhotoAlbumSql = "DELETE FROM " + PhotoAlbumColumns::TABLE;
    string clearAnalysisAlbumSql = "DELETE FROM " + ANALYSIS_ALBUM_TABLE;
    string clearRefreshAlbumSql = "DELETE FROM " + ALBUM_REFRESH_TABLE;
    vector<string> executeSqlStrs = {
        clearPhotoAlbumSql,
        clearAnalysisAlbumSql,
        clearRefreshAlbumSql,
    };
    MEDIA_INFO_LOG("start clear data in all tables");
    ExecSqls(executeSqlStrs);
}

void AlbumsRefreshManagerTest::SetUpTestCase(void)
{
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    SetAllTestTables();
    MEDIA_INFO_LOG("SetUpTestCase");
}

void AlbumsRefreshManagerTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    CleanAllTestTables();
    g_rdbStore = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void AlbumsRefreshManagerTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearAllTableData();
    InitAlbumsTestData();
}

void AlbumsRefreshManagerTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(AlbumsRefreshManagerTest, RefreshPhotoAlbumsBySyncNotifyInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start RefreshPhotoAlbumsBySyncNotifyInfo_Test_001");
    EXPECT_NE((g_rdbStore == nullptr), true);
    SyncNotifyInfo info;
    info.taskType = TIME_END_SYNC;
    AlbumsRefreshManager::GetInstance().RefreshPhotoAlbumsBySyncNotifyInfo(g_rdbStore, info);
    EXPECT_EQ(info.forceRefreshType, ForceRefreshType::NONE);
}

HWTEST_F(AlbumsRefreshManagerTest, RefreshPhotoAlbumsBySyncNotifyInfo_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start RefreshPhotoAlbumsBySyncNotifyInfo_Test_002");
    EXPECT_NE((g_rdbStore == nullptr), true);
    SyncNotifyInfo info;
    info.taskType = TIME_BEGIN_SYNC;
    info.notifyType = NOTIFY_ADD;
    info.urisSize = NOTIFY_ADD_URI_SIZE;
    info.forceRefreshType = ForceRefreshType::NONE;
    AlbumsRefreshManager::GetInstance().RefreshPhotoAlbumsBySyncNotifyInfo(g_rdbStore, info);
    EXPECT_EQ(info.notifyAlbums, true);
}

HWTEST_F(AlbumsRefreshManagerTest, GetSyncNotifyInfo_Notify_ADD, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetSyncNotifyInfo_Notify_ADD");
    CloudSyncNotifyInfo notifyInfo;
    notifyInfo.type = ChangeType::INSERT;
    NotifyType notifyType = AlbumsRefreshManager::GetInstance()
                                                .GetSyncNotifyInfo(notifyInfo, OTHER_URI_TYPE)
                                                .notifyType;
    EXPECT_EQ(notifyType, NOTIFY_ADD);
}

HWTEST_F(AlbumsRefreshManagerTest, GetSyncNotifyInfo_Notify_REMOVE, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetSyncNotifyInfo_Notify_REMOVE");
    CloudSyncNotifyInfo notifyInfo;
    notifyInfo.type = ChangeType::DELETE;
    NotifyType notifyType = AlbumsRefreshManager::GetInstance()
                                                .GetSyncNotifyInfo(notifyInfo, OTHER_URI_TYPE)
                                                .notifyType;
    EXPECT_EQ(notifyType, NOTIFY_REMOVE);
}

HWTEST_F(AlbumsRefreshManagerTest, GetSyncNotifyInfo_Notify_UPDATE, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetSyncNotifyInfo_Notify_UPDATE");
    CloudSyncNotifyInfo notifyInfo;
    notifyInfo.type = ChangeType::UPDATE;
    NotifyType notifyType = AlbumsRefreshManager::GetInstance()
                                                .GetSyncNotifyInfo(notifyInfo, OTHER_URI_TYPE)
                                                .notifyType;
    EXPECT_EQ(notifyType, NOTIFY_UPDATE);
}

HWTEST_F(AlbumsRefreshManagerTest, GetSyncNotifyInfo_Notify_INVALID, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start GetSyncNotifyInfo_Notify_INVALID");
    CloudSyncNotifyInfo notifyInfo;
    notifyInfo.type = ChangeType::DELETE;
    NotifyType notifyType = AlbumsRefreshManager::GetInstance()
                                                .GetSyncNotifyInfo(notifyInfo, OTHER_URI_TYPE)
                                                .notifyType;
    EXPECT_EQ(notifyType, NOTIFY_INVALID);
}
}  // namespace OHOS::Media