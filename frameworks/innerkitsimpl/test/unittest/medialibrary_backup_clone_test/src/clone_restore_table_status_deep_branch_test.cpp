/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloneRestoreTableStatusDeepBranchTest"

#include "clone_restore_table_status_deep_branch_test.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "clone_restore.h"
#include "backup_database_utils.h"
#include "photo_album_column.h"
#include "rdb_helper.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string DB_PATH = "/data/test/backup/clone_restore_table_status_deep_branch.db";
std::shared_ptr<RdbStore> g_db = nullptr;

int ExecSqlList(RdbStore &store, const std::vector<std::string> &sqls)
{
    for (const auto &sql : sqls) {
        int ret = store.ExecuteSql(sql);
        if (ret != E_OK) {
            return ret;
        }
    }
    return E_OK;
}

const std::vector<std::string> DEEP_SCHEMA_SQLS = {
    "CREATE TABLE IF NOT EXISTS Photos ("
        "file_id INTEGER PRIMARY KEY, "
        "data TEXT, "
        "size BIGINT DEFAULT 0, "
        "media_type INT DEFAULT 1, "
        "display_name TEXT, "
        "date_added BIGINT DEFAULT 0, "
        "date_modified BIGINT DEFAULT 0, "
        "date_taken BIGINT DEFAULT 0, "
        "orientation INT DEFAULT 0, "
        "subtype INT DEFAULT 0, "
        "date_trashed BIGINT DEFAULT 0, "
        "hidden INT DEFAULT 0, "
        "position INT DEFAULT 1, "
        "sync_status INT DEFAULT 0, "
        "clean_flag INT DEFAULT 0, "
        "time_pending BIGINT DEFAULT 0, "
        "is_temp INT DEFAULT 0, "
        "photo_file_source_type INT DEFAULT 0, "
        "south_device_type INT DEFAULT 0, "
        "owner_album_id INT DEFAULT 0, "
        "package_name TEXT DEFAULT '', "
        "photo_risk_status INT DEFAULT 0, "
        "is_critical INT DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS PhotoAlbum ("
        "album_id INTEGER PRIMARY KEY, "
        "album_type INT DEFAULT 0, "
        "album_subtype INT DEFAULT 0, "
        "album_name TEXT DEFAULT '', "
        "album_bundle_name TEXT DEFAULT '', "
        "album_lpath TEXT DEFAULT '', "
        "date_modified BIGINT DEFAULT 0, "
        "bundle_name TEXT DEFAULT '', "
        "lpath TEXT DEFAULT '', "
        "priority INT DEFAULT 1, "
        "upload_status INT DEFAULT 0, "
        "is_local INT DEFAULT 1, "
        "cloud_id TEXT DEFAULT '', "
        "relative_path TEXT DEFAULT '', "
        "dirty INT DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS PhotoMap ("
        "map_album INT DEFAULT 0, "
        "map_asset INT DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS AnalysisAlbum ("
        "album_id INTEGER PRIMARY KEY, "
        "album_type INT DEFAULT 0, "
        "album_subtype INT DEFAULT 0, "
        "album_name TEXT DEFAULT '', "
        "tag_id TEXT DEFAULT '');",
    "CREATE TABLE IF NOT EXISTS AnalysisPhotoMap ("
        "map_album INT DEFAULT 0, "
        "map_asset INT DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS Audios ("
        "file_id INTEGER PRIMARY KEY, "
        "data TEXT, "
        "size BIGINT DEFAULT 0, "
        "media_type INT DEFAULT 2, "
        "display_name TEXT, "
        "date_added BIGINT DEFAULT 0, "
        "date_modified BIGINT DEFAULT 0);",
};

class DeepSchemaCallback final : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return ExecSqlList(store, DEEP_SCHEMA_SQLS);
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

void ClearDb()
{
    if (g_db == nullptr) {
        return;
    }
    (void)g_db->ExecuteSql("DELETE FROM Photos;");
    (void)g_db->ExecuteSql("DELETE FROM PhotoAlbum;");
    (void)g_db->ExecuteSql("DELETE FROM PhotoMap;");
    (void)g_db->ExecuteSql("DELETE FROM AnalysisAlbum;");
    (void)g_db->ExecuteSql("DELETE FROM AnalysisPhotoMap;");
    (void)g_db->ExecuteSql("DELETE FROM Audios;");
}

bool Contains(const std::string &src, const std::string &needle)
{
    return src.find(needle) != std::string::npos;
}

std::unordered_map<std::string, std::string> BuildPhotoCols(const std::vector<std::string> &cols)
{
    std::unordered_map<std::string, std::string> m;
    for (const auto &c : cols) {
        m[c] = "INT";
    }
    return m;
}

AlbumInfo MakeAlbumInfo(int32_t oldId, int32_t type, int32_t subtype, const std::string &name)
{
    AlbumInfo info;
    info.albumIdOld = oldId;
    info.albumType = static_cast<PhotoAlbumType>(type);
    info.albumSubType = static_cast<PhotoAlbumSubType>(subtype);
    info.albumName = name;
    return info;
}
} // namespace

void CloneRestoreTableStatusDeepBranchTest::SetUpTestCase(void)
{
    int32_t errCode = E_OK;
    DeepSchemaCallback cb;
    (void)RdbHelper::DeleteRdbStore(DB_PATH);
    g_db = RdbHelper::GetRdbStore(RdbStoreConfig(DB_PATH), 1, cb, errCode);
    ASSERT_NE(g_db, nullptr);
}

void CloneRestoreTableStatusDeepBranchTest::TearDownTestCase(void)
{
    g_db = nullptr;
    (void)RdbHelper::DeleteRdbStore(DB_PATH);
}

void CloneRestoreTableStatusDeepBranchTest::SetUp()
{
    ClearDb();
}

void CloneRestoreTableStatusDeepBranchTest::TearDown()
{
    ClearDb();
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_NullDb_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {{PhotoColumn::PHOTOS_TABLE}};
    restore.CheckTableColumnStatus(nullptr, groups);
    EXPECT_FALSE(restore.IsReadyForRestore(PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_EmptyGroups_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups;
    restore.CheckTableColumnStatus(g_db, groups);
    EXPECT_TRUE(restore.tableColumnStatusMap_.empty());
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_.empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_BreakStopsQueryForSameGroup_001,
    TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {{"UnknownA", PhotoColumn::PHOTOS_TABLE}};
    restore.CheckTableColumnStatus(g_db, groups);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_.count("UnknownA") == 0);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_.count(PhotoColumn::PHOTOS_TABLE) == 0);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasColumns_LargeSetAllHit_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns;
    std::unordered_set<std::string> required;
    for (int i = 0; i < 30; i++) {
        std::string key = "k" + std::to_string(i);
        columns[key] = "INT";
        required.insert(key);
    }
    EXPECT_TRUE(restore.HasColumns(columns, required));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasColumns_LargeSetMissTail_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns;
    std::unordered_set<std::string> required;
    for (int i = 0; i < 30; i++) {
        std::string key = "k" + std::to_string(i);
        required.insert(key);
        if (i != 29) {
            columns[key] = "INT";
        }
    }
    EXPECT_FALSE(restore.HasColumns(columns, required));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasColumn_CaseSensitive_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"Album_Name", "TEXT"}};
    EXPECT_FALSE(restore.HasColumn(columns, "album_name"));
    EXPECT_TRUE(restore.HasColumn(columns, "Album_Name"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlyPosition_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_POSITION});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, PhotoColumn::PHOTO_POSITION));
    EXPECT_FALSE(Contains(s, PhotoColumn::PHOTO_SYNC_STATUS));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlySyncStatus_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_SYNC_STATUS});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, PhotoColumn::PHOTO_SYNC_STATUS));
    EXPECT_FALSE(Contains(s, PhotoColumn::PHOTO_CLEAN_FLAG));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlyCleanFlag_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_CLEAN_FLAG});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, PhotoColumn::PHOTO_CLEAN_FLAG));
    EXPECT_FALSE(Contains(s, MediaColumn::MEDIA_TIME_PENDING));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlyTimePending_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({MediaColumn::MEDIA_TIME_PENDING});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, MediaColumn::MEDIA_TIME_PENDING));
    EXPECT_FALSE(Contains(s, PhotoColumn::PHOTO_FILE_SOURCE_TYPE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlyIsTemp_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_IS_TEMP});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, PhotoColumn::PHOTO_IS_TEMP));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoOnlyFileSourceType_001, TestSize.Level1)
{
    CloneRestore restore;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_FILE_SOURCE_TYPE});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, PhotoColumn::PHOTO_FILE_SOURCE_TYPE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_PhotoNoMatchedColumnsClearsOld_001,
    TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "old = 1";
    auto cols = BuildPhotoCols({"not_used"});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_UnknownKeepsOld_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_["unknown_t"] = "x = 1";
    std::unordered_map<std::string, std::string> cols = {{"x", "INT"}};
    restore.GetQueryWhereClause("unknown_t", cols);
    EXPECT_EQ(restore.tableQueryWhereClauseMap_["unknown_t"], "x = 1");
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_AlbumNoMatchedColumns_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> cols = {{"unknown", "INT"}};
    restore.GetQueryWhereClause(PhotoAlbumColumns::TABLE, cols);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_[PhotoAlbumColumns::TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_AnalysisTypeOnly_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> cols = {{PhotoAlbumColumns::ALBUM_TYPE, "INT"}};
    restore.GetQueryWhereClause(ANALYSIS_ALBUM_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE];
    EXPECT_TRUE(Contains(s, PhotoAlbumColumns::ALBUM_TYPE));
    EXPECT_FALSE(Contains(s, PhotoAlbumColumns::ALBUM_SUBTYPE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_AnalysisNoMatchedColumns_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> cols = {{"unknown", "INT"}};
    restore.GetQueryWhereClause(ANALYSIS_ALBUM_TABLE, cols);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetAlbumExtraQueryWhereClause_PhotoClauseEmpty_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "";
    restore.GetAlbumExtraQueryWhereClause(PhotoAlbumColumns::TABLE);
    std::string s = restore.tableExtraQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_TRUE(Contains(s, "EXISTS"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetAlbumExtraQueryWhereClause_OverrideOld_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableExtraQueryWhereClauseMap_[PhotoAlbumColumns::TABLE] = "old_clause";
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "sync_status = 0";
    restore.GetAlbumExtraQueryWhereClause(PhotoAlbumColumns::TABLE);
    std::string s = restore.tableExtraQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_FALSE(Contains(s, "old_clause"));
    EXPECT_TRUE(Contains(s, "sync_status = 0"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClauseByTable_ExtraExistsButEmpty_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "a = 1";
    restore.tableExtraQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "";
    std::string s = restore.GetQueryWhereClauseByTable(PhotoColumn::PHOTOS_TABLE);
    EXPECT_TRUE(Contains(s, "a = 1"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_EmptyInput_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    std::vector<AlbumInfo> infos;
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_IgnoreInvalidOldIdZero_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) "
        "VALUES (10, 1, 2, 'A');"), E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(0, 1, 2, "A"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, -1);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_IgnoreInvalidOldIdNegative_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) "
        "VALUES (11, 1, 3, 'B');"), E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(-2, 1, 3, "B"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, -1);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_NameContainsQuote_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(1, 1, 2, "a'b"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, -1);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].count(1) == 0);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_WhitespaceName_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) "
        "VALUES (12, 1, 4, '   ');"), E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(2, 1, 4, "   "));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 12);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][2], 12);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_DuplicateInputsSameOldId_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) "
        "VALUES (13, 1, 5, 'C');"), E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(3, 1, 5, "C"));
    infos.push_back(MakeAlbumInfo(3, 1, 5, "C"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 13);
    EXPECT_EQ(infos[1].albumIdNew, 13);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][3], 13);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_DuplicateInputsDifferentOldIds_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) "
        "VALUES (14, 1, 6, 'D');"), E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(4, 1, 6, "D"));
    infos.push_back(MakeAlbumInfo(5, 1, 6, "D"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][4], 14);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][5], 14);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasSameAlbum_NotPhotoTable_NotFound_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    restore.photoAlbumClone_.OnStart(g_db, g_db, false);
    AlbumInfo info;
    info.lPath = "/No/Such/Path";
    info.albumIdNew = -1;
    EXPECT_FALSE(restore.HasSameAlbum(info, ANALYSIS_ALBUM_TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckSouthDeviceType_InvalidValueInDb_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO Photos (file_id, data, position, south_device_type) VALUES (1001, 'p1', 2, 99);"), E_OK);
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckSouthDeviceType_NullTypeMismatch_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO Photos (file_id, data, position, south_device_type) VALUES (1002, 'p2', 2, 0);"), E_OK);
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::HDC));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckSouthDeviceType_MixedCloudAndHdc_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO Photos (file_id, data, position, south_device_type) VALUES (1007, 'p7', 2, 2);"), E_OK);
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO Photos (file_id, data, position, south_device_type) VALUES (1008, 'p8', 2, 3);"), E_OK);
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckSouthDeviceType_SwitchNone_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO Photos (file_id, data, position, south_device_type) VALUES (1009, 'p9', 2, 2);"), E_OK);
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::NONE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckAlbumNameUnique_NotInRepeatList_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::string> repeated = {"abc", "def"};
    EXPECT_TRUE(restore.CheckAlbumNameUnique("xyz", repeated));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, UpdateSourceAlbumName_UniqueAtFirstTry_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.photoAlbumClone_.OnStart(g_db, g_db, false);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(1, static_cast<int32_t>(PhotoAlbumType::SOURCE),
        static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC), "Trip"));
    std::vector<std::string> repeated = {"trip"};
    bool isUnique = false;
    restore.UpdateSourceAlbumName(isUnique, infos, repeated, 0);
    EXPECT_TRUE(isUnique);
    EXPECT_EQ(infos[0].albumName, "Trip 1");
    EXPECT_TRUE(std::count(repeated.begin(), repeated.end(), "trip 1") > 0);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, UpdateSourceAlbumName_IndexOutOfRange_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<AlbumInfo> infos;
    std::vector<std::string> repeated;
    bool isUnique = false;
    restore.UpdateSourceAlbumName(isUnique, infos, repeated, 3);
    EXPECT_FALSE(isUnique);
    EXPECT_TRUE(repeated.empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_AudioGroupReady_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {{AudioColumn::AUDIOS_TABLE}};
    restore.CheckTableColumnStatus(g_db, groups);
    EXPECT_TRUE(restore.IsReadyForRestore(AudioColumn::AUDIOS_TABLE));
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_.count(AudioColumn::AUDIOS_TABLE) == 0 ||
        restore.tableQueryWhereClauseMap_[AudioColumn::AUDIOS_TABLE].empty());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_MapTableReady_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {{PhotoMap::TABLE}};
    restore.CheckTableColumnStatus(g_db, groups);
    EXPECT_TRUE(restore.IsReadyForRestore(PhotoMap::TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, CheckTableColumnStatus_AnalysisMapGroupReady_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {{ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE}};
    restore.CheckTableColumnStatus(g_db, groups);
    EXPECT_TRUE(restore.IsReadyForRestore(ANALYSIS_ALBUM_TABLE));
    EXPECT_TRUE(restore.IsReadyForRestore(ANALYSIS_PHOTO_MAP_TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, IsReadyForRestore_UnknownTableFalse_001, TestSize.Level1)
{
    CloneRestore restore;
    EXPECT_FALSE(restore.IsReadyForRestore("not_exist_table"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_AnalysisAlbumHit_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO AnalysisAlbum (album_id, album_type, album_subtype, album_name) VALUES (301, 2, 4104, 'P');"),
        E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(101, 2, 4104, "P"));
    restore.BatchQueryAlbum(infos, ANALYSIS_ALBUM_TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 301);
    EXPECT_EQ(restore.tableAlbumIdMap_[ANALYSIS_ALBUM_TABLE][101], 301);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_AnalysisAlbumMiss_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(102, 2, 4104, "NoPortrait"));
    restore.BatchQueryAlbum(infos, ANALYSIS_ALBUM_TABLE);
    EXPECT_EQ(infos[0].albumIdNew, -1);
    EXPECT_TRUE(restore.tableAlbumIdMap_[ANALYSIS_ALBUM_TABLE].count(102) == 0);
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasSameAlbum_PhotoAlbumFound_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) VALUES (400, 3, 1, 'X');"), E_OK);
    AlbumInfo info = MakeAlbumInfo(1, 3, 1, "X");
    EXPECT_TRUE(restore.HasSameAlbum(info, PhotoAlbumColumns::TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, HasSameAlbum_PhotoAlbumMiss_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    AlbumInfo info = MakeAlbumInfo(2, 3, 2, "Y");
    EXPECT_FALSE(restore.HasSameAlbum(info, PhotoAlbumColumns::TABLE));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, IsCloudRestoreSatisfied_AllCombinations_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = false;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = false;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_TRUE(restore.IsCloudRestoreSatisfied());
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_CloudAddsPosition2_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = true;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_POSITION});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, "IN (1, 2, 3)"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetQueryWhereClause_NonCloudExcludesPosition2_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = true;
    auto cols = BuildPhotoCols({PhotoColumn::PHOTO_POSITION});
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, cols);
    std::string s = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(s, "IN (1, 3)"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, GetAlbumExtraQueryWhereClause_AnalysisUsesAnalysisMap_001,
    TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "position IN (1, 3)";
    restore.GetAlbumExtraQueryWhereClause(ANALYSIS_ALBUM_TABLE);
    std::string s = restore.tableExtraQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE];
    EXPECT_TRUE(Contains(s, ANALYSIS_PHOTO_MAP_TABLE));
    EXPECT_TRUE(Contains(s, "position IN (1, 3)"));
}

HWTEST_F(CloneRestoreTableStatusDeepBranchTest, BatchQueryAlbum_TwoHitsAndOneMiss_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_db;
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) VALUES (501, 1, 10, 'A1');"),
        E_OK);
    ASSERT_EQ(g_db->ExecuteSql(
        "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) VALUES (502, 1, 11, 'A2');"),
        E_OK);
    std::vector<AlbumInfo> infos;
    infos.push_back(MakeAlbumInfo(201, 1, 10, "A1"));
    infos.push_back(MakeAlbumInfo(202, 1, 11, "A2"));
    infos.push_back(MakeAlbumInfo(203, 1, 12, "A3"));
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 501);
    EXPECT_EQ(infos[1].albumIdNew, 502);
    EXPECT_EQ(infos[2].albumIdNew, -1);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][201], 501);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][202], 502);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].count(203) == 0);
}
} // namespace Media
} // namespace OHOS
