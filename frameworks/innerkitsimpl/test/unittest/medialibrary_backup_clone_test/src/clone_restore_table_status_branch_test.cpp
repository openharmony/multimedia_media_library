/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define MLOG_TAG "CloneRestoreTableStatusBranchTest"

#include "clone_restore_table_status_branch_test.h"

#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define private public
#define protected public
#include "clone_restore.h"
#undef private
#undef protected

#include "backup_database_utils.h"
#include "photo_album_column.h"
#include "rdb_helper.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string FULL_DB_PATH = "/data/test/backup/clone_restore_table_status_full.db";
const std::string MISS_DB_PATH = "/data/test/backup/clone_restore_table_status_miss.db";
std::shared_ptr<RdbStore> g_fullDb = nullptr;
std::shared_ptr<RdbStore> g_missDb = nullptr;

class FullSchemaCallback final : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        std::vector<std::string> sqls = {
            "CREATE TABLE IF NOT EXISTS Photos ("
                "file_id INTEGER PRIMARY KEY, "
                "data TEXT, "
                "size BIGINT DEFAULT 0, "
                "media_type INT DEFAULT 1, "
                "display_name TEXT, "
                "date_added BIGINT DEFAULT 0, "
                "date_modified BIGINT DEFAULT 0, "
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
                "photo_risk_status INT DEFAULT 0, "
                "is_critical INT DEFAULT 0, "
                "package_name TEXT DEFAULT '');",
            "CREATE TABLE IF NOT EXISTS PhotoAlbum ("
                "album_id INTEGER PRIMARY KEY, "
                "album_type INT DEFAULT 0, "
                "album_subtype INT DEFAULT 0, "
                "album_name TEXT, "
                "album_bundle_name TEXT DEFAULT '', "
                "album_lpath TEXT DEFAULT '', "
                "date_modified BIGINT DEFAULT 0);",
            "CREATE TABLE IF NOT EXISTS PhotoMap ("
                "map_album INT DEFAULT 0, "
                "map_asset INT DEFAULT 0);",
            "CREATE TABLE IF NOT EXISTS AnalysisAlbum ("
                "album_id INTEGER PRIMARY KEY, "
                "album_type INT DEFAULT 0, "
                "album_subtype INT DEFAULT 0, "
                "album_name TEXT);",
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
        for (const auto &sql : sqls) {
            int ret = store.ExecuteSql(sql);
            if (ret != E_OK) {
                return ret;
            }
        }
        return E_OK;
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class MissingSchemaCallback final : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        std::vector<std::string> sqls = {
            "CREATE TABLE IF NOT EXISTS Photos ("
                "file_id INTEGER PRIMARY KEY, "
                "data TEXT, "
                "size BIGINT DEFAULT 0, "
                "media_type INT DEFAULT 1, "
                "display_name TEXT, "
                "date_added BIGINT DEFAULT 0, "
                "date_modified BIGINT DEFAULT 0, "
                "orientation INT DEFAULT 0, "
                "subtype INT DEFAULT 0, "
                "date_trashed BIGINT DEFAULT 0);",
            "CREATE TABLE IF NOT EXISTS PhotoAlbum ("
                "album_id INTEGER PRIMARY KEY, "
                "album_type INT DEFAULT 0, "
                "album_subtype INT DEFAULT 0, "
                "album_name TEXT);",
            "CREATE TABLE IF NOT EXISTS AnalysisAlbum ("
                "album_id INTEGER PRIMARY KEY, "
                "album_type INT DEFAULT 0, "
                "album_subtype INT DEFAULT 0, "
                "album_name TEXT);",
            "CREATE TABLE IF NOT EXISTS Audios ("
                "file_id INTEGER PRIMARY KEY, "
                "data TEXT, "
                "size BIGINT DEFAULT 0, "
                "media_type INT DEFAULT 2, "
                "display_name TEXT);",
        };
        for (const auto &sql : sqls) {
            int ret = store.ExecuteSql(sql);
            if (ret != E_OK) {
                return ret;
            }
        }
        return E_OK;
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

void ClearDb(const std::shared_ptr<RdbStore> &db)
{
    if (db == nullptr) {
        return;
    }
    (void)db->ExecuteSql("DELETE FROM Photos;");
    (void)db->ExecuteSql("DELETE FROM PhotoAlbum;");
    (void)db->ExecuteSql("DELETE FROM PhotoMap;");
    (void)db->ExecuteSql("DELETE FROM AnalysisAlbum;");
    (void)db->ExecuteSql("DELETE FROM AnalysisPhotoMap;");
    (void)db->ExecuteSql("DELETE FROM Audios;");
}

bool Contains(const std::string &src, const std::string &needle)
{
    return src.find(needle) != std::string::npos;
}

std::unordered_map<std::string, std::string> BuildPhotoColumns()
{
    return {
        {MediaColumn::MEDIA_ID, "INT"},
        {MediaColumn::MEDIA_FILE_PATH, "TEXT"},
        {MediaColumn::MEDIA_SIZE, "BIGINT"},
        {MediaColumn::MEDIA_TYPE, "INT"},
        {MediaColumn::MEDIA_NAME, "TEXT"},
        {MediaColumn::MEDIA_DATE_ADDED, "BIGINT"},
        {MediaColumn::MEDIA_DATE_MODIFIED, "BIGINT"},
        {PhotoColumn::PHOTO_ORIENTATION, "INT"},
        {PhotoColumn::PHOTO_SUBTYPE, "INT"},
        {MediaColumn::MEDIA_DATE_TRASHED, "BIGINT"},
        {MediaColumn::MEDIA_HIDDEN, "INT"},
        {PhotoColumn::PHOTO_POSITION, "INT"},
        {PhotoColumn::PHOTO_SYNC_STATUS, "INT"},
        {PhotoColumn::PHOTO_CLEAN_FLAG, "INT"},
        {MediaColumn::MEDIA_TIME_PENDING, "BIGINT"},
        {PhotoColumn::PHOTO_IS_TEMP, "INT"},
        {PhotoColumn::PHOTO_FILE_SOURCE_TYPE, "INT"},
    };
}

std::unordered_map<std::string, std::string> BuildAlbumColumns(bool withType = true, bool withName = true,
    bool withSubtype = true)
{
    std::unordered_map<std::string, std::string> columns;
    if (withType) {
        columns[PhotoAlbumColumns::ALBUM_TYPE] = "INT";
    }
    if (withSubtype) {
        columns[PhotoAlbumColumns::ALBUM_SUBTYPE] = "INT";
    }
    if (withName) {
        columns[PhotoAlbumColumns::ALBUM_NAME] = "TEXT";
    }
    return columns;
}
} // namespace

void CloneRestoreTableStatusBranchTest::SetUpTestCase(void)
{
    int32_t errCode = E_OK;
    FullSchemaCallback fullCb;
    MissingSchemaCallback missCb;
    (void)RdbHelper::DeleteRdbStore(FULL_DB_PATH);
    (void)RdbHelper::DeleteRdbStore(MISS_DB_PATH);
    g_fullDb = RdbHelper::GetRdbStore(RdbStoreConfig(FULL_DB_PATH), 1, fullCb, errCode);
    ASSERT_NE(g_fullDb, nullptr);
    g_missDb = RdbHelper::GetRdbStore(RdbStoreConfig(MISS_DB_PATH), 1, missCb, errCode);
    ASSERT_NE(g_missDb, nullptr);
}

void CloneRestoreTableStatusBranchTest::TearDownTestCase(void)
{
    g_fullDb = nullptr;
    g_missDb = nullptr;
    (void)RdbHelper::DeleteRdbStore(FULL_DB_PATH);
    (void)RdbHelper::DeleteRdbStore(MISS_DB_PATH);
}

void CloneRestoreTableStatusBranchTest::SetUp()
{
    ClearDb(g_fullDb);
    ClearDb(g_missDb);
}

void CloneRestoreTableStatusBranchTest::TearDown()
{
    ClearDb(g_fullDb);
    ClearDb(g_missDb);
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasColumn_True_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"a", "INT"}, {"b", "TEXT"}};
    EXPECT_TRUE(restore.HasColumn(columns, "a"));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasColumn_False_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"a", "INT"}};
    EXPECT_FALSE(restore.HasColumn(columns, "x"));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasColumns_AllPresent_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"a", "INT"}, {"b", "TEXT"}};
    std::unordered_set<std::string> required = {"a", "b"};
    EXPECT_TRUE(restore.HasColumns(columns, required));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasColumns_Missing_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"a", "INT"}};
    std::unordered_set<std::string> required = {"a", "b"};
    EXPECT_FALSE(restore.HasColumns(columns, required));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasColumns_EmptyRequired_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"a", "INT"}};
    std::unordered_set<std::string> required;
    EXPECT_TRUE(restore.HasColumns(columns, required));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, IsReadyForRestore_DefaultFalse_001, TestSize.Level1)
{
    CloneRestore restore;
    EXPECT_FALSE(restore.IsReadyForRestore(PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, IsReadyForRestore_True_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableColumnStatusMap_[PhotoColumn::PHOTOS_TABLE] = true;
    EXPECT_TRUE(restore.IsReadyForRestore(PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, IsReadyForRestore_FalseAfterSet_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableColumnStatusMap_[PhotoColumn::PHOTOS_TABLE] = false;
    EXPECT_FALSE(restore.IsReadyForRestore(PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_PhotosNonCloudAll_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = false;
    auto columns = BuildPhotoColumns();
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(clause, "IN (1, 3)"));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_SYNC_STATUS));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_CLEAN_FLAG));
    EXPECT_TRUE(Contains(clause, MediaColumn::MEDIA_TIME_PENDING));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_IS_TEMP));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_FILE_SOURCE_TYPE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_PhotosCloudAll_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = true;
    auto columns = BuildPhotoColumns();
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(clause, "IN (1, 2, 3)"));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_PhotosPartial_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {
        {PhotoColumn::PHOTO_POSITION, "INT"},
        {PhotoColumn::PHOTO_SYNC_STATUS, "INT"},
    };
    restore.GetQueryWhereClause(PhotoColumn::PHOTOS_TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE];
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTO_SYNC_STATUS));
    EXPECT_FALSE(Contains(clause, PhotoColumn::PHOTO_CLEAN_FLAG));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_AlbumAll_001, TestSize.Level1)
{
    CloneRestore restore;
    auto columns = BuildAlbumColumns(true, true, true);
    restore.GetQueryWhereClause(PhotoAlbumColumns::TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_NAME));
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_TYPE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_AlbumOnlyName_001, TestSize.Level1)
{
    CloneRestore restore;
    auto columns = BuildAlbumColumns(false, true, false);
    restore.GetQueryWhereClause(PhotoAlbumColumns::TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_NAME));
    EXPECT_FALSE(Contains(clause, "album_type !="));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_AnalysisAlbumAll_001, TestSize.Level1)
{
    CloneRestore restore;
    auto columns = BuildAlbumColumns(true, true, true);
    restore.GetQueryWhereClause(ANALYSIS_ALBUM_TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE];
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_NAME));
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_SUBTYPE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_AnalysisAlbumOnlyName_001, TestSize.Level1)
{
    CloneRestore restore;
    auto columns = BuildAlbumColumns(false, true, false);
    restore.GetQueryWhereClause(ANALYSIS_ALBUM_TABLE, columns);
    std::string clause = restore.tableQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE];
    EXPECT_TRUE(Contains(clause, PhotoAlbumColumns::ALBUM_NAME));
    EXPECT_FALSE(Contains(clause, PhotoAlbumColumns::ALBUM_SUBTYPE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClause_UnknownTable_001, TestSize.Level1)
{
    CloneRestore restore;
    std::unordered_map<std::string, std::string> columns = {{"x", "INT"}};
    restore.GetQueryWhereClause("unknown_table", columns);
    EXPECT_TRUE(restore.tableQueryWhereClauseMap_.count("unknown_table") == 0 ||
        restore.tableQueryWhereClauseMap_["unknown_table"].empty());
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetAlbumExtraQueryWhereClause_PhotoAlbum_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.GetAlbumExtraQueryWhereClause(PhotoAlbumColumns::TABLE);
    ASSERT_TRUE(restore.tableExtraQueryWhereClauseMap_.count(PhotoAlbumColumns::TABLE) > 0);
    auto clause = restore.tableExtraQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_TRUE(Contains(clause, PhotoMap::TABLE));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetAlbumExtraQueryWhereClause_AnalysisAlbum_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.GetAlbumExtraQueryWhereClause(ANALYSIS_ALBUM_TABLE);
    ASSERT_TRUE(restore.tableExtraQueryWhereClauseMap_.count(ANALYSIS_ALBUM_TABLE) > 0);
    auto clause = restore.tableExtraQueryWhereClauseMap_[ANALYSIS_ALBUM_TABLE];
    EXPECT_TRUE(Contains(clause, ANALYSIS_PHOTO_MAP_TABLE));
    EXPECT_TRUE(Contains(clause, PhotoColumn::PHOTOS_TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetAlbumExtraQueryWhereClause_InvalidTable_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.GetAlbumExtraQueryWhereClause("invalid_table");
    EXPECT_TRUE(restore.tableExtraQueryWhereClauseMap_.count("invalid_table") == 0);
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetAlbumExtraQueryWhereClause_UsesPhotoClause_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "position IN (1, 3)";
    restore.GetAlbumExtraQueryWhereClause(PhotoAlbumColumns::TABLE);
    auto clause = restore.tableExtraQueryWhereClauseMap_[PhotoAlbumColumns::TABLE];
    EXPECT_TRUE(Contains(clause, "position IN (1, 3)"));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClauseByTable_None_001, TestSize.Level1)
{
    CloneRestore restore;
    EXPECT_TRUE(restore.GetQueryWhereClauseByTable(PhotoColumn::PHOTOS_TABLE).empty());
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClauseByTable_OnlyBase_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "a = 1";
    EXPECT_EQ(restore.GetQueryWhereClauseByTable(PhotoColumn::PHOTOS_TABLE), "a = 1");
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClauseByTable_Both_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "a = 1";
    restore.tableExtraQueryWhereClauseMap_[PhotoColumn::PHOTOS_TABLE] = "b = 2";
    EXPECT_EQ(restore.GetQueryWhereClauseByTable(PhotoColumn::PHOTOS_TABLE), "a = 1 AND b = 2");
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckTableColumnStatus_GlobalFalseIfOneMissing_001, TestSize.Level1)
{
    CloneRestore restore;
    std::vector<std::vector<std::string>> groups = {
        {PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE},
    };
    restore.CheckTableColumnStatus(g_missDb, groups);
    EXPECT_FALSE(restore.IsReadyForRestore(PhotoColumn::PHOTOS_TABLE));
    EXPECT_FALSE(restore.IsReadyForRestore(PhotoAlbumColumns::TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_NullDb_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = nullptr;
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_InvalidSwitch_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_fullDb;
    EXPECT_FALSE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::NONE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_EmptyResultTrue_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_fullDb;
    EXPECT_TRUE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_CloudMatch_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO Photos (file_id, data, sync_status, clean_flag, time_pending, is_temp, position, south_device_type)"
        " VALUES (2, 'b', 0, 0, 0, 0, 2, 2);"), E_OK);
    EXPECT_TRUE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_HdcMatch_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO Photos (file_id, data, sync_status, clean_flag, time_pending, is_temp, position, south_device_type)"
        " VALUES (3, 'c', 0, 0, 0, 0, 2, 3);"), E_OK);
    EXPECT_TRUE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::HDC));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, CheckSouthDeviceTypeMatchSwitchStatus_MultiRowsAllMatch_001,
    TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO Photos (file_id, data, sync_status, clean_flag, time_pending, is_temp, position, south_device_type)"
        " VALUES (4, 'd', 0, 0, 0, 0, 2, 2);"), E_OK);
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO Photos (file_id, data, sync_status, clean_flag, time_pending, is_temp, position, south_device_type)"
        " VALUES (5, 'e', 0, 0, 0, 0, 2, 2);"), E_OK);
    EXPECT_TRUE(restore.CheckSouthDeviceTypeMatchSwitchStatus(SwitchStatus::CLOUD));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, BatchQueryAlbum_OneHitOneMiss_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name, album_bundle_name)"
        " VALUES (100, 1, 2, 'A', 'pkg');"), E_OK);

    std::vector<AlbumInfo> infos;
    AlbumInfo a;
    a.albumIdOld = 1;
    a.albumType = static_cast<PhotoAlbumType>(1);
    a.albumSubType = static_cast<PhotoAlbumSubType>(2);
    a.albumName = "A";
    infos.push_back(a);
    AlbumInfo b;
    b.albumIdOld = 2;
    b.albumType = static_cast<PhotoAlbumType>(1);
    b.albumSubType = static_cast<PhotoAlbumSubType>(3);
    b.albumName = "B";
    infos.push_back(b);

    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 100);
    EXPECT_EQ(infos[1].albumIdNew, -1);
    ASSERT_TRUE(restore.tableAlbumIdMap_.count(PhotoAlbumColumns::TABLE) > 0);
    EXPECT_EQ(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE][1], 100);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].count(2) == 0);
}

HWTEST_F(CloneRestoreTableStatusBranchTest, BatchQueryAlbum_NoRow_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_fullDb;
    std::vector<AlbumInfo> infos;
    AlbumInfo a;
    a.albumIdOld = 10;
    a.albumType = static_cast<PhotoAlbumType>(11);
    a.albumSubType = static_cast<PhotoAlbumSubType>(12);
    a.albumName = "N";
    infos.push_back(a);
    restore.BatchQueryAlbum(infos, PhotoAlbumColumns::TABLE);
    EXPECT_EQ(infos[0].albumIdNew, -1);
    EXPECT_TRUE(restore.tableAlbumIdMap_[PhotoAlbumColumns::TABLE].count(10) == 0);
}

HWTEST_F(CloneRestoreTableStatusBranchTest, BatchQueryAlbum_MultiHit_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO AnalysisAlbum (album_id, album_type, album_subtype, album_name) VALUES (201, 2, 4104, 'X');"),
        E_OK);
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO AnalysisAlbum (album_id, album_type, album_subtype, album_name) VALUES (202, 2, 4105, 'Y');"),
        E_OK);
    std::vector<AlbumInfo> infos;
    AlbumInfo a;
    a.albumIdOld = 21;
    a.albumType = static_cast<PhotoAlbumType>(2);
    a.albumSubType = static_cast<PhotoAlbumSubType>(4104);
    a.albumName = "X";
    infos.push_back(a);
    AlbumInfo b;
    b.albumIdOld = 22;
    b.albumType = static_cast<PhotoAlbumType>(2);
    b.albumSubType = static_cast<PhotoAlbumSubType>(4105);
    b.albumName = "Y";
    infos.push_back(b);
    restore.BatchQueryAlbum(infos, ANALYSIS_ALBUM_TABLE);
    EXPECT_EQ(infos[0].albumIdNew, 201);
    EXPECT_EQ(infos[1].albumIdNew, 202);
}

HWTEST_F(CloneRestoreTableStatusBranchTest, HasSameAlbum_Found_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.mediaLibraryRdb_ = g_fullDb;
    ASSERT_EQ(g_fullDb->ExecuteSql(
        "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name, album_bundle_name)"
        " VALUES (500, 1, 9, 'Found', 'pkg');"), E_OK);
    AlbumInfo info;
    info.albumType = static_cast<PhotoAlbumType>(1);
    info.albumSubType = static_cast<PhotoAlbumSubType>(9);
    info.albumName = "Found";
    EXPECT_TRUE(restore.HasSameAlbum(info, PhotoAlbumColumns::TABLE));
}

HWTEST_F(CloneRestoreTableStatusBranchTest, GetQueryWhereClauseByTable_UnrelatedTable_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.tableQueryWhereClauseMap_["t1"] = "a = 1";
    restore.tableExtraQueryWhereClauseMap_["t2"] = "b = 2";
    EXPECT_TRUE(restore.GetQueryWhereClauseByTable("t3").empty());
}

HWTEST_F(CloneRestoreTableStatusBranchTest, IsCloudRestoreSatisfied_Branches_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = false;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_TRUE(restore.IsCloudRestoreSatisfied());
}
} // namespace Media
} // namespace OHOS
