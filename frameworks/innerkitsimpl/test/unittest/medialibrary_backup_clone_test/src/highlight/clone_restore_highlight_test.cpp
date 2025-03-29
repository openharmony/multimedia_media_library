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

#define MLOG_TAG "BackupCloneTest"

#include "clone_restore_highlight_test.h"
#include "clone_highlight_source.h"

#define private public
#define protected public
#include "backup_const.h"
#include "clone_restore_highlight.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "story_album_column.h"
#include "story_cover_info_column.h"
#include "story_play_info_column.h"
#undef protected
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const vector<string> CLEAR_SQLS = {
    "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_TABLE,
    "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE,
    "DELETE FROM " + HIGHLIGHT_ALBUM_TABLE,
    "DELETE FROM " + HIGHLIGHT_COVER_INFO_TABLE,
    "DELETE FROM " + HIGHLIGHT_PLAY_INFO_TABLE,
    "DELETE FROM " + ANALYSIS_ASSET_SD_MAP_TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_ASSET_MAP_TABLE,
    "DELETE FROM " + VISION_LABEL_TABLE,
    "DELETE FROM " + VISION_RECOMMENDATION_TABLE,
    "DELETE FROM " + VISION_SALIENCY_TABLE,
};

const string TEST_BACKUP_PATH = "/data/test/backup/db";
const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
const string NONE_CONDITION = "1";
const int32_t TEST_ID = 1;
const int32_t TEST_NEW_ID = 2;
const int32_t INVALID_COUNT = -1;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

shared_ptr<MediaLibraryRdbStore> newRdbStore;
unique_ptr<CloneRestoreHighlight> cloneRestoreHighlight = nullptr;

void ExecuteRdbSqls(shared_ptr<NativeRdb::RdbStore> store, const vector<string> &sqls)
{
    for (const auto &sql : sqls) {
        int32_t errCode = store->ExecuteSql(sql);
        if (errCode == E_OK) {
            continue;
        }
        MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
    }
}

void ClearHighlightData()
{
    MEDIA_INFO_LOG("Start clear data");
    ExecuteRdbSqls(newRdbStore->GetRaw(), CLEAR_SQLS);
    if (cloneRestoreHighlight) {
        cloneRestoreHighlight->analysisInfos_.clear();
        cloneRestoreHighlight->highlightInfos_.clear();
        cloneRestoreHighlight->coverInfos_.clear();
        cloneRestoreHighlight->playInfos_.clear();
        cloneRestoreHighlight->oldAlbumIds_.clear();
        cloneRestoreHighlight->albumPhotoCounter_.clear();
        cloneRestoreHighlight->intersectionMap_.clear();
        cloneRestoreHighlight->photoIdMap_.Clear();
        cloneRestoreHighlight->photoUriMap_.Clear();
    }
    MEDIA_INFO_LOG("End clear data");
}

void Init(CloneHighlightSource &cloneHighlightSource, const string &path, const vector<string> &tableList)
{
    MEDIA_INFO_LOG("Start init clone source database");
    cloneHighlightSource.Init(path, tableList);
}

void CloneRestoreHighlightTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MEDIA_INFO_LOG("Start init restoreService");
    cloneRestoreHighlight = make_unique<CloneRestoreHighlight>();
    cloneRestoreHighlight->mediaLibraryRdb_ = newRdbStore->GetRaw(); // destination database
}

void CloneRestoreHighlightTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearHighlightData();
    cloneRestoreHighlight->mediaLibraryRdb_ = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void CloneRestoreHighlightTest::SetUp() {}

void CloneRestoreHighlightTest::TearDown(void) {}

void ClearCloneSource(CloneHighlightSource &cloneHighlightSource, const string &dbPath)
{
    cloneHighlightSource.cloneStorePtr_ = nullptr;
    NativeRdb::RdbHelper::DeleteRdbStore(dbPath);
}

void QueryIntBySql(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &querySql, const string &columnName,
    int32_t &result)
{
    ASSERT_NE(rdbStore, nullptr);
    auto resultSet = rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    result = GetInt32Val(columnName, resultSet);
    MEDIA_INFO_LOG("Query %{public}s result: %{public}d", querySql.c_str(), result);
}

int32_t GetAlbumCountByCondition(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &tableName,
    const string condition)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " + condition;
    int32_t result = INVALID_COUNT;
    QueryIntBySql(rdbStore, querySql, MEDIA_COLUMN_COUNT_1, result);
    return result;
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_restore_albums_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_restore_albums_test_001 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE,
        HIGHLIGHT_ALBUM_TABLE, HIGHLIGHT_COVER_INFO_TABLE, HIGHLIGHT_PLAY_INFO_TABLE };
    Init(cloneHighlightSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    cloneRestoreHighlight->RestoreAlbums();
    EXPECT_EQ(cloneRestoreHighlight->isMapOrder_, true);
    string analysisCondition = "album_name = 'test_highlight_album'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 2);
    int32_t highlightCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_ALBUM_TABLE, NONE_CONDITION);
    EXPECT_EQ(highlightCount, 1);
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, NONE_CONDITION);
    EXPECT_EQ(coverCount, 8);
    int32_t playCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_PLAY_INFO_TABLE, NONE_CONDITION);
    EXPECT_EQ(playCount, 1);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_restore_maps_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_restore_maps_test_001 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneHighlightSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    cloneRestoreHighlight->isMapOrder_ = true;
    vector<FileInfo> fileInfos;
    FileInfo testFileInfo;
    testFileInfo.fileIdOld = 1;
    testFileInfo.fileIdNew = 2;
    testFileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    testFileInfo.displayName = "IMG_00000000_000000.jpg";
    testFileInfo.oldPath = "/oldPath/test.jpg";
    fileInfos.emplace_back(testFileInfo);

    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.albumIdOld = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_NEW_ID);
    testAnalysisInfo.oldCoverUri = make_optional<string>("file://media/Photo/1/test/IMG_00000000_000000.jpg");
    testAnalysisInfo.albumName = make_optional<string>("testAlbumName");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    cloneRestoreHighlight->oldAlbumIds_.emplace_back(1);
    cloneRestoreHighlight->RestoreMaps(fileInfos);
    string mapCondition = "map_album = 2 AND map_asset = 2";
    int32_t mapCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_PHOTO_MAP_TABLE, mapCondition);
    EXPECT_EQ(mapCount, 1);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_values_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_values_test_001 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneHighlightSource, TEST_BACKUP_DB_PATH, tableList);
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    cloneRestoreHighlight->isMapOrder_ = false;
    FileInfo testFileInfo;
    testFileInfo.fileIdOld = 1;
    testFileInfo.fileIdNew = 2;
    testFileInfo.cloudPath = "/storage/cloud/files/Photo/16/test.jpg";
    testFileInfo.displayName = "IMG_00000000_000000.jpg";
    testFileInfo.oldPath = "/oldPath/test.jpg";
    vector<FileInfo> FileInfos = { testFileInfo };

    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.albumIdOld = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_NEW_ID);
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    cloneRestoreHighlight->oldAlbumIds_.emplace_back(1);
    vector<NativeRdb::ValuesBucket> values;
    cloneRestoreHighlight->UpdateMapInsertValues(values, FileInfos);
    string mapCondition = "map_album = 2 AND map_asset = 2";
    int32_t mapCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_PHOTO_MAP_TABLE, mapCondition);
    EXPECT_EQ(values.empty(), false);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_albums_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_albums_test_001 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE, HIGHLIGHT_COVER_INFO_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.oldCoverUri = make_optional<string>("file://testOldCoverUri");
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.coverUri = "file://testNewCoverUri";
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumName = make_optional<string>("testAlbumName");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightCoverInfo testCoverInfo;
    testCoverInfo.ratio = make_optional<string>("1_1");
    testCoverInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    cloneRestoreHighlight->coverInfos_.emplace_back(testCoverInfo);

    cloneRestoreHighlight->UpdateAlbums();
    string analysisCondition = "cover_uri = 'file://testNewCoverUri'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 1);
    string coverCondition = "cover_key = 'testAlbumName_1_1_file://testNewCoverUri'";
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, coverCondition);
    EXPECT_EQ(coverCount, 1);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_albums_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_albums_test_002 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE, HIGHLIGHT_COVER_INFO_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.coverUri = "file://testNewCoverUri";
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumName = make_optional<string>("testAlbumName");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightCoverInfo testCoverInfo;
    testCoverInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    cloneRestoreHighlight->coverInfos_.emplace_back(testCoverInfo);

    cloneRestoreHighlight->UpdateAlbums();
    string analysisCondition = "cover_uri = 'file://testNewCoverUri'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 0);
    string coverCondition = "cover_key = 'testAlbumName_1_1_file://testNewCoverUri'";
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, coverCondition);
    EXPECT_EQ(coverCount, 0);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_albums_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_albums_test_003 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE, HIGHLIGHT_COVER_INFO_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.coverUri = "file://testNewCoverUri";
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumName = make_optional<string>("testAlbumName");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightCoverInfo testCoverInfo;
    testCoverInfo.ratio = make_optional<string>("1_1");
    cloneRestoreHighlight->coverInfos_.emplace_back(testCoverInfo);

    cloneRestoreHighlight->UpdateAlbums();
    string analysisCondition = "cover_uri = 'file://testNewCoverUri'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 0);
    string coverCondition = "cover_key = 'testAlbumName_1_1_file://testNewCoverUri'";
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, coverCondition);
    EXPECT_EQ(coverCount, 0);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_albums_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_albums_test_004 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE, HIGHLIGHT_COVER_INFO_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.oldCoverUri = make_optional<string>("file://testOldCoverUri");
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.coverUri = "file://testNewCoverUri";
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_NEW_ID);
    testAnalysisInfo.albumName = make_optional<string>("testAlbumName");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightCoverInfo testCoverInfo;
    testCoverInfo.ratio = make_optional<string>("1_1");
    testCoverInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    cloneRestoreHighlight->coverInfos_.emplace_back(testCoverInfo);

    cloneRestoreHighlight->UpdateAlbums();
    string analysisCondition = "cover_uri = 'file://testNewCoverUri'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 1);
    string coverCondition = "cover_key = 'testAlbumName_1_1_file://testNewCoverUri'";
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, coverCondition);
    EXPECT_EQ(coverCount, 0);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_update_albums_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_update_albums_test_005 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE, HIGHLIGHT_COVER_INFO_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.oldCoverUri = make_optional<string>("file://testOldCoverUri");
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.coverUri = "file://testNewCoverUri";
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightCoverInfo testCoverInfo;
    testCoverInfo.ratio = make_optional<string>("1_1");
    testCoverInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    cloneRestoreHighlight->coverInfos_.emplace_back(testCoverInfo);

    cloneRestoreHighlight->UpdateAlbums();
    string analysisCondition = "cover_uri = 'file://testNewCoverUri'";
    int32_t analysisCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), ANALYSIS_ALBUM_TABLE, analysisCondition);
    EXPECT_EQ(analysisCount, 1);
    string coverCondition = "cover_key = 'testAlbumName_1_1_file://testNewCoverUri'";
    int32_t coverCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_COVER_INFO_TABLE, coverCondition);
    EXPECT_EQ(coverCount, 0);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_get_new_highlight_album_id_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_get_new_highlight_album_id_test_001 start");
    ClearHighlightData();
    int32_t oldId = 1;
    CloneRestoreHighlight::HighlightAlbumInfo testInfo;
    testInfo.highlightIdOld = make_optional<int32_t>(oldId);
    testInfo.highlightIdNew = make_optional<int32_t>(TEST_NEW_ID);
    cloneRestoreHighlight->highlightInfos_.emplace_back(testInfo);
    int32_t newId = cloneRestoreHighlight->GetNewHighlightAlbumId(oldId);
    EXPECT_EQ(newId, testInfo.highlightIdNew.value());
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_get_new_highlight_photo_id_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_get_new_highlight_photo_id_test_001 start");
    ClearHighlightData();
    cloneRestoreHighlight->photoIdMap_.Insert(1, 2);
    int32_t newId = cloneRestoreHighlight->GetNewHighlightPhotoId(1);
    EXPECT_EQ(newId, 2);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_get_new_highlight_photo_uri_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_get_new_highlight_photo_uri_test_001 start");
    ClearHighlightData();
    cloneRestoreHighlight->photoUriMap_.Insert(1, "photouri");
    string newUri = cloneRestoreHighlight->GetNewHighlightPhotoUri(1);
    EXPECT_EQ(newUri, "photouri");
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_is_clone_highlight_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_is_clone_highlight_test_001 start");
    ClearHighlightData();
    cloneRestoreHighlight->isCloneHighlight_ = false;
    bool isClone = cloneRestoreHighlight->IsCloneHighlight();
    EXPECT_EQ(isClone, false);
}

HWTEST_F(CloneRestoreHighlightTest, clone_restore_highlight_deduplicate_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("clone_restore_highlight_deduplicate_test_001 start");
    ClearHighlightData();
    CloneHighlightSource cloneHighlightSource;
    vector<string> tableList = { ANALYSIS_ALBUM_TABLE, HIGHLIGHT_ALBUM_TABLE };
    cloneHighlightSource.Insert(tableList, newRdbStore->GetRaw());
    cloneRestoreHighlight->Init(2, "", newRdbStore->GetRaw(), cloneHighlightSource.cloneStorePtr_, "");
    CloneRestoreHighlight::AnalysisAlbumInfo testAnalysisInfo;
    testAnalysisInfo.albumIdOld = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.highlightIdNew = make_optional<int32_t>(TEST_ID);
    testAnalysisInfo.albumName = make_optional<string>("test_highlight_album");
    cloneRestoreHighlight->analysisInfos_.emplace_back(testAnalysisInfo);

    CloneRestoreHighlight::HighlightAlbumInfo testHighlightInfo;
    testHighlightInfo.albumIdOld = make_optional<int32_t>(TEST_ID);
    testHighlightInfo.highlightVersion = make_optional<int32_t>(2);
    testHighlightInfo.highlightStatus = make_optional<int32_t>(1);
    testHighlightInfo.clusterType = make_optional<string>("TYPE_DBSCAN");
    testHighlightInfo.clusterSubType = make_optional<string>("Old_AOI_0");
    testHighlightInfo.clusterCondition = make_optional<string>("[]");
    cloneRestoreHighlight->highlightInfos_.emplace_back(testHighlightInfo);

    cloneRestoreHighlight->HighlightDeduplicate(testHighlightInfo);
    string highlightCondition = "highlight_status = -4";
    int32_t highlightCount = GetAlbumCountByCondition(newRdbStore->GetRaw(), HIGHLIGHT_ALBUM_TABLE, highlightCondition);
    EXPECT_EQ(highlightCount, 1);
    ClearCloneSource(cloneHighlightSource, TEST_BACKUP_DB_PATH);
}
} // namespace Media
} // namespace OHOS