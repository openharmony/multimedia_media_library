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

#define MLOG_TAG "MediaAlbumsControllerServiceTest"

#include "delete_highlight_albums_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_albums_controller_service.h"
#undef private
#undef protected

#include "message_parcel.h"
#include "user_define_ipc_client.h"
#include "delete_highlight_albums_vo.h"
#include "vision_column.h"
#include "vision_column_comm.h"
#include "story_db_sqls.h"
#include "medialibrary_rdbstore.h"
#include "vision_db_sqls_more.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace IPC;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static const string INSERT_HIGHLIGHT_ALBUM_TABLE = "INSERT INTO " + HIGHLIGHT_ALBUM_TABLE + "(id, " + ALBUM_ID + ", " +
    AI_ALBUM_ID + ", " + SUB_TITLE + ", " + CLUSTER_TYPE + ", " + CLUSTER_SUB_TYPE + ", " + CLUSTER_CONDITION + ", " +
    MIN_DATE_ADDED + ", " + MAX_DATE_ADDED + ", " + GENERATE_TIME + ", " + HIGHLIGHT_VERSION + ", " +
    HIGHLIGHT_STATUS + ", " + HIGHLIGHT_INSERT_PIC_COUNT + ", " + HIGHLIGHT_REMOVE_PIC_COUNT + ", " +
    HIGHLIGHT_SHARE_SCREENSHOT_COUNT + ", " + HIGHLIGHT_SHARE_COVER_COUNT + ", " + HIGHLIGHT_RENAME_COUNT + ", " +
    HIGHLIGHT_CHANGE_COVER_COUNT + ", " + HIGHLIGHT_RENDER_VIEWED_TIMES + ", " +
    HIGHLIGHT_RENDER_VIEWED_DURATION + ", " + HIGHLIGHT_ART_LAYOUT_VIEWED_TIMES + ", " +
    HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION + ", " + HIGHLIGHT_MUSIC_EDIT_COUNT + ", " +
    HIGHLIGHT_FILTER_EDIT_COUNT + ") ";
static const string VALUES_END = ") ";
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

void ClearAlbumTables()
{
    string clearPhotoAlbumSql = "DELETE FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_TYPE + " != " + to_string(PhotoAlbumType::SYSTEM);
    string clearAnalysisAlbumSql = "DELETE FROM " + ANALYSIS_ALBUM_TABLE;
    string clearHighlightAlbumSql = "DELETE FROM " + HIGHLIGHT_ALBUM_TABLE;
    vector<string> executeSqlStrs = {
        clearPhotoAlbumSql,
        clearAnalysisAlbumSql,
        clearHighlightAlbumSql,
    };
    MEDIA_INFO_LOG("start clear data in all tables");
    ExecSqls(executeSqlStrs);
}

void InsertHighlightAlbums()
{
    // highlight_status = 0
    g_rdbStore->ExecuteSql(INSERT_HIGHLIGHT_ALBUM_TABLE + " VALUES ( 1, 1, 2, '2024.05.22', 'TYPE_DBSCAN', "
        "'Old_AOI_0', '[]', 1716307200000, 1716392070000, 1738992083745, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0" +
        VALUES_END);
}

void SetAllTestTables()
{
    vector<string> createTableSqlList = {
        CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
        CREATE_HIGHLIGHT_ALBUM_TABLE,
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

void DeleteHighlightAlbumsTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    SetAllTestTables();
    ClearAlbumTables();
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DeleteHighlightAlbumsTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearAlbumTables();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void DeleteHighlightAlbumsTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearAlbumTables();
}

void DeleteHighlightAlbumsTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

bool QueryHighlightAlbumInfo()
{
    NativeRdb::RdbPredicates rdbPredicate(INSERT_HIGHLIGHT_ALBUM_TABLE);
    string id = "id";
    string idValue = "1";
    rdbPredicate.EqualTo(id, idValue);
    vector<string> columns;
    shared_ptr<NativeRdb::ResultSet> resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() != 0) {
        return true;
    }
    return false;
}

HWTEST_F(DeleteHighlightAlbumsTest, DeleteHighlightAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start DeleteHighlightAlbums_Test_001");
    InsertHighlightAlbums();
    bool ret = QueryHighlightAlbumInfo();
    ASSERT_EQ(ret, true);
    MessageParcel data;
    MessageParcel reply;
    DeleteHighLightAlbumsReqBody reqBody;
    vector<string> albumIds = { "1" };
    vector<int32_t> photoAlbumTypes = { static_cast<int32_t>(PhotoAlbumType::SMART) };
    vector<int32_t> photoAlbumSubtypes = { static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT) };
    reqBody.albumIds = albumIds;
    reqBody.photoAlbumTypes = photoAlbumTypes;
    reqBody.photoAlbumSubtypes = photoAlbumSubtypes;
    bool errConn = !reqBody.Marshalling(data);
    ASSERT_EQ(errConn, false);
    auto service = make_shared<MediaAlbumsControllerService>();
    service->DeleteHighlightAlbums(data, reply);
    MediaEmptyObjVo respVo;
    MediaRespVo<MediaEmptyObjVo> resp;
    bool isValid = resp.Unmarshalling(reply);
    ASSERT_EQ(isValid, true);
    int32_t err = resp.GetErrCode();
    ASSERT_EQ(err, 1);
    MEDIA_INFO_LOG("End DeleteHighlightAlbums_Test_001");
}

HWTEST_F(DeleteHighlightAlbumsTest, DeleteHighlightAlbums_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start DeleteHighlightAlbums_Test_002");
    InsertHighlightAlbums();
    bool ret = QueryHighlightAlbumInfo();
    ASSERT_EQ(ret, true);
    MessageParcel data;
    MessageParcel reply;
    MediaReqVo<DeleteHighLightAlbumsReqBody> reqVo;
    DeleteHighLightAlbumsReqBody reqBody;
    reqBody.albumIds = { "1" };
    reqBody.photoAlbumTypes = { static_cast<int32_t>(PhotoAlbumType::SMART) };
    reqVo.SetBody(reqBody);
    bool errConn = !reqVo.Marshalling(data);
    ASSERT_EQ(errConn, false);
    auto service = make_shared<MediaAlbumsControllerService>();
    service->DeleteHighlightAlbums(data, reply);
    MediaEmptyObjVo respVo;
    MediaRespVo<MediaEmptyObjVo> resp;
    bool isValid = resp.Unmarshalling(reply);
    ASSERT_EQ(isValid, true);
    int32_t err = resp.GetErrCode();
    ASSERT_LT(err, 0);
    MEDIA_INFO_LOG("End DeleteHighlightAlbums_Test_002");
}
}  // namespace OHOS::Media