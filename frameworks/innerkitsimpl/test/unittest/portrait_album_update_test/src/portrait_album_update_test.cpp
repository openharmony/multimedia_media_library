/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "PortraitAlbumUpdateTest"

#include "portrait_album_update_test.h"

#include <chrono>
#include <utility>

#include "fetch_result.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_errno.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "rdb_predicates.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"
#include "vision_db_sqls.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace testing::ext;
using namespace OHOS::DataShare;
using OHOS::DataShare::DataSharePredicates;
using OHOS::DataShare::DataShareValuesBucket;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::atomic<int> number(0);

struct PortraitData {
    int64_t fileId;
    string title;
    string path;
};

int GetNumber()
{
    return ++number;
}

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

void ClearTables()
{
    string clearPhoto = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE;
    string clearAnalysisAlbum = "DELETE FROM " + ANALYSIS_ALBUM_TABLE;
    string clearAnalysisPhotoMap = "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE;
    string clearImageFace = "DELETE FROM " + VISION_IMAGE_FACE_TABLE;
    vector<string> executeSqlStrs = {clearPhoto, clearAnalysisAlbum, clearAnalysisPhotoMap, clearImageFace};
    MEDIA_INFO_LOG("start clear data");
    ExecSqls(executeSqlStrs);
    number = 0;
}

string GetTitle(int64_t &timestamp)
{
    return "IMG_" + to_string(timestamp) + "_" + to_string(GetNumber());
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count() + GetNumber();
}

string GetCoverUri(PortraitData data)
{
    string extrUri = MediaFileUtils::GetExtraUri(data.title + ".jpg", data.path, true);
    return MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(data.fileId), extrUri);
}

int64_t CreatePortraitAlbum()
{
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int64_t albumId = -1;
    string tag = "ser_1711000000000000000";
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(ALBUM_TYPE, PhotoAlbumType::SMART);
    valuesBucket.PutInt(ALBUM_SUBTYPE, PhotoAlbumSubType::PORTRAIT);
    valuesBucket.PutString(TAG_ID, tag);
    valuesBucket.PutString(GROUP_TAG, tag);
    EXPECT_NE(g_rdbStore, nullptr);
    int32_t ret = g_rdbStore->GetRaw()->Insert(albumId, ANALYSIS_ALBUM_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
    MEDIA_INFO_LOG("InsertAlbum albumId is %{public}s", to_string(albumId).c_str());
    return albumId;
}

PortraitData InsertPortraitToPhotos()
{
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int64_t fileId = -1;
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    string data = "/storage/cloud/files/photo/1/" + title + ".jpg";
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestamp);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestamp);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->GetRaw()->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
    MEDIA_INFO_LOG("InsertPhoto fileId is %{public}s", to_string(fileId).c_str());
    PortraitData portraitData;
    portraitData.fileId = fileId;
    portraitData.title = title;
    portraitData.path = data;
    return portraitData;
}

void InsertPortraitToImageFace(int64_t fileId, int totalFaces)
{
    ASSERT_NE(g_rdbStore, nullptr);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int64_t rowId = -1;
    for (size_t faceId = 0; faceId <= totalFaces; faceId++) {
        ValuesBucket valuesBucket;
        valuesBucket.PutInt(MediaColumn::MEDIA_ID, fileId);
        valuesBucket.PutInt(FACE_ID, faceId);
        valuesBucket.PutInt(TOTAL_FACES, totalFaces);
        EXPECT_NE((g_rdbStore == nullptr), true);
        int32_t ret = g_rdbStore->GetRaw()->Insert(rowId, VISION_IMAGE_FACE_TABLE, valuesBucket);
        EXPECT_EQ(ret, E_OK);
    }
    transactionOprn.Finish();
}

void InsertPortraitsToAlbum(const vector<PortraitData> &portraitData, int64_t albumId,
    int64_t coverIndex, int isCoverSatisfied)
{
    ASSERT_NE(g_rdbStore, nullptr);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int64_t rowId = -1;
    for (PortraitData data : portraitData) {
        ValuesBucket valuesBucket;
        valuesBucket.PutInt(MAP_ALBUM, albumId);
        valuesBucket.PutInt(MAP_ASSET, data.fileId);
        EXPECT_NE((g_rdbStore == nullptr), true);
        int32_t ret = g_rdbStore->GetRaw()->Insert(rowId, ANALYSIS_PHOTO_MAP_TABLE, valuesBucket);
        EXPECT_EQ(ret, E_OK);
    }

    int32_t changedRows = -1;
    string coverUri = GetCoverUri(portraitData[coverIndex]);
    MediaLibraryCommand cmd(OperationObject::ANALYSIS_PHOTO_ALBUM, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutString(COVER_URI, coverUri);
    updateValues.PutInt(IS_COVER_SATISFIED, isCoverSatisfied);
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(ALBUM_ID, to_string(albumId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void TrashPortrait(int64_t fileId, int64_t value = 1)
{
    ASSERT_NE(g_rdbStore, nullptr);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutLong(MediaColumn::MEDIA_DATE_TRASHED, value);
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void HidePortrait(int64_t fileId, int64_t value = 1)
{
    ASSERT_NE(g_rdbStore, nullptr);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutInt(MediaColumn::MEDIA_HIDDEN, value);
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void DismissPortrait(int64_t albumId, int64_t fileId)
{
    ASSERT_NE(g_rdbStore, nullptr);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t deletedRows = -1;
    MediaLibraryCommand cmd(OperationObject::ANALYSIS_PHOTO_MAP, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->EqualTo(MAP_ALBUM, to_string(albumId));
    cmd.GetAbsRdbPredicates()->EqualTo(MAP_ASSET, to_string(fileId));
    int32_t ret = g_rdbStore->Delete(cmd, deletedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void PortraitAlbumUpdateTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("PortraitAlbumUpdateTest SetUpTestCase start");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    ASSERT_NE(g_rdbStore, nullptr);
    MEDIA_INFO_LOG("PortraitAlbumUpdateTest SetUpTestCase end");
}

void PortraitAlbumUpdateTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("PortraitAlbumUpdateTest TearDownTestCase");
    ClearTables();
}

void PortraitAlbumUpdateTest::SetUp()
{
    MEDIA_INFO_LOG("PortraitAlbumUpdateTest SetUp");
    ClearTables();
}

void PortraitAlbumUpdateTest::TearDown()
{
    MEDIA_INFO_LOG("PortraitAlbumUpdateTest TearDown");
}

shared_ptr<NativeRdb::ResultSet> QueryPortraitAlbumInfo(int32_t albumId)
{
    EXPECT_GT(albumId, 0);
    vector<string> columns = {COUNT, COVER_URI, IS_COVER_SATISFIED};
    MediaLibraryCommand cmd(OperationObject::ANALYSIS_PHOTO_ALBUM, OperationType::QUERY, MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(ALBUM_ID, to_string(albumId));
    shared_ptr<NativeRdb::ResultSet> resultSet = g_rdbStore->Query(cmd, columns);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    return resultSet;
}

vector<PortraitData> PreparePortraitData()
{
    const int portraitCount = 4;
    const vector<int> faceCount = {1, 1, 2, 3};
    vector<PortraitData> portraits;
    for (size_t index = 0; index < portraitCount; index++) {
    PortraitData portrait = InsertPortraitToPhotos();
    portraits.push_back(portrait);
    sleep(1);
    InsertPortraitToImageFace(portrait.fileId, faceCount[index]);
}
return portraits;
}

int32_t GetCount(const shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    int32_t count = GetInt32Val(COUNT, resultSet);
    EXPECT_GE(count, 0);
    if (count < 0) {
    MEDIA_ERR_LOG("Failed to get count");
    return count;
    }
    return count;
}

string GetPhotoId(const string &uri)
{
    if (uri.compare(0, PhotoColumn::PHOTO_URI_PREFIX.size(), PhotoColumn::PHOTO_URI_PREFIX) != 0) {
        return "";
    }
    string tmp = uri.substr(PhotoColumn::PHOTO_URI_PREFIX.size());
    return tmp.substr(0, tmp.find_first_of('/'));
}

string GetCoverId(const shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    string coverUri = GetStringVal(COVER_URI, resultSet);
    return GetPhotoId(coverUri);
}

bool GetIsCoverSatisfied(const shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    int32_t isCoverSatisfied = GetInt32Val(IS_COVER_SATISFIED, resultSet);
    EXPECT_GE(isCoverSatisfied, 0);
    return isCoverSatisfied == 1;
}

void CheckAlbum(int64_t albumId, int count, int64_t coverId, bool isCoverSatisfied)
{
    shared_ptr<NativeRdb::ResultSet> resultSet = QueryPortraitAlbumInfo(albumId);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(GetCoverId(resultSet), to_string(coverId));
    EXPECT_EQ(GetCount(resultSet), count);
    EXPECT_EQ(GetIsCoverSatisfied(resultSet), isCoverSatisfied);
}

HWTEST_F(PortraitAlbumUpdateTest, portrait_album_update_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("portrait_album_update_test_001 Start");
    std::unordered_map<int32_t, int32_t> updateResult;
    vector<PortraitData> portraits = PreparePortraitData();
    int64_t albumId = CreatePortraitAlbum();
    EXPECT_GT(albumId, 0);
    vector<string> albumIds = {to_string(albumId)};
    vector<string> fileIds;
    for (auto data : portraits) {
        fileIds.push_back(to_string(data.fileId));
    }

    InsertPortraitsToAlbum(portraits, albumId, 1, 1);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, fileIds);
    CheckAlbum(albumId, 4, portraits[1].fileId, true);

    TrashPortrait(portraits[0].fileId);
    TrashPortrait(portraits[1].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds,
        {fileIds[0], fileIds[1]});
    CheckAlbum(albumId, 2, portraits[3].fileId, false);

    TrashPortrait(portraits[3].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[3]});
    CheckAlbum(albumId, 1, portraits[2].fileId, false);

    MEDIA_INFO_LOG("portrait_album_update_test_001 End");
}

HWTEST_F(PortraitAlbumUpdateTest, portrait_album_update_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("portrait_album_update_test_002 Start");
    std::unordered_map<int32_t, int32_t> updateResult;
    vector<PortraitData> portraits = PreparePortraitData();
    int64_t albumId = CreatePortraitAlbum();
    EXPECT_GT(albumId, 0);
    vector<string> albumIds = {to_string(albumId)};
    vector<string> fileIds;
    for (auto data : portraits) {
        fileIds.push_back(to_string(data.fileId));
    }

    InsertPortraitsToAlbum(portraits, albumId, 1, 1);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, fileIds);
    CheckAlbum(albumId, 4, portraits[1].fileId, true);

    HidePortrait(portraits[1].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[1]});
    CheckAlbum(albumId, 3, portraits[0].fileId, true);

    HidePortrait(portraits[0].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[0]});
    CheckAlbum(albumId, 2, portraits[3].fileId, false);

    HidePortrait(portraits[2].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[2]});
    CheckAlbum(albumId, 1, portraits[3].fileId, false);

    MEDIA_INFO_LOG("portrait_album_update_test_002 End");
}

HWTEST_F(PortraitAlbumUpdateTest, portrait_album_update_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("portrait_album_update_test_003 Start");
    std::unordered_map<int32_t, int32_t> updateResult;
    vector<PortraitData> portraits = PreparePortraitData();
    int64_t albumId = CreatePortraitAlbum();
    EXPECT_GT(albumId, 0);
    vector<string> albumIds = {to_string(albumId)};
    vector<string> fileIds;
    for (auto data : portraits) {
        fileIds.push_back(to_string(data.fileId));
    }

    InsertPortraitsToAlbum(portraits, albumId, 1, 1);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, fileIds);
    CheckAlbum(albumId, 4, portraits[1].fileId, true);

    DismissPortrait(albumId, portraits[1].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[1]});
    CheckAlbum(albumId, 3, portraits[0].fileId, true);

    DismissPortrait(albumId, portraits[0].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[0]});
    CheckAlbum(albumId, 2, portraits[3].fileId, false);

    DismissPortrait(albumId, portraits[3].fileId);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(g_rdbStore->GetRaw(), updateResult, albumIds, {fileIds[3]});
    CheckAlbum(albumId, 1, portraits[2].fileId, false);

    MEDIA_INFO_LOG("portrait_album_update_test_003 End");
}

} // namespace Media
} // namespace OHOS