/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "SourceAlbumTest"

#include "medialibrary_album_source_test.h"

#include <chrono>

#include "medialibrary_asset_operations.h"
#include "medialibrary_photo_operations.h"
#include "abs_rdb_predicates.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_file_ext_ability.h"
#include "media_file_extention_utils.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "source_album.h"
#include "uri.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::atomic<int> number(0);

struct InsertResult {
    int64_t fileId;
    string title;
    string displayName;
};

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

void InitSourceAlbumTrigger()
{
    static const vector<string> executeSqlStrs = {
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DELETE_PHOTO_UPDATE_SOURCE_ALBUM
    };
    MEDIA_INFO_LOG("start add source album trigger");
    ExecSqls(executeSqlStrs);
}

void ClearData()
{
    string clearPhotoSql = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE;
    string clearSourceAlbumSql = "DELETE FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SYSTEM) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::SOURCE);
    string initSystemAlbumSql = "UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COVER_URI + " = '', " +
        PhotoAlbumColumns::ALBUM_COUNT + " = 0" +
        " WHERE " + PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SYSTEM);
    vector<string> executeSqlStrs = {
        clearPhotoSql,
        clearSourceAlbumSql,
        initSystemAlbumSql,
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_DELETE_PHOTO_UPDATE_SOURCE_ALBUM
    };
    MEDIA_INFO_LOG("start clear data");
    ExecSqls(executeSqlStrs);
}

int GetNumber()
{
    return ++number;
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count() + GetNumber();
}

string GetCoverUri(InsertResult result)
{
    return PhotoColumn::PHOTO_URI_PREFIX + to_string(result.fileId) + "/" +
        result.title + "/" + result.displayName;
}

inline void CheckColumn(shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet, const string &column,
    ResultSetDataType type, const variant<int32_t, string, int64_t, double> &expected)
{
    EXPECT_EQ(ResultSetUtils::GetValFromColumn(column, resultSet, type), expected);
}

string GetTitle(int64_t &timestamp)
{
    return "IMG_" + to_string(timestamp) + "_" + to_string(GetNumber());
}

string GetDisPlayName(string &title)
{
    return title + ".png";
}

InsertResult InsertPhoto(string &packageName)
{
    MEDIA_INFO_LOG("InsertPhoto packageName is: %{public}s", packageName.c_str());
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int64_t fileId = -1;
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = GetDisPlayName(title);
    MEDIA_INFO_LOG("title is: %{public}s, displayName is: %{public}s",
        title.c_str(), displayName.c_str());
    string data = "/storage/cloud/files/photo/1/" +GetDisPlayName(title);
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    if (packageName != "") {
        valuesBucket.PutString(MediaColumn::MEDIA_PACKAGE_NAME, packageName);
    }
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
    InsertResult result;
    result.fileId = fileId;
    result.title = title;
    result.displayName = displayName;
    return result;
}

void UpdatePhotoTrashed(int64_t &fileId, bool isDelete)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    if (isDelete) {
        updateValues.PutLong(MediaColumn::MEDIA_DATE_TRASHED, GetTimestamp());
    } else {
        updateValues.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    }
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void HidePhoto(int64_t fileId, int value)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
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

void UpdateDisPlayname(int64_t &fileId, string &disPlayname)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutString(MediaColumn::MEDIA_NAME, disPlayname);
    updateValues.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, GetTimestamp());
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    EXPECT_EQ(ret, E_OK);
    transactionOprn.Finish();
}

void ValidPhotoAlbumValue(string packageName, int exceptResultCount, int exceptPhotoCount,
    string exceptCoverUri)
{
    vector<string> columns = { PhotoAlbumColumns::ALBUM_COUNT, PhotoAlbumColumns::ALBUM_COVER_URI};
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_NAME, packageName);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::SOURCE));
    EXPECT_NE((g_rdbStore == nullptr), true);
    auto resultSet = g_rdbStore->Query(cmd, columns);
    EXPECT_NE((resultSet == nullptr), true);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, exceptResultCount);
    int photoCount = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
    string coverURI = GetStringVal(PhotoAlbumColumns::ALBUM_COVER_URI, resultSet);
    MEDIA_INFO_LOG("validPhotoAlbumValue photoCount is: %{public}d, coverURI is %{public}s",
        photoCount, coverURI.c_str());
    EXPECT_EQ(photoCount, exceptPhotoCount);
    EXPECT_EQ(coverURI, exceptCoverUri);
}

void ValidNullPackageNameSourceAlbum()
{
    vector<string> columns = {};
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ALBUM, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->IsNull(PhotoAlbumColumns::ALBUM_NAME);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::SOURCE));
    ASSERT_NE(g_rdbStore, nullptr);
    auto resultSet = g_rdbStore->Query(cmd, columns);
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    MEDIA_INFO_LOG("ValidNullPackageNameSourceAlbum count is: %{public}d", count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);
}

void DeletePhoto(int64_t &fileId)
{
    MEDIA_INFO_LOG("DeletePhoto fileId is %{public}s", to_string(fileId).c_str());
    EXPECT_NE((g_rdbStore == nullptr), true);
    TransactionOperations transactionOprn(g_rdbStore->GetRaw());
    transactionOprn.Start();
    int32_t deletedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    g_rdbStore->Delete(cmd, deletedRows);
    transactionOprn.Finish();
    MEDIA_INFO_LOG("DeletePhoto deletedRows is %{public}d", deletedRows);
}

void MediaLibraryAlbumSourceTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaLibraryAlbumSourceTest SetUpTestCase start");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    ClearData();
    InitSourceAlbumTrigger();
    EXPECT_NE((g_rdbStore == nullptr), true);
    number = 0;
    MEDIA_INFO_LOG("MediaLibraryAlbumSourceTest SetUpTestCase end");
}

void MediaLibraryAlbumSourceTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaLibraryAlbumSourceTest TearDownTestCase");
    ClearData();
}

void MediaLibraryAlbumSourceTest::SetUp()
{
    MEDIA_INFO_LOG("MediaLibraryAlbumSourceTest SetUp");
}

void MediaLibraryAlbumSourceTest::TearDown()
{
    MEDIA_INFO_LOG("MediaLibraryAlbumSourceTest TearDown");
}

HWTEST_F(MediaLibraryAlbumSourceTest, insert_photo_insert_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_insert_source_album_test_001");
    string packageName = "app_001";
    InsertResult result = InsertPhoto(packageName);
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result));
    MEDIA_INFO_LOG("end tdd insert_photo_insert_source_album_test_001");
}

HWTEST_F(MediaLibraryAlbumSourceTest, insert_photo_insert_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_insert_source_album_test_002");
    string packageName = "";
    InsertPhoto(packageName);
    ValidNullPackageNameSourceAlbum();
    MEDIA_INFO_LOG("end tdd insert_photo_insert_source_album_test_002");
}

HWTEST_F(MediaLibraryAlbumSourceTest, insert_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_update_source_album_test_001");
    string packageName = "app_002";
    // insert photo
    InsertPhoto(packageName);
    // insert photo
    InsertResult result = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result));
    MEDIA_INFO_LOG("end tdd insert_photo_update_source_album_test_001");
}

HWTEST_F(MediaLibraryAlbumSourceTest, update_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_001");
    string packageName = "app_003";
    // insert photo
    InsertResult result = InsertPhoto(packageName);
    // insert photo
    InsertPhoto(packageName);
    // update photo name
    string modifyDisPlayName = "testModify001.png";
    UpdateDisPlayname(result.fileId, modifyDisPlayName);
    // verify
    result.displayName = modifyDisPlayName;
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_001");
}

HWTEST_F(MediaLibraryAlbumSourceTest, update_photo_update_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_002");
    string packageName = "app_004";
    // insert photo
    InsertResult result1 = InsertPhoto(packageName);
    // insert photo
    InsertResult result2 = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result2));
    // logic delete photo
    UpdatePhotoTrashed(result2.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result1));
    // logic delete photo
    UpdatePhotoTrashed(result1.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_002");
}

HWTEST_F(MediaLibraryAlbumSourceTest, update_photo_update_source_album_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_003");
    string packageName = "app_005";
    // insert photo
    InsertResult result1 = InsertPhoto(packageName);
    // insert photo
    InsertResult result2 = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result2));
    // hide photo
    HidePhoto(result2.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result1));
    // hide photo
    HidePhoto(result1.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_003");
}

HWTEST_F(MediaLibraryAlbumSourceTest, update_photo_update_source_album_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_004");
    string packageName = "app_006";
    // insert photo
    InsertResult result = InsertPhoto(packageName);
    // hide photo
    HidePhoto(result.fileId, 1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    // cancel hide photo
    HidePhoto(result.fileId, 0);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_004");
}

HWTEST_F(MediaLibraryAlbumSourceTest, update_photo_update_source_album_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_005");
    string packageName = "app_007";
    // insert photo
    InsertResult result = InsertPhoto(packageName);
    // logic delete photo
    UpdatePhotoTrashed(result.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    // cancel logic delete photo
    UpdatePhotoTrashed(result.fileId, false);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_005");
}

HWTEST_F(MediaLibraryAlbumSourceTest, delete_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_001");
    string packageName = "app_008";
    // insert photo
    InsertResult result1 = InsertPhoto(packageName);
    // insert photo
    InsertResult result2 = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result2));
    // delete photo
    DeletePhoto(result2.fileId);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result1));
    // delete photo
    DeletePhoto(result1.fileId);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_001");
}

HWTEST_F(MediaLibraryAlbumSourceTest, delete_photo_update_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_002");
    string packageName = "app_009";
    // insert photo
    InsertResult result1 = InsertPhoto(packageName);
    // insert photo
    InsertResult result2 = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result2));
    // hide photo
    HidePhoto(result2.fileId, 1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result1));
    // delete photo
    DeletePhoto(result1.fileId);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_002");
}

HWTEST_F(MediaLibraryAlbumSourceTest, delete_photo_update_source_album_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_003");
    string packageName = "app_010";
    // insert photo
    InsertResult result1 = InsertPhoto(packageName);
    // insert photo
    InsertResult result2 = InsertPhoto(packageName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(result2));
    // logic delete photo
    UpdatePhotoTrashed(result2.fileId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(result1));
    // delete photo
    DeletePhoto(result1.fileId);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_003");
}
} // namespace Media
} // namespace OHOS