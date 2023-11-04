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

#include "medialibrary_source_album_test.h"

#include <chrono>
#include <mutex>

#include "medialibrary_asset_operations.h"
#include "medialibrary_photo_operations.h"
#include "abs_rdb_predicates.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "media_column.h"
#include "photo_album_column.h"
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
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_file_ext_ability.h"
#include "media_file_extention_utils.h"
#include "result_set_utils.h"
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
const long ERROR_PEDING = -2;
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::atomic<int> fileNumber(0);

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
    vector<string> sqlList = {
        clearPhotoSql,
        clearSourceAlbumSql,
        initSystemAlbumSql
    };
    for (auto &sql : sqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(sql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", sql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", sql.c_str());
    }
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count();
}

string GetQuerySourceAlbumSql(string &packageName)
{
    return "SELECT * FROM " + PhotoAlbumColumns::TABLE + "WHERE " +
        PhotoAlbumColumns::ALBUM_NAME + " = " + packageName + " AND " +
        PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(PhotoAlbumType::SYSTEM) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(PhotoAlbumSubType::SOURCE);
}

string GetCoverUri(int64_t &outRowId, string &title, string &disPlayName)
{
    return PhotoColumn::PHOTO_URI_PREFIX + to_string(outRowId) + "/" + title + "/" + disPlayName;
}

inline void CheckColumn(shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet, const string &column,
    ResultSetDataType type, const variant<int32_t, string, int64_t, double> &expected)
{
    EXPECT_EQ(ResultSetUtils::GetValFromColumn(column, resultSet, type), expected);
}

string GetTitle(int64_t &timestamp)
{
    return "IMG_" + to_string(timestamp) + "_" + to_string(++fileNumber);
}

string GetDisPlayName(string &title)
{
    return title + ".png";
}

void InsertPhoto(string &packageName, int64_t &outRowId, string &title,
    string &displayName, bool isNormnal)
{
    auto store = g_rdbStore->GetRaw();
    if (store == nullptr) {
        MEDIA_ERR_LOG("can not get store");
        return;
    }
    int64_t timestamp = GetTimestamp();
    title = GetTitle(timestamp);
    displayName = GetDisPlayName(title);
    MEDIA_INFO_LOG("insertPhoto packageName is: %{public}s, title is: %{public}s",
        packageName.c_str(), title.c_str());
    string data = "/storage/cloud/files/photo/1/" +GetDisPlayName(title);
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutString(MediaColumn::MEDIA_PACKAGE_NAME, packageName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestamp);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestamp);
    if (isNormnal) {
        valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    } else {
        valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, ERROR_PEDING);
    }
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    int32_t ret = store->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    MEDIA_INFO_LOG("outRowId is %{public}lld", outRowId);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to insert photo! err: %{public}d", ret);
}

void UpdatePhotoTrashed(int64_t fileId, bool isDelete)
{
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
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to update photo! err: %{public}d", ret);
}

void HidePhoto(int64_t fileId, int value)
{
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutInt(MediaColumn::MEDIA_HIDDEN, 1);
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to update photo! err: %{public}d", ret);
}

void UpdateDisPlayname(int64_t fileId, string disPlayname)
{
    int32_t changedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket updateValues;
    updateValues.PutString(MediaColumn::MEDIA_NAME, disPlayname);
    updateValues.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, GetTimestamp());
    cmd.SetValueBucket(updateValues);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Update(cmd, changedRows);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to update photo! err: %{public}d", ret);
}

void ValidPhotoAlbumCount(string packageName, int exceptResultCount)
{
    MEDIA_INFO_LOG("ValidPhotoAlbumCount exceptResultCount is: %{public}d",
        exceptResultCount);
    string querySql = GetQuerySourceAlbumSql(packageName);
    auto resultSet = g_rdbStore->QuerySql(querySql);
    CHECK_AND_RETURN_LOG(resultSet == nullptr, "get source album resultSet is null");
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to get count! err: %{public}d", ret);
    EXPECT_EQ(count, exceptResultCount);
}

void ValidPhotoAlbumValue(string packageName, int exceptResultCount, int exceptCount, string exceptCoverUri)
{
    MEDIA_INFO_LOG("validPhotoAlbumValue packageName is: %{public}s ", packageName.c_str());
    MEDIA_INFO_LOG("validPhotoAlbumValue exceptResultCount is: %{public}d ", exceptResultCount);
    MEDIA_INFO_LOG("validPhotoAlbumValue exceptResultCount is: %{public}d ", exceptResultCount);
    MEDIA_INFO_LOG("validPhotoAlbumValue exceptCoverUri is: %{public}s ", exceptCoverUri.c_str());
    string querySql = GetQuerySourceAlbumSql(packageName);
    auto resultSet = g_rdbStore->QuerySql(querySql);
    CHECK_AND_RETURN_LOG(resultSet == nullptr, "get source album resultSet is null");
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to get count! err: %{public}d", ret);
    EXPECT_EQ(count, exceptResultCount);
    ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to GoToFirstRow! err: %{public}d", ret);
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_COUNT, TYPE_INT32, exceptCount);
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_COVER_URI, TYPE_STRING, exceptCoverUri);
}

void DeletePhoto(int64_t &fileId)
{
    int32_t deletedRows = -1;
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t ret = g_rdbStore->Delete(cmd, deletedRows);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to delete photo! err: %{public}d", ret);
}

void MediaLibrarySourceAlbumTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaLibrarySourceAlbumTest SetUpTestCase start");
    ClearData();
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    fileNumber = 0;
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibrarySourceAlbumTest failed, can not get rdbstore");
        exit(1);
    }
    MEDIA_INFO_LOG("MediaLibrarySourceAlbumTest SetUpTestCase end");
}

void MediaLibrarySourceAlbumTest::TearDownTestCase()
{}

void MediaLibrarySourceAlbumTest::SetUp()
{}

void MediaLibrarySourceAlbumTest::TearDown()
{
    MEDIA_INFO_LOG("MediaLibrarySourceAlbumTest TearDown");
    ClearData();
}

/**
 * @tc.name: insert_photo_insert_source_album_test_001
 * @tc.desc: insert a normal photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, insert_photo_insert_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_insert_source_album_test_001");
    string packageName = "app_001";
    int64_t outRowId;
    string title;
    string displayName;
    InsertPhoto(packageName, outRowId, title, displayName, true);
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId, title, displayName));
    MEDIA_INFO_LOG("end tdd insert_photo_insert_source_album_test_001");
}

/**
 * @tc.name: insert_photo_insert_source_album_test_002
 * @tc.desc: insert a pending photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, insert_photo_insert_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_insert_source_album_test_002");
    string packageName = "app_002";
    // insert photo
    int64_t outRowId;
    string title;
    string displayName;
    InsertPhoto(packageName, outRowId, title, displayName, false);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd insert_photo_insert_source_album_test_002");
}

/**
 * @tc.name: insert_photo_update_source_album_test_001
 * @tc.desc: insert two normal photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, insert_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_update_source_album_test_001");
    string packageName = "app_003";
    // insert photo
    int64_t outRowId1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    MEDIA_INFO_LOG("end tdd insert_photo_update_source_album_test_001");
}

/**
 * @tc.name: insert_photo_update_source_album_test_002
 * @tc.desc: insert a normal photo, insert a pending photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, insert_photo_update_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd insert_photo_update_source_album_test_002");
    string packageName = "app_004";
    // insert photo
    int64_t outRowId1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert pending photo
    int64_t outRowId2;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, false);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    MEDIA_INFO_LOG("end tdd insert_photo_update_source_album_test_002");
}

/**
 * @tc.name: update_photo_update_source_album_test_001
 * @tc.desc: insert two normal photo, update a photo diaplayName
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, update_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_001");
    string packageName = "app_005";
    // insert photo
    int64_t outRowId1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // update photo name
    string modifyDisPlayName = "testModify001.png";
    UpdateDisPlayname(outRowId1, modifyDisPlayName);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId1, title1, modifyDisPlayName));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_001");
}

/**
 * @tc.name: update_photo_update_source_album_test_002
 * @tc.desc: insert two normal photo, logic delete two photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, update_photo_update_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_002");
    string packageName = "app_006";
    // insert photo
    int64_t outRowId1 = -1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2 = -1;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    // logic delete photo
    UpdatePhotoTrashed(outRowId2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    // logic delete photo
    UpdatePhotoTrashed(outRowId1, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_002");
}

/**
 * @tc.name: update_photo_update_source_album_test_003
 * @tc.desc: insert two normal photo, hide two photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, update_photo_update_source_album_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_003");
    string packageName = "app_007";
    // insert photo
    int64_t outRowId1 = -1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2 = -1;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    // hide photo
    HidePhoto(outRowId2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    // hide photo
    HidePhoto(outRowId1, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_003");
}

/**
 * @tc.name: update_photo_update_source_album_test_004
 * @tc.desc: insert a normal photo, hide photo, cancel hide
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, update_photo_update_source_album_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_004");
    string packageName = "app_008";
    // insert photo
    int64_t outRowId = -1;
    string title;
    string displayName;
    InsertPhoto(packageName, outRowId, title, displayName, true);
    // hide photo
    HidePhoto(outRowId, 1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    // cancel hide photo
    HidePhoto(outRowId, 0);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId, title, displayName));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_004");
}

/**
 * @tc.name: update_photo_update_source_album_test_005
 * @tc.desc: insert a normal photo, logic delete photo, cancel delete
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, update_photo_update_source_album_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd update_photo_update_source_album_test_005");
    string packageName = "app_009";
    // insert photo
    int64_t outRowId = -1;
    string title;
    string displayName;
    InsertPhoto(packageName, outRowId, title, displayName, true);
    // logic delete photo
    UpdatePhotoTrashed(outRowId, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    // cancel logic delete photo
    UpdatePhotoTrashed(outRowId, false);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId, title, displayName));
    MEDIA_INFO_LOG("end tdd update_photo_update_source_album_test_005");
}

/**
 * @tc.name: delete_photo_update_source_album_test_001
 * @tc.desc: insert two normal photo, delete two photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, delete_photo_update_source_album_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_001");
    string packageName = "app_010";
    // insert photo
    int64_t outRowId1 = -1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2 = -1;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    // delete photo
    DeletePhoto(outRowId2);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    // delete photo
    DeletePhoto(outRowId1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_001");
}

/**
 * @tc.name: delete_photo_update_source_album_test_002
 * @tc.desc: insert two normal photo, hide a photo, delete a photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, delete_photo_update_source_album_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_002");
    string packageName = "app_011";
    // insert photo
    int64_t outRowId1 = -1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2 = -1;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    // hide photo
    HidePhoto(outRowId2, 1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    // delete photo
    DeletePhoto(outRowId1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_002");
}

/**
 * @tc.name: delete_photo_update_source_album_test_003
 * @tc.desc: insert two normal photo, logic delete a photo, delete a photo
 * @tc.type: FUNC
 * @tc.require: issueI6B1SE
 */
HWTEST_F(MediaLibrarySourceAlbumTest, delete_photo_update_source_album_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd delete_photo_update_source_album_test_003");
    string packageName = "app_012";
    // insert photo
    int64_t outRowId1 = -1;
    string title1;
    string displayName1;
    InsertPhoto(packageName, outRowId1, title1, displayName1, true);
    // insert photo
    int64_t outRowId2 = -1;
    string title2;
    string displayName2;
    InsertPhoto(packageName, outRowId2, title2, displayName2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 2, GetCoverUri(outRowId2, title2, displayName2));
    // logic delete photo
    UpdatePhotoTrashed(outRowId2, true);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 1, GetCoverUri(outRowId1, title1, displayName1));
    // delete photo
    DeletePhoto(outRowId1);
    // verify
    ValidPhotoAlbumValue(packageName, 1, 0, "");
    MEDIA_INFO_LOG("end tdd delete_photo_update_source_album_test_003");
}
} // namespace Media
} // namespace OHOS