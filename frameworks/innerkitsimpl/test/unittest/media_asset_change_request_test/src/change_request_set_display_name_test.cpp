/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "ChangeRequestSetDisplayNameTest"

#include "change_request_set_display_name_test.h"

#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_photo_operations.h"
#include "fetch_result.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "rdb_utils.h"
#include "uri.h"
#include "userfilemgr_uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace std;
using namespace testing::ext;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;
using namespace OHOS::RdbDataShareAdapter;

const std::string SET_DISPLAY_NAME_KEY = "set_displayName";
const std::string CAN_FALLBACK = "can_fallback";
const std::string OLD_DISPLAY_NAME = "old_displayName";
const std::string API_VERSION = "api_version";

const std::string INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_ID + ", " +
                                 MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_TITLE + ", " +
                                 MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_MIME_TYPE + ", " +
                                 MediaColumn::MEDIA_TYPE + ", " + PhotoColumn::PHOTO_MEDIA_SUFFIX + ", " +
                                 PhotoColumn::PHOTO_SUBTYPE + ", " + MediaColumn::MEDIA_DATE_TAKEN + ")";

const std::string VALUES_BEGIN = " VALUES (";
const string VALUES_END = ") ";

const std::string PHOTO_AEERT_REAL_NAME = "IMG_1501924305_000.jpg";
const std::string OLD_PHOTO_AEERT_DISPLAY_NAME = "old_photo_asset.jpg";
const std::string NEW_PHOTO_AEERT_DISPLAY_NAME = "new_photo_asset.heif";

const std::string VIDEO_AEERT_REAL_NAME = "IMG_1501924305_000.mp4";
const std::string OLD_VIDEO_AEERT_DISPLAY_NAME = "old_video_asset.mp4";
const std::string NEW_VIDEO_AEERT_DISPLAY_NAME = "new_video_asset.avi";

const std::string OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME = "old_moving_photo_asset.jpg";
const std::string NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME = "new_moving_photo_asset.heif";

const std::string OLD_PHOTO_PATH = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string OLD_VIDEO_PATH = "/storage/cloud/files/Photo/16/VID_1742022530_004.mp4";

// file_id,
// data, title, display_name, mime_type, media_suffix, meta_date_modified, last_visit_time
const std::string INSERT_PHOTO_AEERT =
    INSERT_PHOTO + VALUES_BEGIN + "1, " +
    "'/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg', 'old_photo_asset', 'old_photo_asset.jpg', " +
    "'image/jpeg', 1, 'jpg', 0, " + to_string(MediaFileUtils::UTCTimeMilliSeconds()) + VALUES_END;

const std::string INSERT_MOVING_PHOTO_AEERT =
    INSERT_PHOTO + VALUES_BEGIN + "1, " +
    "'/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg', 'old_moving_photo_asset', 'old_moving_photo_asset.jpg', "
    + "'image/jpeg', 1, 'jpg', 3, " + to_string(MediaFileUtils::UTCTimeMilliSeconds()) + VALUES_END;

const std::string INSERT_VIDEO_PHOTO_AEERT =
    INSERT_PHOTO + VALUES_BEGIN + "1, " +
    "'/storage/cloud/files/Photo/16/VID_1742022530_004.mp4', 'old_video_asset', 'old_video_asset.mp4', " +
    "'video/mp4', 2, 'mp4', 0, " + to_string(MediaFileUtils::UTCTimeMilliSeconds()) + VALUES_END;

const std::string DELETE_DATA = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE file_id = 1";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
void SetTables()
{
    std::vector<std::string> createTableSqlList = { PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void CleanTestTables()
{
    std::vector<std::string> dropTableList = { PhotoColumn::PHOTOS_TABLE };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    system("rm -rf /storage/cloud/files/.cache");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    SetTables();
}

void ChangeRequestSetDisplayNameTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("start SetDisplayNameTest");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    SetTables();
    MEDIA_INFO_LOG("setDisplayNameTest::SetUpTestCase:: Finish");
}

void ChangeRequestSetDisplayNameTest::TearDownTestCase()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    ClearAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("SetDisplayNameTest Clean is finish");
}

void ChangeRequestSetDisplayNameTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start SetDisplayNameTest failed, can not get rdbstore");
        exit(1);
    }
    ClearAndRestart();
}

void ChangeRequestSetDisplayNameTest::TearDown()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start SetDisplayNameTest failed, can not get rdbstore");
        exit(1);
    }
    int32_t ret = g_rdbStore->ExecuteSql(DELETE_DATA);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", DELETE_DATA.c_str());
        return;
    }
}

std::unique_ptr<FileAsset> QueryAssetByFileId(const std::string &fileId)
{
    std::string querySql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_ID + " = " + fileId;
    EXPECT_NE((g_rdbStore == nullptr), true);
    auto resultSet = g_rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Get resultSet failed");
        return nullptr;
    }

    int32_t resultSetCount = 0;
    int32_t ret = resultSet->GetRowCount(resultSetCount);
    if (ret != NativeRdb::E_OK || resultSetCount <= 0) {
        MEDIA_ERR_LOG("resultSet row count is 0");
        return nullptr;
    }

    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult = make_shared<FetchResult<FileAsset>>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Get fetchFileResult failed");
        return nullptr;
    }
    auto fileAsset = fetchFileResult->GetObjectFromRdb(resultSet, 0);
    if (fileAsset == nullptr || fileAsset->GetId() < 0) {
        return nullptr;
    }
    return fileAsset;
}

void UriAppendKeyValue(std::string &uri, const std::string &key, std::string value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t pos = uri.find('#');
    if (pos == string::npos) {
        uri += append;
    } else {
        uri.insert(pos, append);
    }
}

int32_t UpdateFileAsset(const std::string &newDisplayName, const std::string &isCanFallback,
    const std::string &oldDisplayName)
{
    std::string uri = PAH_UPDATE_PHOTO;
    UriAppendKeyValue(uri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    UriAppendKeyValue(uri, SET_DISPLAY_NAME_KEY, newDisplayName);
    UriAppendKeyValue(uri, CAN_FALLBACK, isCanFallback);
    UriAppendKeyValue(uri, OLD_DISPLAY_NAME, oldDisplayName);
    Uri updateAssetUri(uri);

    MediaLibraryCommand cmd(updateAssetUri);
    
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, newDisplayName);
    std::string newTitle = MediaFileUtils::GetTitleFromDisplayName(newDisplayName);
    values.Put(MediaColumn::MEDIA_TITLE, newTitle);
    
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = " + "1");

    return MediaLibraryDataManager::GetInstance()->Update(cmd, values, predicates);
}

std::unique_ptr<FileAsset> CreateNewFileAsset(const std::string &newDisplayName, const std::string oldPath)
{
    std::unique_ptr<FileAsset> fileAsset = std::make_unique<FileAsset>();
    fileAsset->SetDisplayName(newDisplayName);

    std::string newTitle = MediaFileUtils::GetTitleFromDisplayName(newDisplayName);
    fileAsset->SetTitle(newTitle);

    std::string mimeType = MediaFileUtils::GetMimeTypeFromDisplayName(newDisplayName);
    fileAsset->SetMimeType(mimeType);

    std::string newExtension = MediaFileUtils::GetExtensionFromPath(newDisplayName);
    std::string newPath = MediaFileUtils::UnSplitByChar(oldPath, '.') + "." + newExtension;
    
    fileAsset->SetPath(newPath);

    return fileAsset;
}

int32_t CompareNewAssetToDdAsset(
    const std::unique_ptr<FileAsset> &oldAsset, const std::unique_ptr<FileAsset> &newAsset)
{
    if (oldAsset->GetPath() != newAsset->GetPath()) {
        MEDIA_ERR_LOG("Path is different.");
        return E_ERR;
    }

    if (oldAsset->GetDisplayName() != newAsset->GetDisplayName()) {
        MEDIA_ERR_LOG("DisplayName is different.");
        return E_ERR;
    }

    if (oldAsset->GetTitle() != newAsset->GetTitle()) {
        MEDIA_ERR_LOG("Title is different.");
        return E_ERR;
    }

    if (oldAsset->GetMimeType() != newAsset->GetMimeType()) {
        MEDIA_ERR_LOG("MimeType is different.");
        return E_ERR;
    }
    return E_OK;
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_001
 * @tc.desc: photo SetDisplayName oldExtension is jpg and newExtension is heif, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_001, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);
    
    auto newFileAsset = CreateNewFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_002
 * @tc.desc: SetDisplayName oldExtension is jpg and newExtension is mp4, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_002, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);

    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_003
 * @tc.desc: moving photo SetDisplayName oldExtension is jpg and newExtension is heif, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_003, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_MOVING_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    std::string mp4Path = MediaFileUtils::UnSplitByChar(oldPath, '.') + ".mp4";
    EXPECT_EQ(MediaFileUtils::CreateFile(mp4Path), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);
    
    auto newFileAsset = CreateNewFileAsset(NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_004
 * @tc.desc: moving photo SetDisplayName oldExtension is jpg and newExtension is mp4, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_004, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_MOVING_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    std::string mp4Path = MediaFileUtils::UnSplitByChar(oldPath, '.') + ".mp4";
    EXPECT_EQ(MediaFileUtils::CreateFile(mp4Path), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);

    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_005
 * @tc.desc:  video SetDisplayName oldExtension is mp4 and newExtension is avi, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_005, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_VIDEO_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_VIDEO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);

    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_VIDEO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_006
 * @tc.desc:  video SetDisplayName oldExtension is mp4 and newExtension is heif, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_006, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_VIDEO_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    ret = UpdateFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_VIDEO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);

    auto newFileAsset = CreateNewFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, OLD_VIDEO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_007
 * @tc.desc:  photo SetDisplayName after editdata, oldExtension is jpg and newExtension is heif, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_007, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));

    ret = UpdateFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);
    
    auto newFileAsset = CreateNewFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/editdata"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/source.jpg"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_008
 * @tc.desc:  photo SetDisplayName after editdata, oldExtension is jpg and newExtension is mp4, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_008, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);
    
    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/editdata"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_009
 * @tc.desc:  movingphoto SetDisplayName after editdata, oldExtension is jpg newExtension is heif, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_009, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    std::string mp4Path = MediaFileUtils::UnSplitByChar(oldPath, '.') + ".mp4";
    EXPECT_EQ(MediaFileUtils::CreateFile(mp4Path), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/extraData"));

    ret = UpdateFileAsset(NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);
    
    auto newFileAsset = CreateNewFileAsset(NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/source.jpg"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_010
 * @tc.desc:  moving photo SetDisplayName after editdata, oldExtension is jpg and newExtension is mp4, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_010, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    std::string mp4Path = MediaFileUtils::UnSplitByChar(oldPath, '.') + ".mp4";
    EXPECT_EQ(MediaFileUtils::CreateFile(mp4Path), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/editdata"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/extraData"));

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);
    
    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_PHOTO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(mp4Path), true);
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.heif/source.jpg"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/IMG_1501924305_000.jpg/source.jpg"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_011
 * @tc.desc:  video SetDisplayName after editdata, oldExtension is mp4 and newExtension is avi, expect set success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_011, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_VIDEO_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/editdata"));

    ret = UpdateFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_VIDEO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, 0);
    
    auto newFileAsset = CreateNewFileAsset(NEW_VIDEO_AEERT_DISPLAY_NAME, OLD_VIDEO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), true);
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/source.mp4"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/editdata"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.avi/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.avi/editdata"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_OK);
}

/**
 * @tc.name: SetDisplayName_PhotoAsset_012
 * @tc.desc:  video SetDisplayName after editdata, oldExtension is mp4 and newExtension is heif, expect set fail
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestSetDisplayNameTest, SetDisplayName_PhotoAsset_012, TestSize.Level0)
{
    EXPECT_NE((g_rdbStore == nullptr), true);
    int32_t ret = g_rdbStore->ExecuteSql(INSERT_VIDEO_PHOTO_AEERT);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    auto oldFileAsset = QueryAssetByFileId("1");
    string oldPath = oldFileAsset->GetPath();
    EXPECT_EQ(MediaFileUtils::CreateDirectory("/storage/cloud/files/Photo/16/"), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    // 构造缩略图
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), false);
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/LCD.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.thumbs/Photo/16/VID_1742022530_004.mp4/THM.jpg"));
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    // 构造编辑路径
    EXPECT_EQ(true,
        MediaFileUtils::CreateDirectory("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::CreateFile("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/editdata"));

    ret = UpdateFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_VIDEO_AEERT_DISPLAY_NAME);
    EXPECT_GE(ret, E_INVALID_VALUES);
    
    auto newFileAsset = CreateNewFileAsset(NEW_PHOTO_AEERT_DISPLAY_NAME, OLD_VIDEO_PATH);
    EXPECT_NE(newFileAsset, nullptr);
    EXPECT_EQ(PhotoFileUtils::IsThumbnailExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(newFileAsset->GetPath()), false);
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/source.mp4"));
    EXPECT_EQ(true,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.mp4/editdata"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.avi/source.mp4"));
    EXPECT_EQ(false,
        MediaFileUtils::IsFileExists("/storage/cloud/files/.editData/Photo/16/VID_1742022530_004.avi/editdata"));

    auto dbFileAsset = QueryAssetByFileId("1");
    EXPECT_NE(dbFileAsset, nullptr);

    EXPECT_EQ(CompareNewAssetToDdAsset(dbFileAsset, newFileAsset), E_ERR);
}


} // namespace Media
} // namespace OHOS