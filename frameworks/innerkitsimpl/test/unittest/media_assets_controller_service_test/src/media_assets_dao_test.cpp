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

#define MLOG_TAG "MediaAssetsDaoTest"

#define private public
#define protected public
#include "media_assets_dao_test.h"
#undef private
#undef protected

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>

#include "media_assets_dao.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_notify.h"
#include "asset_accurate_refresh.h"
#include "media_file_utils.h"
#include "media_column.h"
#include "photos_po.h"
#include "photo_album_po.h"
#include "cloud_media_define.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Media::ORM;
using namespace Common;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t InsertPhoto(int32_t fileId, const string &displayName, int32_t mediaType, int64_t size = 1024000)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        PhotoColumn::PHOTO_CLOUD_ID + ", " +
        PhotoColumn::PHOTO_CLOUD_VERSION + ", " +
        PhotoColumn::PHOTO_SOURCE_PATH + ", " +
        MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN + ", " +
        PhotoColumn::PHOTO_FILE_SOURCE_TYPE + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME + ", " +
        PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE + ", " +
        PhotoColumn::PHOTO_BURST_KEY +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', " +
        to_string(mediaType) + ", " +
        to_string(size) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, 0, 1, '', 0, '', 0, 0, 0, '', 0, '')";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithCloudInfo(int32_t fileId, const string &displayName, const string &cloudId,
    int32_t position, int32_t dirty, int64_t cloudVersion = 1)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        PhotoColumn::PHOTO_CLOUD_ID + ", " +
        PhotoColumn::PHOTO_CLOUD_VERSION + ", " +
        PhotoColumn::PHOTO_SOURCE_PATH + ", " +
        MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN + ", " +
        PhotoColumn::PHOTO_FILE_SOURCE_TYPE + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME + ", " +
        PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, " +
        to_string(dirty) + ", " +
        to_string(position) + ", '" +
        cloudId + "', " +
        to_string(cloudVersion) + ", '', 0, 0, 0, '', 0)";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithPackageName(int32_t fileId, const string &displayName, const string &packageName)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        MediaColumn::MEDIA_PACKAGE_NAME +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, 0, 1, '" +
        packageName + "')";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithSouthDeviceType(int32_t fileId, const string &displayName, int32_t southDeviceType)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, 0, 1, " +
        to_string(southDeviceType) + ")";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithBurstKey(int32_t fileId, const string &displayName, const string &burstKey)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        PhotoColumn::PHOTO_BURST_KEY +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, 0, 1, '" +
        burstKey + "')";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithHidden(int32_t fileId, const string &displayName, const string &sourcePath,
    int32_t hidden, int32_t orientation = 0)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        PhotoColumn::PHOTO_SOURCE_PATH + ", " +
        MediaColumn::MEDIA_DATE_TRASHED + ", " +
        MediaColumn::MEDIA_HIDDEN +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(orientation) + ", 0, 0, 1, '" +
        sourcePath + "', 0, " +
        to_string(hidden) + ")";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithAlbum(int32_t fileId, const string &displayName, int32_t albumId,
    int32_t orientation = 0)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        MediaColumn::MEDIA_DATE_TRASHED +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(orientation) + ", " +
        to_string(albumId) + ", 0, 1, 0)";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoWithTrash(int32_t fileId, const string &displayName, int64_t dateTrashed)
{
    string sql = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
        MediaColumn::MEDIA_ID + ", " +
        MediaColumn::MEDIA_NAME + ", " +
        MediaColumn::MEDIA_TYPE + ", " +
        MediaColumn::MEDIA_SIZE + ", " +
        MediaColumn::MEDIA_DATE_ADDED + ", " +
        MediaColumn::MEDIA_DATE_MODIFIED + ", " +
        PhotoColumn::PHOTO_ORIENTATION + ", " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + ", " +
        PhotoColumn::PHOTO_DIRTY + ", " +
        PhotoColumn::PHOTO_POSITION + ", " +
        MediaColumn::MEDIA_DATE_TRASHED +
        ") VALUES (" +
        to_string(fileId) + ", '" +
        displayName + "', 1, 1024000, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", 0, 0, 0, 1, " +
        to_string(dateTrashed) + ")";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertAlbum(int32_t albumId, const string &albumName, const string &lpath)
{
    string sql = "INSERT INTO " + PhotoAlbumColumns::TABLE + "(" +
        PhotoAlbumColumns::ALBUM_ID + ", " +
        PhotoAlbumColumns::ALBUM_NAME + ", " +
        PhotoAlbumColumns::ALBUM_LPATH + ", " +
        PhotoAlbumColumns::ALBUM_TYPE + ", " +
        PhotoAlbumColumns::ALBUM_DATE_ADDED + ", " +
        PhotoAlbumColumns::ALBUM_DATE_MODIFIED +
        ") VALUES (" +
        to_string(albumId) + ", '" +
        albumName + "', '" +
        lpath + "', 1, " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ", " +
        to_string(MediaFileUtils::UTCTimeMilliSeconds()) + ")";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t InsertPhotoExt(const string &fileId)
{
    string sql = "INSERT INTO " + PhotoExtColumn::PHOTOS_EXT_TABLE + "(" +
        PhotoExtColumn::PHOTO_ID +
        ") VALUES ('" +
        fileId + ")";
    return g_rdbStore->ExecuteSql(sql);
}

static int32_t QueryPhotoExists(int32_t fileId)
{
    vector<string> columns = {MediaColumn::MEDIA_ID};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr) {
        return 0;
    }
    int32_t rowCount = 0;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    return rowCount;
}

static int32_t QueryPhotoCloudId(int32_t fileId, string &cloudId)
{
    vector<string> columns = {PhotoColumn::PHOTO_CLOUD_ID};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_FAIL;
    }
    int32_t index = 0;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_CLOUD_ID, index);
    resultSet->GetString(index, cloudId);
    resultSet->Close();
    return E_OK;
}

static int32_t QueryPhotoPosition(int32_t fileId, int32_t &position)
{
    vector<string> columns = {PhotoColumn::PHOTO_POSITION};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_FAIL;
    }
    int32_t index = 0;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_POSITION, index);
    resultSet->GetInt(index, position);
    resultSet->Close();
    return E_OK;
}

static int32_t QueryPhotoDirty(int32_t fileId, int32_t &dirty)
{
    vector<string> columns = {PhotoColumn::PHOTO_DIRTY};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_FAIL;
    }
    int32_t index = 0;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_DIRTY, index);
    resultSet->GetInt(index, dirty);
    resultSet->Close();
    return E_OK;
}

static int32_t QueryPhotoCloudVersion(int32_t fileId, int64_t &cloudVersion)
{
    vector<string> columns = {PhotoColumn::PHOTO_CLOUD_VERSION};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr) {
        return E_FAIL;
    }
    int32_t index = 0;
    resultSet->GetColumnIndex(PhotoColumn::PHOTO_CLOUD_VERSION, index);
    resultSet->GetLong(index, cloudVersion);
    resultSet->Close();
    return E_OK;
}

static int32_t QueryPhotoDateTrashed(int32_t fileId, int64_t &dateTrashed)
{
    vector<string> columns = {MediaColumn::MEDIA_DATE_TRASHED};
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_FAIL;
    }
    int32_t index = 0;
    resultSet->GetColumnIndex(MediaColumn::MEDIA_DATE_TRASHED, index);
    resultSet->GetLong(index, dateTrashed);
    resultSet->Close();
    return E_OK;
}

static int32_t QueryPhotoExtExists(const string &fileId)
{
    vector<string> columns = {PhotoExtColumn::PHOTO_ID};
    RdbPredicates rdbPredicates(PhotoExtColumn::PHOTOS_EXT_TABLE);
    rdbPredicates.EqualTo(PhotoExtColumn::PHOTO_ID, fileId);
    auto resultSet = g_rdbStore->Query(rdbPredicates, columns);
    if (resultSet == nullptr) {
        return 0;
    }
    int32_t rowCount = 0;
    resultSet->GetRowCount(rowCount);
    resultSet->Close();
    return rowCount;
}

void MediaAssetsDaoTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaAssetsDaoTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoExtColumn::PHOTOS_EXT_TABLE);
    MEDIA_INFO_LOG("MediaAssetsDaoTest SetUpTestCase");
}

void MediaAssetsDaoTest::TearDownTestCase(void)
{
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoExtColumn::PHOTOS_EXT_TABLE);
    MEDIA_INFO_LOG("MediaAssetsDaoTest TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void MediaAssetsDaoTest::SetUp(void)
{
    MEDIA_INFO_LOG("MediaAssetsDaoTest SetUp");
}

void MediaAssetsDaoTest::TearDown(void)
{
    MEDIA_INFO_LOG("MediaAssetsDaoTest TearDown");
}

void MediaAssetsDaoTest::InitDatabase(void)
{
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoExtColumn::PHOTOS_EXT_TABLE);
}

void MediaAssetsDaoTest::CreateTestPhotosTable(void)
{
    string sql = "CREATE TABLE IF NOT EXISTS " + PhotoColumn::PHOTOS_TABLE + " (" +
        MediaColumn::MEDIA_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
        MediaColumn::MEDIA_NAME + " TEXT, " +
        MediaColumn::MEDIA_TYPE + " INTEGER, " +
        MediaColumn::MEDIA_SIZE + " INTEGER, " +
        MediaColumn::MEDIA_DATE_ADDED + " INTEGER, " +
        MediaColumn::MEDIA_DATE_MODIFIED + " INTEGER, " +
        PhotoColumn::PHOTO_ORIENTATION + " INTEGER, " +
        PhotoColumn::PHOTO_OWNER_ALBUM_ID + " INTEGER, " +
        PhotoColumn::PHOTO_DIRTY + " INTEGER, " +
        PhotoColumn::PHOTO_POSITION + " INTEGER, " +
        PhotoColumn::PHOTO_CLOUD_ID + " TEXT, " +
        PhotoColumn::PHOTO_CLOUD_VERSION + " INTEGER, " +
        PhotoColumn::PHOTO_SOURCE_PATH + " TEXT, " +
        MediaColumn::MEDIA_DATE_TRASHED + " INTEGER, " +
        MediaColumn::MEDIA_HIDDEN + " INTEGER, " +
        PhotoColumn::PHOTO_FILE_SOURCE_TYPE + " INTEGER, " +
        MediaColumn::MEDIA_PACKAGE_NAME + " TEXT, " +
        PhotoColumn::PHOTO_SOUTH_DEVICE_TYPE + " INTEGER, " +
        PhotoColumn::PHOTO_BURST_KEY + " TEXT)";
    g_rdbStore->ExecuteSql(sql);
}

void MediaAssetsDaoTest::CreateTestPhotoAlbumTable(void)
{
    string sql = "CREATE TABLE IF NOT EXISTS " + PhotoAlbumColumns::TABLE + " (" +
        PhotoAlbumColumns::ALBUM_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
        PhotoAlbumColumns::ALBUM_NAME + " TEXT, " +
        PhotoAlbumColumns::ALBUM_LPATH + " TEXT, " +
        PhotoAlbumColumns::ALBUM_TYPE + " INTEGER, " +
        PhotoAlbumColumns::ALBUM_DATE_ADDED + " INTEGER, " +
        PhotoAlbumColumns::ALBUM_DATE_MODIFIED + " INTEGER)";
    g_rdbStore->ExecuteSql(sql);
}

void MediaAssetsDaoTest::CreateTestPhotoExtTable(void)
{
    string sql = "CREATE TABLE IF NOT EXISTS " + PhotoExtColumn::PHOTOS_EXT_TABLE + " (" +
        PhotoExtColumn::PHOTO_ID + " TEXT PRIMARY KEY)";
    g_rdbStore->ExecuteSql(sql);
}

void MediaAssetsDaoTest::InsertTestPhoto(int32_t fileId, const string &displayName, int32_t mediaType)
{
    InsertPhoto(fileId, displayName, mediaType);
}

void MediaAssetsDaoTest::InsertTestAlbum(int32_t albumId, const string &albumName, const string &lpath)
{
    InsertAlbum(albumId, albumName, lpath);
}

void MediaAssetsDaoTest::InsertTestPhotoExt(const string &fileId)
{
    InsertPhotoExt(fileId);
}

void MediaAssetsDaoTest::CleanTables(void)
{
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    ClearTable(PhotoExtColumn::PHOTOS_EXT_TABLE);
}

HWTEST_F(MediaAssetsDaoTest, QueryAssets_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAssets_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    vector<string> fileIds;
    vector<PhotosPo> queryResult;
    int32_t ret = dao.QueryAssets(fileIds, queryResult);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    fileIds.push_back(to_string(TEST_FILE_ID_1));
    ret = dao.QueryAssets(fileIds, queryResult);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(queryResult.size(), 0);
    EXPECT_EQ(queryResult[0].fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, QueryAssets_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAssets_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    int32_t ret = dao.QueryAssets(fileIds, queryResult);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(queryResult.size(), 2);
}

HWTEST_F(MediaAssetsDaoTest, QueryAssets_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAssets_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    vector<string> fileIds = {"999999"};
    vector<PhotosPo> queryResult;
    int32_t ret = dao.QueryAssets(fileIds, queryResult);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(queryResult.size(), 0);
}

HWTEST_F(MediaAssetsDaoTest, CreateNewAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateNewAsset_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;
    int64_t newAssetId = 0;
    NativeRdb::ValuesBucket values;
    int32_t ret = dao.CreateNewAsset(photoRefresh, newAssetId, values);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, ClearCloudInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("ClearCloudInfo_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;
    int32_t ret = dao.ClearCloudInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_NE(ret, E_OK);

    ret = dao.ClearCloudInfo(photoRefresh, 0);
    EXPECT_NE(ret, E_OK);

    ret = dao.ClearCloudInfo(photoRefresh, -1);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, ClearCloudInfo_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("ClearCloudInfo_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 3, 1, 100);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t ret = dao.ClearCloudInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    string cloudId;
    ret = QueryPhotoCloudId(TEST_FILE_ID_1, cloudId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(cloudId.empty());

    int32_t dirty = 0;
    ret = QueryPhotoDirty(TEST_FILE_ID_1, dirty);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(dirty, static_cast<int32_t>(DirtyType::TYPE_NEW));

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_1, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::LOCAL));

    int64_t cloudVersion = 0;
    ret = QueryPhotoCloudVersion(TEST_FILE_ID_1, cloudVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(cloudVersion, 0);
}

HWTEST_F(MediaAssetsDaoTest, ResetPositionToCloudOnly_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("ResetPositionToCloudOnly_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;
    int32_t ret = dao.ResetPositionToCloudOnly(photoRefresh, TEST_FILE_ID_1);
    EXPECT_NE(ret, E_OK);

    ret = dao.ResetPositionToCloudOnly(photoRefresh, 0);
    EXPECT_NE(ret, E_OK);

    ret = dao.ResetPositionToCloudOnly(photoRefresh, -1);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, ResetPositionToCloudOnly_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("ResetPositionToCloudOnly_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 1, 1, 100);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t ret = dao.ResetPositionToCloudOnly(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_1, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumByAlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumByAlbumId_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumByAlbumId(0, albumInfo);
    EXPECT_NE(ret, E_OK);

    ret = dao.QueryAlbumByAlbumId(-1, albumInfo);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumByAlbumId_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumByAlbumId_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumByAlbumId(TEST_ALBUM_ID, albumInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo.has_value());
    EXPECT_EQ(albumInfo->albumId.value_or(0), TEST_ALBUM_ID);
    EXPECT_EQ(albumInfo->albumName.value_or(""), "TestAlbum");
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumByAlbumId_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumByAlbumId_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumByAlbumId(999999, albumInfo);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(albumInfo.has_value());
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumBylPath_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumBylPath_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumBylPath("", albumInfo);
    EXPECT_NE(ret, E_OK);

    ret = dao.QueryAlbumBylPath(" ", albumInfo);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumBylPath_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumBylPath_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumBylPath("/Pictures/TestAlbum", albumInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo.has_value());
    EXPECT_EQ(albumInfo->albumId.value_or(0), TEST_ALBUM_ID);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbumBylPath_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbumBylPath_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbumBylPath("/Pictures/NonExistentAlbum", albumInfo);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(albumInfo.has_value());
}

HWTEST_F(MediaAssetsDaoTest, GetLpathFromSourcePath_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetLpathFromSourcePath_Test_001 Begin");
    MediaAssetsDao dao;

    string lpath = dao.GetLpathFromSourcePath("");
    EXPECT_TRUE(lpath.empty());

    lpath = dao.GetLpathFromSourcePath("invalid_path");
    EXPECT_TRUE(lpath.empty());

    lpath = dao.GetLpathFromSourcePath("/storage/emulated/0");
    EXPECT_TRUE(lpath.empty());

    lpath = dao.GetLpathFromSourcePath("/storage/emulated/0/file.jpg");
    EXPECT_TRUE(lpath.empty());
}

HWTEST_F(MediaAssetsDaoTest, GetLpathFromSourcePath_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetLpathFromSourcePath_Test_002 Begin");
    MediaAssetsDao dao;

    string lpath = dao.GetLpathFromSourcePath("/storage/emulated/0/Pictures/TestAlbum/file.jpg");
    EXPECT_EQ(lpath, "/Pictures/TestAlbum");

    lpath = dao.GetLpathFromSourcePath("/storage/emulated/0/DCIM/Camera/photo.jpg");
    EXPECT_EQ(lpath, "/DCIM/Camera");
}

HWTEST_F(MediaAssetsDaoTest, GetLpathFromSourcePath_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetLpathFromSourcePath_Test_003 Begin");
    MediaAssetsDao dao;

    string lpath = dao.GetLpathFromSourcePath("/invalid/prefix/Pictures/file.jpg");
    EXPECT_TRUE(lpath.empty());
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbum_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbum(TEST_ALBUM_ID, "", albumInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo.has_value());
    EXPECT_EQ(albumInfo->albumId.value_or(0), TEST_ALBUM_ID);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbum_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbum(0, "/storage/emulated/0/Pictures/TestAlbum/file.jpg", albumInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo.has_value());
    EXPECT_EQ(albumInfo->albumId.value_or(0), TEST_ALBUM_ID);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhoto_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhoto_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 0);

    PhotosPo photoInfo;
    photoInfo.ownerAlbumId = TEST_ALBUM_ID;
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhoto(photoInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhoto_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhoto_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithHidden(TEST_FILE_ID_1, "test_001.jpg", "/storage/emulated/0/Pictures", 1, 0);

    PhotosPo photoInfo;
    photoInfo.sourcePath = "/storage/emulated/0/Pictures";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhoto(photoInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhoto_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhoto_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.ownerAlbumId = 0;
    photoInfo.sourcePath = "";

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhoto(photoInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInHiddenAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInHiddenAlbum_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithHidden(TEST_FILE_ID_1, "test_001.jpg", "/storage/emulated/0/Pictures", 1, 0);

    PhotosPo photoInfo;
    photoInfo.sourcePath = "/storage/emulated/0/Pictures";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInHiddenAlbum(photoInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInHiddenAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInHiddenAlbum_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.sourcePath = "/storage/emulated/0/Pictures";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInHiddenAlbum(photoInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInHiddenAlbum_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInHiddenAlbum_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.sourcePath = "";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInHiddenAlbum(photoInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInTargetAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInTargetAlbum_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 0);

    PhotoAlbumPo albumInfo;
    albumInfo.albumId = TEST_ALBUM_ID;

    PhotosPo photoInfo;
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInTargetAlbum(photoInfo, albumInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInTargetAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInTargetAlbum_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    PhotoAlbumPo albumInfo;
    albumInfo.albumId = TEST_ALBUM_ID;

    PhotosPo photoInfo;
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInTargetAlbum(photoInfo, albumInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInTargetAlbum_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInTargetAlbum_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 0);

    PhotoAlbumPo albumInfo;
    albumInfo.albumId = TEST_ALBUM_ID;

    PhotosPo photoInfo;
    photoInfo.displayName = "test_002.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInTargetAlbum(photoInfo, albumInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, MergeCloudInfoIntoTargetPhoto_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MergeCloudInfoIntoTargetPhoto_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.MergeCloudInfoIntoTargetPhoto(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, MergeCloudInfoIntoTargetPhoto_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MergeCloudInfoIntoTargetPhoto_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id1", 1, 1, 100);
    InsertPhotoWithCloudInfo(TEST_FILE_ID_2, "test_002.jpg", "cloud_id2", 1, 1, 200);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.MergeCloudInfoIntoTargetPhoto(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, MergeCloudInfoIntoTargetPhoto_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MergeCloudInfoIntoTargetPhoto_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 1, 1, 100);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    int32_t ret = dao.MergeCloudInfoIntoTargetPhoto(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, DeletePhotoInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DeletePhotoInfo_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;
    int32_t ret = dao.DeletePhotoInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_NE(ret, E_OK);

    ret = dao.DeletePhotoInfo(photoRefresh, 0);
    EXPECT_NE(ret, E_OK);

    ret = dao.DeletePhotoInfo(photoRefresh, -1);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, DeletePhotoInfo_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("DeletePhotoInfo_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.DeletePhotoInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    int32_t exists = QueryPhotoExists(TEST_FILE_ID_1);
    EXPECT_EQ(exists, 0);
}

HWTEST_F(MediaAssetsDaoTest, MoveOutTrash_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MoveOutTrash_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    PhotosPo photoInfo;
    photoInfo.fileId = TEST_FILE_ID_1;

    int32_t ret = dao.MoveOutTrash(photoInfo, photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, MoveOutTrash_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MoveOutTrash_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    int64_t trashTime = MediaFileUtils::UTCTimeMilliSeconds();
    InsertPhotoWithTrash(TEST_FILE_ID_1, "test_001.jpg", trashTime);

    PhotosPo photoInfo;
    photoInfo.fileId = TEST_FILE_ID_1;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.MoveOutTrash(photoInfo, photoRefresh);
    EXPECT_EQ(ret, E_OK);

    int64_t dateTrashed = 0;
    ret = QueryPhotoDateTrashed(TEST_FILE_ID_1, dateTrashed);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(dateTrashed, 0);
}

HWTEST_F(MediaAssetsDaoTest, LogicalDeleteCloudTrashedPhoto_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("LogicalDeleteCloudTrashedPhoto_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    PhotosPo photoInfo;
    photoInfo.fileId = TEST_FILE_ID_1;

    int32_t ret = dao.LogicalDeleteCloudTrashedPhoto(photoInfo, photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_001 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    targetPhotoInfo.size = 1024000;
    targetPhotoInfo.orientation = 0;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_TRUE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_002 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test1.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test2.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    targetPhotoInfo.size = 1024000;
    targetPhotoInfo.orientation = 0;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_FALSE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_003 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_VIDEO;
    targetPhotoInfo.size = 1024000;
    targetPhotoInfo.orientation = 0;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_FALSE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_004 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    targetPhotoInfo.size = 2048000;
    targetPhotoInfo.orientation = 0;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_FALSE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_005 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_IMAGE;
    targetPhotoInfo.size = 1024000;
    targetPhotoInfo.orientation = 90;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_FALSE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, IsSameAssetIgnoreAlbum_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsSameAssetIgnoreAlbum_Test_006 Begin");
    MediaAssetsDao dao;

    PhotosPo photoInfo;
    photoInfo.displayName = "test.jpg";
    photoInfo.mediaType = TEST_MEDIA_TYPE_VIDEO;
    photoInfo.size = 1024000;
    photoInfo.orientation = 0;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.displayName = "test.jpg";
    targetPhotoInfo.mediaType = TEST_MEDIA_TYPE_VIDEO;
    targetPhotoInfo.size = 1024000;
    targetPhotoInfo.orientation = 90;

    bool isSame = dao.IsSameAssetIgnoreAlbum(photoInfo, targetPhotoInfo);
    EXPECT_TRUE(isSame);
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBoth_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBoth_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.fileId = TEST_FILE_ID_1;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.fileId = TEST_FILE_ID_2;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);

    int32_t ret = dao.UpdatePositionToBoth(sourcePhotoInfo, targetPhotoInfo, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBothBoth_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBoth_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.UpdatePositionToBoth(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_2, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBoth_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBoth_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    int32_t ret = dao.UpdatePositionToBoth(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBothAndFileSourceTypeToLake_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBothAndFileSourceTypeToLake_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.fileId = TEST_FILE_ID_1;

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.fileId = TEST_FILE_ID_2;
    targetPhotoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);

    int32_t ret = dao.UpdatePositionToBothAndFileSourceTypeToLake(sourcePhotoInfo, targetPhotoInfo, photoRefresh);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBothAndFileSourceTypeToLake_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBothAndFileSourceTypeToLake_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.UpdatePositionToBothAndFileSourceTypeToLake(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_2, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBothAndFileSourceTypeToLake_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBothAndFileSourceTypeToLake_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhoto(TEST_FILE_ID_1, "test_001.jpg", TEST_MEDIA_TYPE_IMAGE);
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    int32_t ret = dao.UpdatePositionToBothAndFileSourceTypeToLake(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, FindAssetsByBurstKey_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindAssetsByBurstKey_Test_001 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    string burstKey = "";
    vector<PhotosPo> photoInfoList;
    int32_t ret = dao.FindAssetsByBurstKey(burstKey, photoInfoList);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, FindAssetsByBurstKey_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindAssetsByBurstKey_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    string burstKey = "test_burst_key_001";
    InsertPhotoWithBurstKey(TEST_FILE_ID_1, "test_001.jpg", burstKey);
    InsertPhotoWithBurstKey(TEST_FILE_ID_2, "test_002.jpg", burstKey);

    vector<PhotosPo> photoInfoList;
    int32_t ret = dao.FindAssetsByBurstKey(burstKey, photoInfoList);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfoList.size(), 2);
}

HWTEST_F(MediaAssetsDaoTest, FindAssetsByBurstKey_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindAssetsByBurstKey_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    string burstKey = "non_existent_burst_key";
    vector<PhotosPo> photoInfoList;
    int32_t ret = dao.FindAssetsByBurstKey(burstKey, photoInfoList);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photoInfoList.size(), 0);
}

HWTEST_F(MediaAssetsDaoTest, DeletePhotoExtTable_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DeletePhotoExtTable_Test_002 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    int32_t ret = dao.DeletePhotoExtTable(to_string(TEST_FILE_ID_1));
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, HandlePackageName_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandlePackageName_Test_002 Begin");
    MediaAssetsDao dao;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.packageName = "";

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.packageName = "com.test.app";

    NativeRdb::ValuesBucket values;
    int32_t ret = dao.HandlePackageName(sourcePhotoInfo, targetPhotoInfo, values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, HandlePackageName_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandlePackageName_Test_003 Begin");
    MediaAssetsDao dao;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.packageName = "com.test.app";

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.packageName = "com.test.app";

    NativeRdb::ValuesBucket values;
    int32_t ret = dao.HandlePackageName(sourcePhotoInfo, targetPhotoInfo, values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, HandleSouthDeviceType_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandleSouthDeviceType_Test_002 Begin");
    MediaAssetsDao dao;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.southDeviceType = static_cast<int32_t>(SouthDeviceType::SOUTH_DEVICE_NULL);

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.southDeviceType = static_cast<int32_t>(SouthDeviceType::SOUTH_DEVICE_NULL);

    NativeRdb::ValuesBucket values;
    int32_t ret = dao.HandleSouthDeviceType(sourcePhotoInfo, targetPhotoInfo, values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, HandlePackageName_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandlePackageName_Test_004 Begin");
    MediaAssetsDao dao;

    PhotosPo sourcePhotoInfo;
    sourcePhotoInfo.packageName = "";

    PhotosPo targetPhotoInfo;
    targetPhotoInfo.packageName = "";

    NativeRdb::ValuesBucket values;
    int32_t ret = dao.HandlePackageName(sourcePhotoInfo, targetPhotoInfo, values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbum_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbum_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbum(999999, "", albumInfo);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(albumInfo.has_value());
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbum_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbum_Test_005 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    optional<PhotoAlbumPo> albumInfo;
    int32_t ret = dao.QueryAlbum(0, "/storage/emulated/0/Pictures/TestAlbum/file.jpg", albumInfo);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(albumInfo.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInHiddenAlbum_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInHiddenAlbum_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithHidden(TEST_FILE_ID_1, "test_001.jpg", "/storage/emulated/0/Pictures", 1, 90);

    PhotosPo photoInfo;
    photoInfo.sourcePath = "/storage/emulated/0/Pictures";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 90;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInHiddenAlbum(photoInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInHiddenAlbum_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInHiddenAlbum_Test_005 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithHidden(TEST_FILE_ID_1, "test_001.jpg", "/storage/emulated/0/Pictures", 1, 0);

    PhotosPo photoInfo;
    photoInfo.sourcePath = "/storage/emulated/0/Pictures";
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 2048000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInHiddenAlbum(photoInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInTargetAlbum_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInTargetAlbum_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 90);

    PhotoAlbumPo albumInfo;
    albumInfo.albumId = TEST_ALBUM_ID;

    PhotosPo photoInfo;
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 1024000;
    photoInfo.orientation = 90;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInTargetAlbum(photoInfo, albumInfo, samePhotoInfoOp);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp.has_value());
    EXPECT_EQ(samePhotoInfoOp->fileId.value_or(0), TEST_FILE_ID_1);
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhotoInTargetAlbum_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhotoInTargetAlbum_Test_005 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 0);

    PhotoAlbumPo albumInfo;
    albumInfo.albumId = TEST_ALBUM_ID;

    PhotosPo photoInfo;
    photoInfo.displayName = "test_001.jpg";
    photoInfo.size = 2048000;
    photoInfo.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp;
    int32_t ret = dao.FindSamePhotoInTargetAlbum(photoInfo, albumInfo, samePhotoInfoOp);
    EXPECT_NE(ret, E_OK);
    EXPECT_FALSE(samePhotoInfoOp.has_value());
}

HWTEST_F(MediaAssetsDaoTest, MergeCloudInfoIntoTargetPhoto_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MergeCloudInfoIntoTargetPhoto_Test_006 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 1, 1, 100);
    InsertPhotoWithPackageName(TEST_FILE_ID_2, "test_002.jpg", "");

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    queryResult[0].packageName = "com.test.app";

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.MergeCloudInfoIntoTargetPhoto(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_EQ(ret, E_OK);

    string cloudId;
    ret = QueryPhotoCloudId(TEST_FILE_ID_2, cloudId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(cloudId, "cloud_id_001");
}

HWTEST_F(MediaAssetsDaoTest, ClearCloudInfo_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("ClearCloudInfo_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 3, 1, 100);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t ret = dao.ClearCloudInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    string cloudId;
    ret = QueryPhotoCloudId(TEST_FILE_ID_1, cloudId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(cloudId.empty());
}

HWTEST_F(MediaAssetsDaoTest, ResetPositionToCloudOnly_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("ResetPositionToCloudOnly_Test_003 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 3, 1, 100);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t ret = dao.ResetPositionToCloudOnly(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_1, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBoth_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBoth_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithPackageName(TEST_FILE_ID_1, "test_001.jpg", "");
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    queryResult[0].packageName = "com.test.app";

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.UpdatePositionToBoth(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_2, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, UpdatePositionToBothAndFileSourceTypeToLake_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdatePositionToBothAndFileSourceTypeToLake_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithPackageName(TEST_FILE_ID_1, "test_001.jpg", "");
    InsertPhoto(TEST_FILE_ID_2, "test_002.jpg", TEST_MEDIA_TYPE_IMAGE);

    vector<string> fileIds = {to_string(TEST_FILE_ID_1), to_string(TEST_FILE_ID_2)};
    vector<PhotosPo> queryResult;
    dao.QueryAssets(fileIds, queryResult);

    queryResult[0].packageName = "com.test.app";

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.UpdatePositionToBothAndFileSourceTypeToLake(queryResult[0], queryResult[1], photoRefresh);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_2, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
}

HWTEST_F(MediaAssetsDaoTest, FindSamePhoto_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindSamePhoto_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertPhotoWithAlbum(TEST_FILE_ID_1, "test_001.jpg", TEST_ALBUM_ID, 0);
    InsertPhotoWithAlbum(TEST_FILE_ID_2, "test_002.jpg", TEST_ALBUM_ID, 0);

    PhotosPo photoInfo1;
    photoInfo1.ownerAlbumId = TEST_ALBUM_ID;
    photoInfo1.displayName = "test_001.jpg";
    photoInfo1.size = 1024000;
    photoInfo1.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp1;
    int32_t ret = dao.FindSamePhoto(photoInfo1, samePhotoInfoOp1);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp1.has_value());
    EXPECT_EQ(samePhotoInfoOp1->fileId.value_or(0), TEST_FILE_ID_1);

    PhotosPo photoInfo2;
    photoInfo2.ownerAlbumId = TEST_ALBUM_ID;
    photoInfo2.displayName = "test_002.jpg";
    photoInfo2.size = 1024000;
    photoInfo2.orientation = 0;

    optional<PhotosPo> samePhotoInfoOp2;
    ret = dao.FindSamePhoto(photoInfo2, samePhotoInfoOp2);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(samePhotoInfoOp2.has_value());
    EXPECT_EQ(samePhotoInfoOp2->fileId.value_or(0), TEST_FILE_ID_2);
}

HWTEST_F(MediaAssetsDaoTest, QueryAlbum_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryAlbum_Test_006 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertAlbum(TEST_ALBUM_ID, "TestAlbum", "/Pictures/TestAlbum");
    InsertAlbum(TEST_ALBUM_ID + 1, "TestAlbum2", "/Pictures/TestAlbum2");

    optional<PhotoAlbumPo> albumInfo1;
    int32_t ret = dao.QueryAlbum(TEST_ALBUM_ID, "", albumInfo1);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo1.has_value());
    EXPECT_EQ(albumInfo1->albumId.value_or(0), TEST_ALBUM_ID);

    optional<PhotoAlbumPo> albumInfo2;
    ret = dao.QueryAlbum(TEST_ALBUM_ID + 1, "", albumInfo2);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(albumInfo2.has_value());
    EXPECT_EQ(albumInfo2->albumId.value_or(0), TEST_ALBUM_ID + 1);
}

HWTEST_F(MediaAssetsDaoTest, ClearCloudInfo_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("ClearCloudInfo_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 1, 1, 100);
    InsertPhotoWithCloudInfo(TEST_FILE_ID_2, "test_002.jpg", "cloud_id_002", 1, 1, 200);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.ClearCloudInfo(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    string cloudId;
    ret = QueryPhotoCloudId(TEST_FILE_ID_1, cloudId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(cloudId.empty());

    ret = QueryPhotoCloudId(TEST_FILE_ID_2, cloudId);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(cloudId, "cloud_id_002");
}

HWTEST_F(MediaAssetsDaoTest, ResetPositionToCloudOnly_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("ResetPositionToCloudOnly_Test_004 Begin");
    InitDatabase();
    MediaAssetsDao dao;

    InsertPhotoWithCloudInfo(TEST_FILE_ID_1, "test_001.jpg", "cloud_id_001", 1, 1, 100);
    InsertPhotoWithCloudInfo(TEST_FILE_ID_2, "test_002.jpg", "cloud_id_002", 1, 1, 200);

    shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh =
        make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = dao.ResetPositionToCloudOnly(photoRefresh, TEST_FILE_ID_1);
    EXPECT_EQ(ret, E_OK);

    int32_t position = 0;
    ret = QueryPhotoPosition(TEST_FILE_ID_1, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, static_cast<int32_t>(PhotoPositionType::CLOUD));

    ret = QueryPhotoPosition(TEST_FILE_ID_2, position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, 1);
}

}  // namespace OHOS::Media::Common