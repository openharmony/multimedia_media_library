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

#include "medialibrary_backup_test.h"
#include "media_log.h"
#include "update_restore.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const std::string TEST_ORIGIN_PATH = "/data/test/backup/db";
const std::string TEST_UPDATE_FILE_DIR = "/data/test/backup/file";
const std::string GALLERY_APP_NAME = "photos";
const std::string MEDIA_APP_NAME = "mediaprovider";
const std::string MEDIA_LIBRARY_APP_NAME = "medialibrary";

const int EXPECTED_NUM = 5;
const int EXPECTED_OREINTATION = 270;
const std::string EXPECTED_PACKAGE_NAME = "wechat";
const std::string EXPECTED_USER_COMMENT = "fake_wechat";

class GalleryMediaOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_GALLERY_MEDIA;
    static const string CREATE_GARBAGE_ALBUM;
};

const string GalleryMediaOpenCall::CREATE_GALLERY_MEDIA = string("CREATE TABLE IF NOT EXISTS gallery_media ") +
    " (id INTEGER PRIMARY KEY AUTOINCREMENT, local_media_id INTEGER, _data TEXT COLLATE NOCASE," +
    " _display_name TEXT, description TEXT, is_hw_favorite INTEGER, _size INTEGER, recycledTime INTEGER," +
    " duration INTEGER, media_type INTEGER, showDateToken INTEGER, date_modified INTEGER, height INTEGER, " +
    " width INTEGER, title TEXT, orientation INTEGER, storage_id INTEGER, relative_bucket_id TEXT);";

const string GalleryMediaOpenCall::CREATE_GARBAGE_ALBUM = string("CREATE TABLE IF NOT EXISTS garbage_album") +
    "(app_name TEXT, cache_dir TEXT, nick_name TEXT, nick_dir TEXT, type INTEGER, relative_bucket_id TEXT);";

int GalleryMediaOpenCall::OnCreate(RdbStore &store)
{
    store.ExecuteSql(CREATE_GALLERY_MEDIA);
    return store.ExecuteSql(CREATE_GARBAGE_ALBUM);
}

int GalleryMediaOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

class PhotosOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_PHOTOS;
};

const string PhotosOpenCall::CREATE_PHOTOS = string("CREATE TABLE IF NOT EXISTS Photos ") +
    " (file_id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT, title TEXT, display_name TEXT, size BIGINT," +
    " media_type INT, date_add BIGINT, duration INT, is_favorite INT default 0, date_trashed BIGINT DEFAULT 0," +
    " hidden INT DEFAULT 0, height INT, width INT, user_comment TEXT, orientation INT DEFAULT 0, " +
    " package_name TEXT);";

int PhotosOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_PHOTOS);
}

int PhotosOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<NativeRdb::RdbStore> galleryStorePtr = nullptr;
shared_ptr<NativeRdb::RdbStore> photosStorePtr = nullptr;

void InitGalleryDB()
{
    const string dbPath = TEST_ORIGIN_PATH + "/" + GALLERY_APP_NAME + "/ce/databases/gallery.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    GalleryMediaOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    galleryStorePtr = store;
    store->ExecuteSql(string("INSERT INTO gallery_media VALUES(1, 1, ") +
        "'/storage/emulated/0/tencent/MicroMsg/WeiXin/fake_wechat.jpg', 'fake_wechat.jpg', 'fake_wechat', " +
        " null, 2419880, 0, 0, 1, 1432973383179, 1432973383, 2976, 3968, 'fake_wechat', 0, 65537, -1803300197)");
    store->ExecuteSql(string("INSERT INTO galPlery_media VALUES(2, 2, '/storage/emulated/0/Pictures/favorite.jpg', ") +
        "'favorite.jpg', 'favorite', 1, 7440437, 0, 0, 1, 1495957457427, 15464937461, 3840, 5120, " +
        "'favorite', 0, 65537, 218866788)");
    store->ExecuteSql(string("INSERT INTO gallery_media VALUES(3, -4, ") +
        "'/storage/emulated/0/Pictures/hiddenAlbum/bins/0/xxx','hidden.jpg', 'hidden', null, 2716337, 0, 0, 1, " +
        "1495961420646, 1546937461, 2976, 3968, 'hidden', 0, 65537, 218866788)");
    store->ExecuteSql(string("INSERT INTO gallery_media VALUES(4, 4, ") +
        "'/storage/emulated/0/Pictures/.Gallery2/recycle/bins/0/xx', 'trashed.jpg', 'trashed', null, 2454477, " +
        "1698397634260, 0, 1, 1495959683996, 1546937461, 2976, 3968, 'trashed', 0, 65537, 218866788)");
    store->ExecuteSql(string("INSERT INTO gallery_media VALUES(5, 5, ") +
        "'/storage/emulated/0/Pictures/orientation.jpg', 'orientation.jpg', 'orientation', null, 2781577, 0, 0," +
        " 1, 1495962070277, 1698397638, 2448, 3264, 'orientation', 270, 65537, 218866788)");
    store->ExecuteSql(string("INSERT INTO gallery_media VALUES(6, 6, ") +
        "'/storage/emulated/0/BaiduMap/cache/fake_garbage_baidu.jpg', 'fake_garbage_baidu.jpg', " +
        "'fake_garbage_baidu', null, 2160867, 0, 0, 1, 1495954569032, 1546937461, 2976, 3968, " +
        "'fake_garbage_baidu', 0, 65537, -1492241466)");
    store->ExecuteSql(string("INSERT INTO garbage_album VALUES('baidu', '/BaiduMap/cache', ") +
        "null, null, 1, -1492241466);");
    store->ExecuteSql("INSERT INTO garbage_album VALUES(null, null, 'wechat', '/tencent/MicroMsg/WeiXin', 0, null);");
}

void InitMediaDB()
{
    const string dbPath = TEST_ORIGIN_PATH + "/" + MEDIA_LIBRARY_APP_NAME + "/ce/databases/media_library.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    GalleryMediaOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    photosStorePtr = store;
    std::unique_ptr<UpdateRestore> restoreService = std::make_unique<UpdateRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME);
    restoreService->Init(TEST_ORIGIN_PATH, TEST_UPDATE_FILE_DIR, false);
    std::vector<FileInfo> fileInfos = restoreService -> QueryFileInfos(0);
    restoreService -> InitGarbageAlbum();
    for (size_t i = 0; i < fileInfos.size(); i++) {
        const NativeRdb::ValuesBucket values = restoreService -> GetInsertValue(fileInfos[i], TEST_ORIGIN_PATH);
        int64_t rowNum = 0;
        if (photosStorePtr -> Insert(rowNum, "Photos", values) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s", fileInfos[i].filePath.c_str());
        }
    }
}

void MediaLibraryBackupTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    InitGalleryDB();
    InitMediaDB();
}

void MediaLibraryBackupTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

// SetUp:Execute before each test case
void MediaLibraryBackupTest::SetUp() {}

void MediaLibraryBackupTest::TearDown(void) {}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_init, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_init start");
    std::unique_ptr<UpdateRestore> restoreService = std::make_unique<UpdateRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME);
    int32_t result = restoreService->Init(TEST_ORIGIN_PATH, TEST_UPDATE_FILE_DIR, false);
    EXPECT_EQ(result, 0);
    MEDIA_INFO_LOG("medialib_backup_test_init end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_query_total_number, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number start");
    std::unique_ptr<UpdateRestore> restoreService = std::make_unique<UpdateRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME);
    restoreService->Init(TEST_ORIGIN_PATH, TEST_UPDATE_FILE_DIR, false);
    int32_t number = restoreService -> QueryTotalNumber();
    EXPECT_EQ(number, EXPECTED_NUM);
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_trashed, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed start");
    std::string queryTrashed = "SELECT file_id, date_trashed from Photos where display_name 'trashed.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryTrashed);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        int64_t trashedTime = GetInt64Val("data_trashed", resultSet);
        EXPECT_GT(trashedTime, 0);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_favorite, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite start");
    std::string queryFavorite = "SELECT file_id, is_favorite from Photos where display_name 'favorite.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryFavorite);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        int32_t isFavorite = GetInt32Val("is_favorite", resultSet);
        EXPECT_EQ(isFavorite, 1);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_hidden, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden start");
    std::string queryHidden = "SELECT file_id, hidden from Photos where display_name 'hidden.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryHidden);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        int32_t isHidden = GetInt32Val("hidden", resultSet);
        EXPECT_EQ(isHidden, 1);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_orientation, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation start");
    std::string queryOrientation = "SELECT file_id, orientation from Photos where display_name 'orientation.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryOrientation);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        int32_t orientation = GetInt32Val("orientation", resultSet);
        EXPECT_EQ(orientation, EXPECTED_OREINTATION);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_package_name, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name start");
    std::string queryPackageName = "SELECT file_id, package_name from Photos where display_name 'fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryPackageName);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        std::string packageName = GetStringVal("package_name", resultSet);
        EXPECT_EQ(packageName, EXPECTED_PACKAGE_NAME);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_user_comment, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment start");
    std::string queryUserComment = "SELECT file_id, user_comment from Photos where display_name 'fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryUserComment);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultsql is null.");
        return;
    }
    if (resultSet -> GoToNextRow() == NativeRdb::E_OK) {
        std::string userComment = GetStringVal("user_comment", resultSet);
        EXPECT_EQ(userComment, EXPECTED_USER_COMMENT);
    }
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment end");
}
} // namespace Media
} // namespace OHOS