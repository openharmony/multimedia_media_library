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

#include "backup_database_utils.h"
#include "external_source.h"
#include "gallery_source.h"
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
const std::string GALLERY_APP_NAME = "gallery";
const std::string MEDIA_APP_NAME = "external";
const std::string MEDIA_LIBRARY_APP_NAME = "medialibrary";

const int EXPECTED_NUM = 5;
const int EXPECTED_OREINTATION = 270;
const std::string EXPECTED_PACKAGE_NAME = "wechat";
const std::string EXPECTED_USER_COMMENT = "fake_wechat";
const int64_t EXPECTED_DATE_ADDED = 1432973383;
const int64_t EXPECTED_DATE_TAKEN = 1432973383;

class PhotosOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_PHOTOS;
};

const string PhotosOpenCall::CREATE_PHOTOS = string("CREATE TABLE IF NOT EXISTS Photos ") +
    " (file_id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT, title TEXT, display_name TEXT, size BIGINT," +
    " media_type INT, date_added BIGINT, date_taken BIGINT, duration INT, is_favorite INT default 0, " +
    " date_trashed BIGINT DEFAULT 0, hidden INT DEFAULT 0, height INT, width INT, user_comment TEXT, " +
    " orientation INT DEFAULT 0, package_name TEXT);";

int PhotosOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_PHOTOS);
}

int PhotosOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<NativeRdb::RdbStore> photosStorePtr = nullptr;
std::unique_ptr<UpdateRestore> restoreService = nullptr;

void Init(GallerySource &gallerySource, ExternalSource &externalSource)
{
    MEDIA_INFO_LOG("start init galleryDb");
    const string galleryDbPath = TEST_ORIGIN_PATH + "/" + GALLERY_APP_NAME + "/ce/databases/gallery.db";
    gallerySource.Init(galleryDbPath);
    MEDIA_INFO_LOG("end init galleryDb");
    MEDIA_INFO_LOG("start init externalDb");
    const string externalDbPath = TEST_ORIGIN_PATH + "/" + MEDIA_APP_NAME + "/ce/databases/external.db";
    externalSource.Init(externalDbPath);
    MEDIA_INFO_LOG("end init externalDb");
    const string dbPath = TEST_ORIGIN_PATH + "/" + MEDIA_LIBRARY_APP_NAME + "/ce/databases/media_library.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    PhotosOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    photosStorePtr = store;
    restoreService = std::make_unique<UpdateRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME);
    restoreService->Init(TEST_ORIGIN_PATH, TEST_UPDATE_FILE_DIR, false);
    restoreService -> InitGarbageAlbum();
}

void RestoreFromGallery()
{
    std::vector<FileInfo> fileInfos = restoreService -> QueryFileInfos(0);
    for (size_t i = 0; i < fileInfos.size(); i++) {
        const NativeRdb::ValuesBucket values = restoreService -> GetInsertValue(fileInfos[i], TEST_ORIGIN_PATH,
            SourceType::GALLERY);
        int64_t rowNum = 0;
        if (photosStorePtr -> Insert(rowNum, "Photos", values) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s", fileInfos[i].filePath.c_str());
        }
    }
}

void RestoreFromExternal(GallerySource &gallerySource, bool isCamera)
{
    MEDIA_INFO_LOG("start restore from %{public}s", (isCamera ? "camera" : "others"));
    int32_t maxId = BackupDatabaseUtils::QueryInt(gallerySource.galleryStorePtr_, isCamera ?
        QUERY_MAX_ID_CAMERA_SCREENSHOT : QUERY_MAX_ID_OTHERS, MAX_ID);
    int32_t type = isCamera ? SourceType::EXTERNAL_CAMERA : SourceType::EXTERNAL_OTHERS;
    std::vector<FileInfo> fileInfos = restoreService -> QueryFileInfosFromExternal(0, maxId, isCamera);
    for (size_t i = 0; i < fileInfos.size(); i++) {
        const NativeRdb::ValuesBucket values = restoreService -> GetInsertValue(fileInfos[i], TEST_ORIGIN_PATH,
            type);
        int64_t rowNum = 0;
        if (photosStorePtr -> Insert(rowNum, "Photos", values) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s", fileInfos[i].filePath.c_str());
        }
    }
}

void MediaLibraryBackupTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    GallerySource gallerySource;
    ExternalSource externalSource;
    Init(gallerySource, externalSource);
    RestoreFromGallery();
    RestoreFromExternal(gallerySource, true);
    RestoreFromExternal(gallerySource, false);
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
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number %{public}d", number);
    EXPECT_EQ(number, EXPECTED_NUM);
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_trashed, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed start");
    std::string queryTrashed = "SELECT file_id, date_trashed from Photos where display_name ='trashed.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int64_t trashedTime = GetInt64Val("date_trashed", resultSet);
    EXPECT_GT(trashedTime, 0);
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_favorite, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite start");
    std::string queryFavorite = "SELECT file_id, is_favorite from Photos where display_name ='favorite.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryFavorite);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int32_t isFavorite = GetInt32Val("is_favorite", resultSet);
    EXPECT_EQ(isFavorite, 1);
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_hidden, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden start");
    std::string queryHidden = "SELECT file_id, hidden from Photos where display_name ='hidden.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryHidden);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int32_t isHidden = GetInt32Val("hidden", resultSet);
    EXPECT_EQ(isHidden, 1);
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_orientation, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation start");
    std::string queryOrientation = "SELECT file_id, orientation from Photos where display_name ='orientation.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryOrientation);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int32_t orientation = GetInt32Val("orientation", resultSet);
    EXPECT_EQ(orientation, EXPECTED_OREINTATION);
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_package_name, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name start");
    std::string queryPackageName = "SELECT file_id, package_name from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryPackageName);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    std::string packageName = GetStringVal("package_name", resultSet);
    EXPECT_EQ(packageName, EXPECTED_PACKAGE_NAME);
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_user_comment, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment start");
    std::string queryUserComment = "SELECT file_id, user_comment from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryUserComment);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    std::string userComment = GetStringVal("user_comment", resultSet);
    EXPECT_EQ(userComment, EXPECTED_USER_COMMENT);
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_date_added, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_added start");
    std::string queryDateAdded = "SELECT file_id, date_added from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryDateAdded);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int64_t dateAdded = GetInt64Val("date_added", resultSet);
    EXPECT_EQ(dateAdded, EXPECTED_DATE_ADDED);
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_added end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_date_taken, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_taken start");
    std::string queryDateTaken = "SELECT file_id, date_taken from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryDateTaken);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    int64_t dateTaken = GetInt64Val("date_taken", resultSet);
    EXPECT_EQ(dateTaken, EXPECTED_DATE_TAKEN);
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_taken end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_valid, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_valid start");
    std::string queryNotSyncValid = "SELECT file_id, date_taken from Photos where display_name ='not_sync_valid.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_valid end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_invalid, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_invalid start");
    std::string queryNotSyncInvalid = "SELECT file_id, date_taken from Photos where display_name ='not_sync_invalid.jpg'";
    auto resultSet = photosStorePtr -> QuerySql(queryNotSyncInvalid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet -> GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_invalid end");
}
} // namespace Media
} // namespace OHOS