/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_backup_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#define private public
#define protected public
#include "backup_const_map.h"
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "external_source.h"
#include "gallery_source.h"
#include "media_log.h"
#include "upgrade_restore.h"
#include "media_file_utils.h"
#undef private
#undef protected

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const std::string TEST_BACKUP_PATH = "/data/test/backup/db";
const std::string TEST_UPGRADE_FILE_DIR = "/data/test/backup/file";
const std::string GALLERY_APP_NAME = "gallery";
const std::string MEDIA_APP_NAME = "external";
const std::string MEDIA_LIBRARY_APP_NAME = "medialibrary";

const int EXPECTED_NUM = 30;
const int EXPECTED_OREINTATION = 270;
const std::string EXPECTED_PACKAGE_NAME = "wechat";
const std::string EXPECTED_USER_COMMENT = "user_comment";
const int64_t EXPECTED_DATE_ADDED = 1432973383179;
const int64_t EXPECTED_DATE_TAKEN = 1432973383;
const int64_t TEST_TRUE_MEDIAID = 1;
const int64_t TEST_FALSE_MEDIAID = -1;

const string PhotosOpenCall::CREATE_PHOTOS = string("CREATE TABLE IF NOT EXISTS Photos ") +
    " (file_id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT, title TEXT, display_name TEXT, size BIGINT," +
    " media_type INT, date_added BIGINT, date_taken BIGINT, duration INT, is_favorite INT default 0, " +
    " date_trashed BIGINT DEFAULT 0, hidden INT DEFAULT 0, height INT, width INT, user_comment TEXT, " +
    " orientation INT DEFAULT 0, package_name TEXT);";

const string PhotosOpenCall::CREATE_PHOTOS_ALBUM = "CREATE TABLE IF NOT EXISTS PhotoAlbum \
    (album_id INTEGER PRIMARY KEY AUTOINCREMENT, album_type INT,   \
    album_subtype INT, album_name TEXT COLLATE NOCASE, cover_uri TEXT, count \
    INT DEFAULT 0, date_modified BIGINT DEFAULT 0, dirty INT DEFAULT  1  , cloud_id TEXT,  \
    relative_path TEXT, contains_hidden INT DEFAULT 0, hidden_count INT DEFAULT 0,  \
    hidden_cover TEXT DEFAULT '', album_order INT,  image_count INT DEFAULT 0,  \
    video_count INT DEFAULT 0, bundle_name TEXT, local_language TEXT,  \
    is_local INT)";

const string PhotosOpenCall::CREATE_PHOTOS_MAP = "CREATE TABLE IF NOT EXISTS  PhotoMap \
    (map_album INT, map_asset INT, dirty INT DEFAULT 1, PRIMARY KEY (map_album, map_asset))";

int PhotosOpenCall::OnCreate(RdbStore &store)
{
    int ret = 0;
    ret += store.ExecuteSql(CREATE_PHOTOS);
    ret += store.ExecuteSql(CREATE_PHOTOS_ALBUM);
    ret += store.ExecuteSql(CREATE_PHOTOS_MAP);
    return ret;
}

int PhotosOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

std::shared_ptr<NativeRdb::RdbStore> photosStorePtr = nullptr;
std::unique_ptr<UpgradeRestore> restoreService = nullptr;

void InitPhotoAlbum()
{
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (0, 1, 'test101');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'TmallPic');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, '美图贴贴');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'funnygallery');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'xiaohongshu');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'Douyin');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'save');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'Weibo');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'Camera');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'Screenshots');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) \
        VALUES (1024, 2049, 'Screenrecorder');");
    photosStorePtr->ExecuteSql("INSERT INTO PhotoAlbum (album_type, album_subtype,album_name) VALUES (1024, 2049,'" +
        GetDUALBundleName() + " Share');");
}

void Init(GallerySource &gallerySource, ExternalSource &externalSource)
{
    MEDIA_INFO_LOG("start init galleryDb");
    const string galleryDbPath = TEST_BACKUP_PATH + "/" + GALLERY_APP_NAME + "/ce/databases/gallery.db";
    gallerySource.Init(galleryDbPath);
    MEDIA_INFO_LOG("end init galleryDb");
    MEDIA_INFO_LOG("start init externalDb");
    const string externalDbPath = TEST_BACKUP_PATH + "/" + MEDIA_APP_NAME + "/ce/databases/external.db";
    externalSource.Init(externalDbPath);
    MEDIA_INFO_LOG("end init externalDb");
    const string dbPath = TEST_BACKUP_PATH + "/" + MEDIA_LIBRARY_APP_NAME + "/ce/databases/media_library.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    PhotosOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    photosStorePtr = store;
    InitPhotoAlbum();
    restoreService = std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, UPGRADE_RESTORE_ID);
    restoreService->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, false);
    restoreService->InitGarbageAlbum();
    restoreService->HandleClone();
}

void RestoreFromGallery()
{
    std::vector<FileInfo> fileInfos = restoreService->QueryFileInfos(0);
    for (size_t i = 0; i < fileInfos.size(); i++) {
        const NativeRdb::ValuesBucket values = restoreService->GetInsertValue(fileInfos[i], TEST_BACKUP_PATH,
            SourceType::GALLERY);
        int64_t rowNum = 0;
        if (photosStorePtr->Insert(rowNum, "Photos", values) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s", fileInfos[i].filePath.c_str());
        }
    }
}

void RestoreFromExternal(GallerySource &gallerySource, bool isCamera)
{
    MEDIA_INFO_LOG("start restore from %{public}s", (isCamera ? "camera" : "others"));
    int32_t maxId = BackupDatabaseUtils::QueryInt(gallerySource.galleryStorePtr_, isCamera ?
        QUERY_MAX_ID_CAMERA_SCREENSHOT : QUERY_MAX_ID_OTHERS, CUSTOM_MAX_ID);
    int32_t type = isCamera ? SourceType::EXTERNAL_CAMERA : SourceType::EXTERNAL_OTHERS;
    std::vector<FileInfo> fileInfos = restoreService->QueryFileInfosFromExternal(0, maxId, isCamera);
    MEDIA_INFO_LOG("%{public}d asset will restor, maxid: %{public}d", (int)fileInfos.size(), maxId);
    for (size_t i = 0; i < fileInfos.size(); i++) {
        const NativeRdb::ValuesBucket values = restoreService->GetInsertValue(fileInfos[i], TEST_BACKUP_PATH,
            type);
        int64_t rowNum = 0;
        if (photosStorePtr->Insert(rowNum, "Photos", values) != E_OK) {
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
    std::unique_ptr<UpgradeRestore> restoreService = std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME,
        UPGRADE_RESTORE_ID);
    int32_t result = restoreService->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, false);
    EXPECT_EQ(result, 0);
    MEDIA_INFO_LOG("medialib_backup_test_init end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_query_total_number, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number start");
    std::unique_ptr<UpgradeRestore> restoreService = std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME,
        UPGRADE_RESTORE_ID);
    restoreService->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, false);
    int32_t number = restoreService->QueryTotalNumber();
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number %{public}d", number);
    EXPECT_EQ(number, EXPECTED_NUM);
    MEDIA_INFO_LOG("medialib_backup_test_query_total_number end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_trashed, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed start");
    std::string queryTrashed = "SELECT file_id, date_trashed from Photos where display_name ='trashed.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int64_t trashedTime = GetInt64Val("date_trashed", resultSet);
    EXPECT_GT(trashedTime, 0);
    MEDIA_INFO_LOG("medialib_backup_test_valid_trashed end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_favorite, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite start");
    std::string queryFavorite = "SELECT file_id, is_favorite from Photos where display_name ='favorite.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryFavorite);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int32_t isFavorite = GetInt32Val("is_favorite", resultSet);
    EXPECT_EQ(isFavorite, 1);
    MEDIA_INFO_LOG("medialib_backup_test_valid_favorite end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_hidden, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden start");
    std::string queryHidden = "SELECT file_id, hidden from Photos where display_name ='hidden.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryHidden);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int32_t isHidden = GetInt32Val("hidden", resultSet);
    EXPECT_EQ(isHidden, 1);
    MEDIA_INFO_LOG("medialib_backup_test_valid_hidden end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_orientation, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation start");
    std::string queryOrientation = "SELECT file_id, orientation from Photos where display_name ='orientation.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryOrientation);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int32_t orientation = GetInt32Val("orientation", resultSet);
    EXPECT_EQ(orientation, EXPECTED_OREINTATION);
    MEDIA_INFO_LOG("medialib_backup_test_valid_orientation end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_package_name, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name start");
    std::string queryPackageName = "SELECT file_id, package_name from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryPackageName);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    std::string packageName = GetStringVal("package_name", resultSet);
    EXPECT_EQ(packageName, "");
    MEDIA_INFO_LOG("medialib_backup_test_valid_package_name end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_user_comment, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment start");
    std::string queryUserComment = "SELECT file_id, user_comment from Photos where display_name ='user_common.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryUserComment);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    std::string userComment = GetStringVal("user_comment", resultSet);
    EXPECT_EQ(userComment, EXPECTED_USER_COMMENT);
    MEDIA_INFO_LOG("medialib_backup_test_valid_user_comment end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_date_added, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_added start");
    std::string queryDateAdded = "SELECT file_id, date_added from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryDateAdded);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int64_t dateAdded = GetInt64Val("date_added", resultSet);
    EXPECT_EQ(dateAdded, EXPECTED_DATE_ADDED);
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_added end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_valid_date_taken, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_taken start");
    std::string queryDateTaken = "SELECT file_id, date_taken from Photos where display_name ='fake_wechat.jpg'";
    auto resultSet = photosStorePtr-> QuerySql(queryDateTaken);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    int64_t dateTaken = GetInt64Val("date_taken", resultSet);
    EXPECT_EQ(dateTaken, EXPECTED_DATE_TAKEN);
    MEDIA_INFO_LOG("medialib_backup_test_valid_date_taken end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_valid, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_valid start");
    std::string queryNotSyncValid = "SELECT file_id from Photos where display_name ='not_sync_weixin.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_valid end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_invalid, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_invalid start");
    std::string queryNotSyncInvalid =
        "SELECT file_id from Photos where display_name ='not_sync_invalid.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncInvalid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_invalid end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_pending_camera, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_pending_camera start");
    std::string queryNotSyncPendingCamera =
        "SELECT file_id from Photos where display_name ='not_sync_pending_camera.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncPendingCamera);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_pending_camera end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_sync_pending_others, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_pending_others start");
    std::string queryNotSyncPendingOthers =
        "SELECT file_id from Photos where display_name ='not_sync_pending_others.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncPendingOthers);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_sync_pending_others end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_not_restore_size_0, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_not_restore_size_0 start");
    std::string queryNotSyncPendingOthers =
        "SELECT file_id from Photos where display_name ='zero_size.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncPendingOthers);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_not_restore_size_0 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_create_asset_path_by_id, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_create_asset_path_by_id start");
    int32_t uniqueId = 2;
    int32_t fileType = 1;
    std::string extension = "jpg";
    std::string cloudPath;
    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    std::string dir = RESTORE_CLOUD_DIR + "/" + to_string(uniqueId) + "/IMG_" +
        to_string(MediaFileUtils::UTCTimeSeconds()) + "_00" + to_string(uniqueId) + "." + extension;
    int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileType, extension, cloudPath);
    MEDIA_INFO_LOG("dir: %{public}s, cloudPath: %{public}s", dir.c_str(), cloudPath.c_str());
    ASSERT_TRUE(dir == cloudPath);
    MEDIA_INFO_LOG("medialib_backup_test_create_asset_path_by_id end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_update_clone, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_update_clone start");
    int32_t uniqueId = 2;
    int32_t fileType = 1;
    std::string extension = "jpg";
    std::string cloudPath;
    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    std::string dir = RESTORE_CLOUD_DIR + "/" + to_string(uniqueId) + "/IMG_" +
        to_string(MediaFileUtils::UTCTimeSeconds()) + "_00" + to_string(uniqueId) + "." + extension;
    int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileType, extension, cloudPath);
    MEDIA_INFO_LOG("dir: %{public}s, cloudPath: %{public}s", dir.c_str(), cloudPath.c_str());
    ASSERT_TRUE(dir == cloudPath);
    MEDIA_INFO_LOG("medialib_backup_test_update_clone end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_a_media_not_sync_valid, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_a_media_not_sync_valid start");
    std::string queryNotSyncValid = "SELECT file_id from Photos where display_name ='a_media_not_sync.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_a_media_not_sync_valid end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_a_media_favorite_video, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_a_media_favorite_video start");
    std::string queryNotSyncValid = "SELECT file_id from Photos where display_name ='a_media_favorite.mp4'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_a_media_favorite_video end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_a_media_favorite_image, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_a_media_favorite_video start");
    std::string queryNotSyncValid = "SELECT file_id from Photos where display_name ='a_media_favorite.mp4'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_a_media_favorite_video end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_a_media_zero_size, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_a_media_zero_size start");
    std::string queryNotSyncValid = "SELECT file_id from Photos where display_name ='a_media_zero_size.jpg'";
    auto resultSet = photosStorePtr->QuerySql(queryNotSyncValid);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_a_media_zero_size end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_modify_file, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_test_modify_file start");
    struct stat bufBefore;
    const char *path = "/data/test/backup/1.txt";
    stat(path, &bufBefore);
    int64_t beforeModifiedTime = MediaFileUtils::Timespec2Millisecond(bufBefore.st_mtim);
    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    struct utimbuf buf;
    buf.actime = currentTime;
    buf.modtime = currentTime;
    utime(path, &buf);
    struct stat bufAfter;
    stat(path, &bufAfter);
    int64_t afterModifiedTime = MediaFileUtils::Timespec2Millisecond(bufAfter.st_mtim);
    ASSERT_TRUE(afterModifiedTime != beforeModifiedTime);
    MEDIA_INFO_LOG("medialib_backup_test_modify_file end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_CreateAssetPathById_mediaType_audio, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_CreateAssetPathById_mediaType_audio start");
    int32_t uniqueId = 2;
    int32_t fileType = 3;
    std::string extension = "mp3";
    std::string cloudPath;
    int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileType, extension, cloudPath);
    EXPECT_EQ(errCode, E_OK);
    MEDIA_INFO_LOG("BackupFileUtils_CreateAssetPathById_mediaType_audio end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_CreateAssetPathById_mediaType_video, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_CreateAssetPathById_mediaType_video start");
    int32_t uniqueId = 2;
    int32_t fileType = 2;
    std::string extension = "mp4";
    std::string cloudPath;
    int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileType, extension, cloudPath);
    EXPECT_EQ(errCode, E_OK);
    MEDIA_INFO_LOG("BackupFileUtils_CreateAssetPathById_mediaType_video end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_GetFileNameFromPath_path_empty, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_path_empty start");
    string path;
    string res = BackupFileUtils::GetFileNameFromPath(path);
    EXPECT_EQ(res, "");
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_path_empty end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_GetFileNameFromPath_path_not_have, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_path_not_have start");
    string path = "test";
    string res = BackupFileUtils::GetFileNameFromPath(path);
    EXPECT_EQ(res, "");
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_path_not_have end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_GetFileNameFromPath_ok, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_ok start");
    string path = "test/ee/ee";
    string res = BackupFileUtils::GetFileNameFromPath(path);
    EXPECT_NE(res, "");
    MEDIA_INFO_LOG("BackupFileUtils_GetFileNameFromPath_ok end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_GetFileTitle_dispalyName_empty, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_GetFileTitle_dispalyName_empty start");
    string displayName;
    string res = BackupFileUtils::GetFileTitle(displayName);
    EXPECT_EQ(res, "");
    MEDIA_INFO_LOG("BackupFileUtils_GetFileTitle_dispalyName_empty end");
}

HWTEST_F(MediaLibraryBackupTest, BackupFileUtils_GetFileTitle_ok, TestSize.Level0)
{
    MEDIA_INFO_LOG("BackupFileUtils_GetFileTitle_ok start");
    string displayName = "test.mp3";
    string res = BackupFileUtils::GetFileTitle(displayName);
    EXPECT_NE(res, "");
    MEDIA_INFO_LOG("BackupFileUtils_GetFileTitle_ok end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_sceneCode_UPGRADE_RESTORE_ID, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_sceneCode_UPGRADE_RESTORE_ID start");
    restoreService->RestoreAudio();
    std::string queryAudio = "SELECT file_id from Audios where display_name ='audio1.mp3'";
    auto resultSet = photosStorePtr->QuerySql(queryAudio);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("RestoreAudio_sceneCode_UPGRADE_RESTORE_ID end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_sceneCode_Clone, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_sceneCode_Clone start");
    restoreService->sceneCode_ = DUAL_FRAME_CLONE_RESTORE_ID;
    restoreService->RestoreAudio();
    std::string queryAudio = "SELECT file_id from Audios where display_name ='audio1.mp3'";
    auto resultSet = photosStorePtr->QuerySql(queryAudio);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("RestoreAudio_sceneCode_Clone end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_RestoreAudioBatch_clone_no_audioRdb, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_RestoreAudioBatch_clone_no_db start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->RestoreAudioBatch(0);
    std::string queryAudio = "SELECT file_id from Audios where display_name ='audio1.mp3'";
    auto resultSet = photosStorePtr->QuerySql(queryAudio);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("RestoreAudio_RestoreAudioBatch_clone_no_db end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_RestoreAudioBatch_clone_fake_audiodb, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_RestoreAudioBatch_clone_fake_audiodb start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->audioRdb_ = photosStorePtr;
    upgrade->RestoreAudioBatch(0);
    std::string queryAudio = "SELECT file_id from Audios where display_name ='audio1.mp3'";
    auto resultSet = photosStorePtr->QuerySql(queryAudio);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("RestoreAudio_RestoreAudioBatch_clone_no_db end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_ParseResultSetFromAudioDb_return_false, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_ParseResultSetFromAudioDb_return_false start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    FileInfo info;
    bool res = upgrade->ParseResultSetFromAudioDb(resultSet, info);
    EXPECT_NE(res, true);
    MEDIA_INFO_LOG("RestoreAudio_ParseResultSetFromAudioDb_return_false end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_GetAudioInsertValues_fileInfos_empty, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_GetAudioInsertValues_fileInfos_empty start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    std::vector<FileInfo> fileInfos;
    auto res = upgrade->GetAudioInsertValues(0, fileInfos);
    EXPECT_EQ(res.size(), 0);
    MEDIA_INFO_LOG("RestoreAudio_GetAudioInsertValues_fileInfos_empty end");
}

HWTEST_F(MediaLibraryBackupTest, RestoreAudio_GetAudioInsertValues_file_not_exit, TestSize.Level0)
{
    MEDIA_INFO_LOG("RestoreAudio_GetAudioInsertValues_file_not_exit start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    std::vector<FileInfo> fileInfos;
    FileInfo info;
    fileInfos.push_back(info);
    NativeRdb::ValuesBucket value;
    upgrade->SetAudioValueFromMetaData(info, value);
    auto res = upgrade->GetAudioInsertValues(0, fileInfos);
    EXPECT_EQ(res.size(), 0);
    MEDIA_INFO_LOG("RestoreAudio_GetAudioInsertValues_file_not_exit end");
}


HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test001 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test001 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'test001';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test001 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test001 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test002 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test002 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'test002';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test002 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test003 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test003 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'test003';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test003 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test003 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test004 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test004 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'TmallPic';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test004 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test004 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test005 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test005 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'UCDownloads';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test005 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test005 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test006 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test006 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name  = 'xiaohongshu';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test006 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test006 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test007 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test007 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Douyin';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test007 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test007 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test008 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test008 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Weibo';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test008 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test008 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test009 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test009 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Camera';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'camera1.jpg';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test009 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test009 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test010 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test010 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Screenshots';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'screenshots1.jpg';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test010 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test010 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test011 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test011 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Screenrecorder';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'screenrecorder1.mp4';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test011 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test011 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test012 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test012 start");
    restoreService->RestorePhoto();
    std::string sql = "SELECT album_id from PhotoAlbum where album_name = '" + GetDUALBundleName() + " Share';";
    auto resultSet = photosStorePtr->QuerySql(sql);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    sql = "SELECT file_id from Photos where display_name = '" + GetDUALBundleName() + "Share1.jpg';";
    resultSet = photosStorePtr->QuerySql(sql);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test012 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test012 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test101, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test101 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test101 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_type,album_subtype from PhotoAlbum where album_name = 'test101';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    int32_t album_type = GetInt32Val("album_type", resultSet);
    int32_t album_subtype = GetInt32Val("album_subtype", resultSet);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    EXPECT_EQ(album_type, 0);
    EXPECT_EQ(album_subtype, 0);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test101 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test101 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test102, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test102 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test102 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'TmallPic';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test102 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test102 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test103, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test103 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test103 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'MTTT';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test103 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test103 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test104, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test104 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test104 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'funnygallery';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test104 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test104 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test105, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test105 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test105 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'xiaohongshu';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test105 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test105 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test106, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test106 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test106 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Douyin';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test106 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test106 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test107, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test107 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test107 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'save';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test107 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test107 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test108, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test108 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test108 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Weibo';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test108 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test108 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test109, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test109 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test109 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Camera';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'camera2.jpg';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test109 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test109 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test110, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test110 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test110 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Screenshots';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'screenshots2.jpg';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test110 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test110 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test111, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test111 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test111 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = 'Screenrecorder';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = 'screenrecorder2.mp4';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test111 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test111 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ablum_test112, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test112 start";
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test112 start");
    restoreService->RestorePhoto();
    std::string queryTrashed = "SELECT album_id from PhotoAlbum where album_name = '" + GetDUALBundleName() +" Share';";
    auto resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_TRUE(resultSet->GoToNextRow() == NativeRdb::E_OK);

    queryTrashed = "SELECT file_id from Photos where display_name = '" + GetDUALBundleName() + "Share2.jpg';";
    resultSet = photosStorePtr->QuerySql(queryTrashed);
    ASSERT_FALSE(resultSet == nullptr);
    ASSERT_FALSE(resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("medialib_backup_test_ablum_test112 end");
    GTEST_LOG_(INFO) << "medialib_backup_test_ablum_test112 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InsertAudio_upgrade, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InsertAudio_upgrade start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaLibraryRdb_ = photosStorePtr;
    upgrade->migrateAudioDatabaseNumber_ = 0;
    std::vector<FileInfo> fileInfos;
    FileInfo fileInfo1;
    fileInfo1.filePath = "test";
    fileInfos.push_back(fileInfo1);
    FileInfo fileInfo2;
    fileInfo2.filePath = "/storage/cloud/100/files/Documents/CreateImageThumbnailTest_001.jpg";
    fileInfo2.cloudPath = "/storage/cloud/files/Audio/10/AUD_3322.jpg";
    fileInfos.push_back(fileInfo2);
    upgrade->InsertAudio(UPGRADE_RESTORE_ID, fileInfos);
    EXPECT_EQ(upgrade->migrateAudioDatabaseNumber_, 0);
    MEDIA_INFO_LOG("medialib_backup_InsertAudio_upgrade end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InsertAudio_clone, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InsertAudio_clone start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaLibraryRdb_ = photosStorePtr;
    upgrade->migrateAudioDatabaseNumber_ = 0;
    std::vector<FileInfo> fileInfos;
    FileInfo fileInfo1;
    fileInfo1.filePath = "test";
    fileInfos.push_back(fileInfo1);
    FileInfo fileInfo2;
    fileInfo2.filePath = "/storage/cloud/100/files/Documents/CreateImageThumbnailTest_001.jpg";
    fileInfo2.cloudPath = "/storage/cloud/files/Audio/10/AUD_3322.jpg";
    fileInfos.push_back(fileInfo2);
    upgrade->InsertAudio(DUAL_FRAME_CLONE_RESTORE_ID, fileInfos);
    EXPECT_EQ(upgrade->migrateAudioDatabaseNumber_, 0);
    MEDIA_INFO_LOG("medialib_backup_InsertAudio_clone end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_MoveDirectory, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_MoveDirectory start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string srcDir = "/data/test";
    string dstDir = "/data/test1";
    EXPECT_EQ(upgrade->MoveDirectory(srcDir, dstDir), 0);
    MEDIA_INFO_LOG("medialib_backup_MoveDirectory end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_BatchQueryPhoto, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_BatchQueryPhoto start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo1;
    fileInfo1.cloudPath = "test";
    fileInfo1.mediaAlbumId = TEST_FALSE_MEDIAID;
    fileInfos.push_back(fileInfo1);

    FileInfo fileInfo2;
    fileInfo2.cloudPath = "";
    fileInfo2.mediaAlbumId = TEST_FALSE_MEDIAID;
    fileInfos.push_back(fileInfo2);

    FileInfo fileInfo3;
    fileInfo3.cloudPath = "test";
    fileInfo3.mediaAlbumId = TEST_TRUE_MEDIAID;
    fileInfos.push_back(fileInfo3);

    FileInfo fileInfo4;
    fileInfo4.cloudPath = "";
    fileInfo4.mediaAlbumId = TEST_TRUE_MEDIAID;
    fileInfos.push_back(fileInfo4);
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->BatchQueryPhoto(fileInfos);
    EXPECT_EQ(fileInfos[0].fileIdNew, TEST_FALSE_MEDIAID);
    MEDIA_INFO_LOG("medialib_backup_BatchQueryPhoto end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_BatchInsertMap, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_BatchInsertMap start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo1;
    fileInfo1.cloudPath = "test";
    fileInfo1.mediaAlbumId = TEST_FALSE_MEDIAID;
    fileInfos.push_back(fileInfo1);

    FileInfo fileInfo2;
    fileInfo2.cloudPath = "";
    fileInfo2.mediaAlbumId = TEST_FALSE_MEDIAID;
    fileInfos.push_back(fileInfo2);

    FileInfo fileInfo3;
    fileInfo3.cloudPath = "test";
    fileInfo3.mediaAlbumId = TEST_TRUE_MEDIAID;
    fileInfo3.packageName = "testPackage";
    fileInfos.push_back(fileInfo3);

    FileInfo fileInfo4;
    fileInfo4.cloudPath = "";
    fileInfo4.mediaAlbumId = TEST_TRUE_MEDIAID;
    fileInfos.push_back(fileInfo4);

    FileInfo fileInfo5;
    fileInfo5.cloudPath = "test";
    fileInfo5.mediaAlbumId = TEST_TRUE_MEDIAID;
    fileInfo5.packageName = "";
    fileInfos.push_back(fileInfo5);

    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    int64_t totalRowNum = 0;
    upgrade->BatchInsertMap(fileInfos, totalRowNum);
    EXPECT_EQ(totalRowNum, 0);
    MEDIA_INFO_LOG("medialib_backup_BatchInsertMap end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateFileInfo_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    GalleryAlbumInfo galleryAlbumInfo;
    galleryAlbumInfo.albumCNName = SCREEN_SHOT_AND_RECORDER;
    FileInfo info;
    info.fileType = MediaType::MEDIA_TYPE_VIDEO;
    upgrade->mediaScreenreCorderAlbumId_ = TEST_TRUE_MEDIAID;
    upgrade->UpdateFileInfo(galleryAlbumInfo, info);
    EXPECT_EQ(info.packageName, VIDEO_SCREEN_RECORDER_NAME);
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateFileInfo_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    GalleryAlbumInfo galleryAlbumInfo;
    galleryAlbumInfo.albumCNName = SCREEN_SHOT_AND_RECORDER;
    FileInfo info;
    info.fileType = MediaType::MEDIA_TYPE_VIDEO;
    upgrade->mediaScreenreCorderAlbumId_ = TEST_TRUE_MEDIAID;
    upgrade->UpdateFileInfo(galleryAlbumInfo, info);
    EXPECT_EQ(info.packageName, VIDEO_SCREEN_RECORDER_NAME);
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateFileInfo_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_003 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    GalleryAlbumInfo galleryAlbumInfo;
    galleryAlbumInfo.albumCNName = SCREEN_SHOT_AND_RECORDER;
    FileInfo info;
    info.fileType = MediaType::MEDIA_TYPE_VIDEO;
    upgrade->mediaScreenreCorderAlbumId_ = TEST_TRUE_MEDIAID;
    upgrade->UpdateFileInfo(galleryAlbumInfo, info);
    EXPECT_EQ(info.packageName, VIDEO_SCREEN_RECORDER_NAME);
    MEDIA_INFO_LOG("medialib_backup_UpdateFileInfo_003 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InstertHiddenAlbum_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InstertHiddenAlbum_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string ablumIPath = "test";
    FileInfo info;
    upgrade->InstertHiddenAlbum(ablumIPath, info);
    EXPECT_EQ(info.packageName, "");
    MEDIA_INFO_LOG("medialib_backup_InstertHiddenAlbum_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InstertHiddenAlbum_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InstertHiddenAlbum_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string ablumIPath = "test/01";
    FileInfo info;
    upgrade->nickMap_["test/01"] = "1";
    upgrade->InstertHiddenAlbum(ablumIPath, info);
    EXPECT_EQ(info.packageName, "");
    MEDIA_INFO_LOG("medialib_backup_InstertHiddenAlbum_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateHiddenAlbumToMediaAlbumId_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateHiddenAlbumToMediaAlbumId_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string sourcePath = "/storage/emulated/0/test/001.jpg";
    FileInfo info;
    GalleryAlbumInfo galleryInfo;
    galleryInfo.albumlPath = "0";
    galleryInfo.mediaAlbumId = TEST_TRUE_MEDIAID;
    upgrade->galleryAlbumMap_["0"] = galleryInfo;

    GalleryAlbumInfo galleryInfo1;
    upgrade->galleryAlbumMap_["1"] = galleryInfo1;
    upgrade->UpdateHiddenAlbumToMediaAlbumId(sourcePath, info);
    EXPECT_EQ(info.mediaAlbumId, TEST_FALSE_MEDIAID);
    MEDIA_INFO_LOG("medialib_backup_UpdateHiddenAlbumToMediaAlbumId_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateHiddenAlbumToMediaAlbumId_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateHiddenAlbumToMediaAlbumId_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string sourcePath = "";
    FileInfo info;
    upgrade->UpdateHiddenAlbumToMediaAlbumId(sourcePath, info);
    EXPECT_EQ(info.packageName, "");
    MEDIA_INFO_LOG("medialib_backup_UpdateHiddenAlbumToMediaAlbumId_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateMediaScreenreCorderAlbumId_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateMediaScreenreCorderAlbumId_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaScreenreCorderAlbumId_ = TEST_FALSE_MEDIAID;
    upgrade->UpdateMediaScreenreCorderAlbumId();
    EXPECT_EQ(upgrade->photoAlbumInfos_.size(), 0);
    MEDIA_INFO_LOG("medialib_backup_UpdateMediaScreenreCorderAlbumId_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_UpdateMediaScreenreCorderAlbumId_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_UpdateMediaScreenreCorderAlbumId_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaScreenreCorderAlbumId_ = TEST_TRUE_MEDIAID;
    upgrade->UpdateMediaScreenreCorderAlbumId();
    EXPECT_EQ(upgrade->photoAlbumInfos_.size(), 0);
    MEDIA_INFO_LOG("medialib_backup_UpdateMediaScreenreCorderAlbumId_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_BatchQueryAlbum, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_BatchQueryAlbum start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    vector<GalleryAlbumInfo> galleryAlbumInfos;
    GalleryAlbumInfo galleryAlbumInfos1;
    galleryAlbumInfos1.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos.push_back(galleryAlbumInfos1);

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos2.albumMediaName = "test";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    GalleryAlbumInfo galleryAlbumInfos3;
    galleryAlbumInfos3.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos3.albumMediaName = "\test\2";
    galleryAlbumInfos.push_back(galleryAlbumInfos3);
    upgrade->BatchQueryAlbum(galleryAlbumInfos);
    EXPECT_EQ(upgrade->photoAlbumInfos_.size(), 0);
    MEDIA_INFO_LOG("medialib_backup_BatchQueryAlbum end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_BatchQueryAlbum_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_BatchQueryAlbum_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    vector<GalleryAlbumInfo> galleryAlbumInfos;
    GalleryAlbumInfo galleryAlbumInfos1;
    galleryAlbumInfos1.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos.push_back(galleryAlbumInfos1);

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos2.albumMediaName = "test";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    GalleryAlbumInfo galleryAlbumInfos3;
    galleryAlbumInfos3.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos3.albumMediaName = "\test\2";
    galleryAlbumInfos.push_back(galleryAlbumInfos3);
    upgrade->BatchQueryAlbum(galleryAlbumInfos);
    EXPECT_EQ(upgrade->photoAlbumInfos_.size(), 0);
    MEDIA_INFO_LOG("medialib_backup_BatchQueryAlbum_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_GetInsertValues_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_GetInsertValues_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    vector<GalleryAlbumInfo> galleryAlbumInfos;
    GalleryAlbumInfo galleryAlbumInfos1;
    galleryAlbumInfos1.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos.push_back(galleryAlbumInfos1);

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos2.albumListName = "test";
    galleryAlbumInfos2.albumCNName = "test";
    galleryAlbumInfos2.albumNickName = "test";
    galleryAlbumInfos2.albumENName = "test1";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    GalleryAlbumInfo galleryAlbumInfos3;
    galleryAlbumInfos3.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos.push_back(galleryAlbumInfos3);

    GalleryAlbumInfo galleryAlbumInfos4;
    galleryAlbumInfos4.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos4.albumListName = "test";
    galleryAlbumInfos.push_back(galleryAlbumInfos4);

    bool bInsertScreenreCorderAlbum = true;
    upgrade->GetInsertValues(galleryAlbumInfos, bInsertScreenreCorderAlbum);
    EXPECT_EQ(galleryAlbumInfos[1].albumMediaName, "test");
    MEDIA_INFO_LOG("medialib_backup_GetInsertValues_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_GetInsertValues_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_GetInsertValues_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    vector<GalleryAlbumInfo> galleryAlbumInfos;

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos2.albumENName = "test1";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    bool bInsertScreenreCorderAlbum = false;
    upgrade->GetInsertValues(galleryAlbumInfos, bInsertScreenreCorderAlbum);
    EXPECT_EQ(galleryAlbumInfos[0].albumMediaName, "test1");
    MEDIA_INFO_LOG("medialib_backup_GetInsertValues_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InsertAlbum_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InsertAlbum_001 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaLibraryRdb_ = photosStorePtr;
    vector<GalleryAlbumInfo> galleryAlbumInfos;

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_TRUE_MEDIAID;
    galleryAlbumInfos2.albumENName = "test1";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    bool bInsertScreenreCorderAlbum = false;
    upgrade->InsertAlbum(galleryAlbumInfos, bInsertScreenreCorderAlbum);
    EXPECT_EQ(galleryAlbumInfos[0].albumMediaName, "");
    MEDIA_INFO_LOG("medialib_backup_InsertAlbum_001 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_InsertAlbum_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("medialib_backup_InsertAlbum_002 start");
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    upgrade->mediaLibraryRdb_ = photosStorePtr;
    vector<GalleryAlbumInfo> galleryAlbumInfos;

    GalleryAlbumInfo galleryAlbumInfos2;
    galleryAlbumInfos2.mediaAlbumId = TEST_FALSE_MEDIAID;
    galleryAlbumInfos2.albumENName = "test1";
    galleryAlbumInfos.push_back(galleryAlbumInfos2);

    bool bInsertScreenreCorderAlbum = true;
    upgrade->InsertAlbum(galleryAlbumInfos, bInsertScreenreCorderAlbum);
    EXPECT_EQ(galleryAlbumInfos[0].albumMediaName, "test1");
    MEDIA_INFO_LOG("medialib_backup_InsertAlbum_002 end");
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ParseXml_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_001 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "/data/test/backup/test.xml";
    auto res = upgrade->ParseXml(xmlPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_001 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ParseXml_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_002 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "/data/test/backup/test1.xml";
    auto res = upgrade->ParseXml(xmlPath);
    EXPECT_EQ(res, -1);
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_002 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ParseXml_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_003 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "/data/test/backup/test2.xml";
    auto res = upgrade->ParseXml(xmlPath);
    EXPECT_EQ(res, -1);
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_003 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ParseXml_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_004 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "/data/test/backup/test3.xml";
    auto res = upgrade->ParseXml(xmlPath);
    EXPECT_EQ(res, -1);
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_004 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_ParseXml_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_005 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "/data/test/backup/test4.xml";
    auto res = upgrade->ParseXml(xmlPath);
    EXPECT_EQ(res, -1);
    GTEST_LOG_(INFO) << "medialib_backup_test_ParseXml_005 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_StringToInt_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_001 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "";
    auto res = upgrade->StringToInt(xmlPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_001 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_StringToInt_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_002 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "   22e";
    auto res = upgrade->StringToInt(xmlPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_002 end";
}

HWTEST_F(MediaLibraryBackupTest, medialib_backup_test_StringToInt_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_003 start";
    std::unique_ptr<UpgradeRestore> upgrade =
        std::make_unique<UpgradeRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, DUAL_FRAME_CLONE_RESTORE_ID);
    string xmlPath = "777777777777777777777777777777777777777777777777777";
    auto res = upgrade->StringToInt(xmlPath);
    EXPECT_EQ(res, 0);
    GTEST_LOG_(INFO) << "medialib_backup_test_StringToInt_003 end";
}
} // namespace Media
} // namespace OHOS