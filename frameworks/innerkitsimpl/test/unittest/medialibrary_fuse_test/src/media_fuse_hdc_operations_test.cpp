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
#define MLOG_TAG "MediaFuseHdcOperationsTest"
#include <gtest/gtest.h>
#include "medialibrary_errno.h"
#include "media_fuse_hdc_operations.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_uri.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "rdb_utils.h"

using namespace testing;
using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {
class MediaFuseHdcOperationsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;
static int32_t ClearTable(const string &table)
{
    NativeRdb::RdbPredicates predicates(table);
    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear photos table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void MediaFuseHdcOperationsTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void MediaFuseHdcOperationsTest::TearDownTestCase(void)
{
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void MediaFuseHdcOperationsTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
}

void MediaFuseHdcOperationsTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static const string SQL_CREATE_ALBUM = "INSERT INTO " + PhotoAlbumColumns::TABLE + "(" +
    PhotoAlbumColumns::ALBUM_TYPE + ", " + PhotoAlbumColumns::ALBUM_SUBTYPE + ", " +
    PhotoAlbumColumns::ALBUM_NAME + ", " + PhotoAlbumColumns::ALBUM_DATE_MODIFIED + ", " +
    PhotoAlbumColumns::ALBUM_IS_LOCAL + ", " + PhotoAlbumColumns::ALBUM_DATE_ADDED + ", " +
    PhotoAlbumColumns::ALBUM_LPATH + ", " + PhotoAlbumColumns::ALBUM_PRIORITY + ")";

static void CreateAlbum(const std::string &albumName)
{
    // album_type, album_subtype, album_name, date_modified, is_local, date_added, lpath, priority
    g_rdbStore->ExecuteSql(SQL_CREATE_ALBUM + "VALUES (0, 1, '"+
        albumName + "', 1748354341383, 1 , 1748354341383, '/Pictures/Users/" + albumName + "', 1)");
}

static const string SQL_INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" +
    MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
    MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
    MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
    MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
    MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_POSITION + ", " +
    PhotoColumn::PHOTO_SHOOTING_MODE + ", " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + ")";

static void InsertAssetIntoPhotosTable(const string& data, const string& title, int32_t albumId)
{
    // data, size, title, display_name, media_type,position
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, date_trashed, hidden
    // height, width, edit_time, position, shooting_mode, owner_album_id
    g_rdbStore->ExecuteSql(SQL_INSERT_PHOTO + "VALUES ('" + data + "', 175258, '" + title + "', '" +
        title + ".jpg', 1, 'com.ohos.camera', '相机', 1748423617814, 1748424146785, 1748424146785, 0, 0, 0, 0, " +
        "1280, 960, 0, 1, '1', " + to_string(albumId) + ")"); // cam, pic, shootingmode = 1
}

static shared_ptr<NativeRdb::ResultSet> QueryAsset(const string& table, const string& key, const string& value,
    const vector<string>& columns)
{
    NativeRdb::RdbPredicates rdbPredicates(table);
    rdbPredicates.EqualTo(key, value);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file asset");
        return nullptr;
    }
    return resultSet;
}

static void AssetsPrepare(int32_t& albumId, string& uri)
{
    // 1、创建相册
    string albumName = "test01";
    CreateAlbum(albumName);
    vector<string> columns;
    auto resultSet = QueryAsset(PhotoAlbumColumns::TABLE, PhotoAlbumColumns::ALBUM_NAME, "test01", columns);
    if (resultSet == nullptr) {
        return;
    }

    albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    if (albumId <= 0) {
        return;
    }

    // 2、插入一条数据照片到相册
    string title = "testPhoto";
    string data = "/storage/cloud/files/Photo/9/IMG_1748505946_009.jpg";
    InsertAssetIntoPhotosTable(data, title, albumId);
    resultSet = QueryAsset(PhotoColumn::PHOTOS_TABLE, MediaColumn::MEDIA_NAME, title + ".jpg", columns);
    if (resultSet == nullptr) {
        return;
    }

    string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    if (displayName.size() <= 0) {
        return;
    }

    int32_t fileId = GetInt32Val(PhotoColumn::MEDIA_ID, resultSet);
    string path = GetStringVal(PhotoColumn::MEDIA_FILE_PATH, resultSet);
    uri = MediaFileUri::GetPhotoUri(to_string(fileId), path, displayName);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetArgs_test_001, Level1)
{
    std::string path = "/Photo/Album1/photo.jpg";
    std::vector<std::string> parts;
    int32_t ret = MediaFuseHdcOperations::GetArgs(path, parts);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(parts.size(), 3);
    EXPECT_EQ(parts[0], "Photo");
    EXPECT_EQ(parts[1], "Album1");
    EXPECT_EQ(parts[2], "photo.jpg");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetArgs_test_002, Level1)
{
    std::string path = "/Invalid/photo.jpg";
    std::vector<std::string> parts;
    int32_t ret = MediaFuseHdcOperations::GetArgs(path, parts);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_test_001, Level1)
{
    std::string input = "/Photo/Album1/photo.jpg";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_test_002, Level1)
{
    std::string input = "/Photo/Album1/photo";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_test_003, Level1)
{
    std::string input = "";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_test_004, Level1)
{
    std::string input = "/Photo/Album1/";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_test_005, Level1)
{
    std::string input = "photo.jpg";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_006, Level1)
{
    std::string input = "/Photo/.hidden";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ExtractFileNameAndExtension_007, Level1)
{
    std::string input = "/Photo/file.";
    std::string outName, outExt;
    int32_t ret = MediaFuseHdcOperations::ExtractFileNameAndExtension(input, outName, outExt);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_JpgToMp4_test_001, Level1)
{
    std::string displayName = "photo.jpg";
    std::string videoName = MediaFuseHdcOperations::JpgToMp4(displayName);
    EXPECT_EQ(videoName, "photo.mp4");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_JpgToMp4_test_002, Level1)
{
    std::string displayName = "photo.PNG";
    std::string videoName = MediaFuseHdcOperations::JpgToMp4(displayName);
    EXPECT_EQ(videoName, "photo.mp4");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_JpgToMp4_test_003, Level1)
{
    std::string displayName = "photo";
    std::string videoName = MediaFuseHdcOperations::JpgToMp4(displayName);
    EXPECT_EQ(videoName, "photo.mp4");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_JpgToMp4_test_004, Level1)
{
    std::string displayName = "";
    std::string videoName = MediaFuseHdcOperations::JpgToMp4(displayName);
    EXPECT_EQ(videoName, "");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_IsImageOrVideoFile_test_001, Level1)
{
    std::string fileName = "test.jpg";
    bool ret = MediaFuseHdcOperations::IsImageOrVideoFile(fileName);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_IsImageOrVideoFile_test_002, Level1)
{
    std::string fileName = "test.mp4";
    bool ret = MediaFuseHdcOperations::IsImageOrVideoFile(fileName);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_IsImageOrVideoFile_test_003, Level1)
{
    std::string fileName = "test.txt";
    bool ret = MediaFuseHdcOperations::IsImageOrVideoFile(fileName);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetPathFromDisplayname_test_001, Level1)
{
    std::string filePath;
    int32_t ret = MediaFuseHdcOperations::GetPathFromDisplayname("", 1, filePath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetPathFromDisplayname_test_002, Level1)
{
    std::string filePath;
    int32_t ret = MediaFuseHdcOperations::GetPathFromDisplayname("invalid.jpg", 1, filePath);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_IsMovingPhoto_test_001, Level1)
{
    int32_t subtype = 0;
    int32_t effectMode = 0;
    bool ret = MediaFuseHdcOperations::IsMovingPhoto(subtype, effectMode);
    EXPECT_FALSE(ret);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleRootOrPhoto_test_001, Level1)
{
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleRootOrPhoto("/", &stbuf);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleRootOrPhoto_test_002, Level1)
{
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleRootOrPhoto("/Photo", &stbuf);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleRootOrPhoto_test_003, Level1)
{
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleRootOrPhoto("/Other", &stbuf);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleLstat_test_001, Level1)
{
    std::string localPath = "/data";
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleLstat(localPath, &stbuf);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleLstat_test_002, Level1)
{
    std::string localPath = "/not_exist_path_123456";
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleLstat(localPath, &stbuf);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetAlbumIdFromAlbumName_test_001, Level1)
{
    int32_t albumId = 0;
    int32_t ret = MediaFuseHdcOperations::GetAlbumIdFromAlbumName("", albumId);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_Parse_test_001, Level1)
{
    std::string path = "/Photo";
    int32_t albumId = -1;
    std::string filePath;
    std::string displayName;
    int32_t ret = MediaFuseHdcOperations::Parse(path, albumId, filePath, displayName);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleMovingPhoto_test_001, Level1)
{
    std::string filePath;
    std::string displayName = "";
    int32_t albumId = 1;
    int32_t ret = MediaFuseHdcOperations::HandleMovingPhoto(filePath, displayName, albumId);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleMovingPhoto_test_002, Level1)
{
    std::string filePath;
    std::string displayName = "photo.jpg";
    int32_t albumId = 1;
    int32_t ret = MediaFuseHdcOperations::HandleMovingPhoto(filePath, displayName, albumId);
    EXPECT_LT(ret, 0);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleFstat_test_001, Level1)
{
    fuse_file_info fi;
    fi.fh = 0;
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleFstat(reinterpret_cast<const struct fuse_file_info*>(&fi), &stbuf);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleFstat_test_002, Level1)
{
    fuse_file_info fi;
    fi.fh = -1;
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleFstat(reinterpret_cast<const struct fuse_file_info*>(&fi), &stbuf);
    EXPECT_LT(ret, 0);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleDirStat_test_001, Level1)
{
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandleDirStat(-1, &stbuf);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandlePhotoPath_test_001, Level1)
{
    std::string inputPath = "NotPhotoAlbum";
    int32_t albumId = 0;
    std::string localPath;
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandlePhotoPath(inputPath, albumId, localPath, &stbuf);
    EXPECT_LT(ret, 0);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandlePhotoPath_test_002, Level1)
{
    std::string inputPath = "Photo/photo.jpg";
    int32_t albumId = 0;
    std::string localPath;
    struct stat stbuf = {};
    int32_t ret = MediaFuseHdcOperations::HandlePhotoPath(inputPath, albumId, localPath, &stbuf);
    EXPECT_LT(ret, 0);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_HandleFilePath_test_001, Level1)
{
    std::vector<std::string> args = {"Album2", "photo.jpg"};
    int32_t albumId = 0;
    std::string localPath;
    int32_t ret = MediaFuseHdcOperations::HandleFilePath(args, albumId, localPath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ConvertToLocalPhotoPath_test_001, Level1)
{
    std::string inputPath = "";
    std::string output;
    int32_t ret = MediaFuseHdcOperations::ConvertToLocalPhotoPath(inputPath, output);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ConvertToLocalPhotoPath_test_002, Level1)
{
    std::string inputPath = "/invalid/path/photo.jpg";
    std::string output;
    int32_t ret = MediaFuseHdcOperations::ConvertToLocalPhotoPath(inputPath, output);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ConvertToLocalPhotoPath_test_003, Level1)
{
    std::string inputPath = "/storage/cloud/files/Photo/Album1/photo.jpg";
    std::string output;
    int32_t ret = MediaFuseHdcOperations::ConvertToLocalPhotoPath(inputPath, output);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(output, "/storage/media/local/files/Photo/Album1/photo.jpg");
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_CreateFd_test_001, Level1)
{
    std::string displayName = "";
    int32_t albumId = 1;
    int32_t fd = -1;
    int32_t ret = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_CreateFd_test_002, Level1)
{
    std::string displayName = "photo.jpg";
    int32_t albumId = 1;
    int32_t fd = -1;
    int32_t ret = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
    EXPECT_EQ(ret, E_SUCCESS);
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_CreateFd_test_003, Level1)
{
    std::string displayName = "video.mp4";
    int32_t albumId = 1;
    int32_t fd = -1;
    int32_t ret = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
    EXPECT_EQ(ret, E_SUCCESS);
    ClearTable(PhotoAlbumColumns::TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_CreateFd_test_004, Level1)
{
    std::string displayName = "1.txt";
    int32_t albumId = 1;
    int32_t fd = -1;
    int32_t ret = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_UpdatePhotoRdb_test_001, Level1)
{
    std::string displayName = "invalid/name.jpg";
    std::string filePath = "";
    int32_t ret = MediaFuseHdcOperations::UpdatePhotoRdb(displayName, filePath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_UpdatePhotoRdb_test_002, Level1)
{
    std::string displayName = "photo.jpg";
    std::string filePath = "";
    int32_t ret = MediaFuseHdcOperations::UpdatePhotoRdb(displayName, filePath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_UpdatePhotoRdb_test_003, Level1)
{
    std::string displayName = "photo.jpg";
    std::string filePath = "/storage/media/local/files/Photo/Album1/photo.jpg";
    int32_t ret = MediaFuseHdcOperations::UpdatePhotoRdb(displayName, filePath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ScanFileByPath_test_001, Level1)
{
    std::string path = "";
    int32_t ret = MediaFuseHdcOperations::ScanFileByPath(path);
    EXPECT_EQ(ret, -EINVAL);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ScanFileByPath_test_002, Level1)
{
    std::string path = "/Photo";
    int32_t ret = MediaFuseHdcOperations::ScanFileByPath(path);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_ReadPhotoRootDir_test_001, Level1)
{
    void *buf = nullptr;
    fuse_fill_dir_t filler = nullptr;
    off_t offset = 0;
    int32_t ret = MediaFuseHdcOperations::ReadPhotoRootDir(buf, filler, offset);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_DeletePhotoByFilePath_test_001, Level1)
{
    std::string filePath = "";
    int32_t ret = MediaFuseHdcOperations::DeletePhotoByFilePath(filePath);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_GetAlbumMTime_test_001, Level1)
{
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    time_t mtime = MediaFuseHdcOperations::GetAlbumMTime(resultSet);
    EXPECT_GT(mtime, 0);
}

HWTEST_F(MediaFuseHdcOperationsTest, MediaLibrary_OperationsSuccess_test_001, Level1)
{
    int32_t albumId = -1;
    string uri = "";
    AssetsPrepare(albumId, uri);
    std::string displayName = "testPhoto.jpg";
    std::string albumName = "test01";
    std::string path = "/Photo/test01/testPhoto.jpg";
    std::string filePath;
    int32_t ret = MediaFuseHdcOperations::GetPathFromDisplayname(displayName, albumId, filePath);
    EXPECT_EQ(ret, E_SUCCESS);
    std::string fileId;
    ret = MediaFuseHdcOperations::GetFileIdFromPath(filePath, fileId);
    EXPECT_EQ(ret, E_SUCCESS);
    ret = MediaFuseHdcOperations::GetAlbumIdFromAlbumName(albumName, albumId);
    EXPECT_EQ(ret, E_SUCCESS);
    ret = MediaFuseHdcOperations::Parse(path, albumId, filePath, displayName);
    EXPECT_EQ(ret, E_SUCCESS);
    struct stat stbuf = {};
    ret = MediaFuseHdcOperations::HandleDirStat(albumId, &stbuf);
    EXPECT_EQ(ret, E_SUCCESS);
    std::vector<std::string> args = {"test01", "testPhoto.jpg"};
    std::string localPath;
    ret = MediaFuseHdcOperations::UpdatePhotoRdb(displayName, filePath);
    EXPECT_EQ(ret, E_SUCCESS);
    ret = MediaFuseHdcOperations::ScanFileByPath(path);
    EXPECT_EQ(ret, E_SUCCESS);
    ret = MediaFuseHdcOperations::DeletePhotoByFilePath(filePath);
    EXPECT_EQ(ret, E_SUCCESS);
}
} // namespace Media
} // namespace OHOS
