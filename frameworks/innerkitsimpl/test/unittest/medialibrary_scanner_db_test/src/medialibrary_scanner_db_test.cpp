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
#include "medialibrary_device.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_scanner_db_test.h"
#include "medialibrary_unittest_utils.h"
#include "thumbnail_utils.h"
#define private public
#include "media_scanner_db.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class ConfigTestOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_TABLE_TEST;
};

const string ConfigTestOpenCall::CREATE_TABLE_TEST = string("CREATE TABLE IF NOT EXISTS test ") +
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<NativeRdb::RdbStore> storePtr = nullptr;
void MediaLibraryExtUnitTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_scanner_db_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    storePtr = store;

    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryExtUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp()
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
}

void MediaLibraryExtUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteMetadata_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    vector<string> idList;
    bool ret = mediaScannerDb.DeleteMetadata(idList);
    EXPECT_NE(ret, true);
    vector<string> idListTest = {"DeleteMetadata"};
    ret = mediaScannerDb.DeleteMetadata(idListTest);
    EXPECT_NE(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_NotifyDatabaseChange_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    MediaType mediaType = MEDIA_TYPE_AUDIO;
    mediaScannerDb.NotifyDatabaseChange(mediaType);
    auto scannerTest =  MediaScannerDb::GetDatabaseInstance();
    EXPECT_NE(scannerTest, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ReadAlbums_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    unordered_map<string, Metadata> albumMap_;
    string path = "/storage/cloud/files/";
    int32_t ret = mediaScannerDb.ReadAlbums(path, albumMap_);
    EXPECT_EQ(ret, E_OK);
    string pathTest = "";
    ret = mediaScannerDb.ReadAlbums(pathTest, albumMap_);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ReadError_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    vector<string> ret = mediaScannerDb.ReadError();
    EXPECT_EQ(ret.size(), 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_InsertMetadata_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    mediaScannerDb.SetRdbHelper();
    Metadata metadata;
    bool setScannedId = false;
    string ret = mediaScannerDb.InsertMetadata(metadata, setScannedId);
    EXPECT_NE(ret, "");
    int32_t parentId = 1;
    string albumPath = "/storage/cloud/files/";
    string albumName = "InsertMetadata";
    int32_t albumId = UNKNOWN_ID;
    struct stat statInfo;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);
    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);
    metadata.SetFileId(albumId);
    ret = mediaScannerDb.InsertMetadata(metadata, setScannedId);
    EXPECT_NE(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateAlbum_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    Metadata metadata;
    int32_t ret = mediaScannerDb.UpdateAlbum(metadata);
    EXPECT_NE(ret, 0);
    int32_t parentId = 1;
    string albumPath = "/storage/cloud/files/";
    string albumName = "UpdateAlbum";
    int32_t albumId = UNKNOWN_ID;
    struct stat statInfo;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);
    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);
    metadata.SetFileId(albumId);
    ret = mediaScannerDb.UpdateAlbum(metadata);
    EXPECT_NE(ret, 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteError_test_001, TestSize.Level0)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaScannerDb mediaScannerDb;
    string err = "";
    int32_t ret = mediaScannerDb.DeleteError(err);
    EXPECT_EQ(ret, E_OK);
    string errTest = "DeleteError";
    ret = mediaScannerDb.DeleteError(err);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_RecordError_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    string err = "";
    int32_t ret = mediaScannerDb.RecordError(err);
    EXPECT_EQ(ret, E_OK);
    ret = mediaScannerDb.RecordError(err);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_InsertMetadata_test_002, TestSize.Level0)
{
    MediaLibraryUnitTestUtils::Init();
    MediaScannerDb mediaScannerDb;
    mediaScannerDb.SetRdbHelper();
    Metadata metadata;
    int32_t parentId = 1;
    string albumPath = "/storage/cloud/files/";
    string albumName = "InsertMetadata";
    int32_t albumId = UNKNOWN_ID;
    struct stat statInfo;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);
    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);
    metadata.SetFileId(albumId);
    bool setScannedId = false;
    string ret = mediaScannerDb.InsertMetadata(metadata, setScannedId);
    EXPECT_NE(ret, "");
    unordered_map<string, Metadata> albumMap_;
    string pathTest = "";
    unordered_map<int32_t, MediaType> prevIdMap = mediaScannerDb.GetIdsFromFilePath(pathTest);
    EXPECT_GT(prevIdMap.size(), 0);
    string path = "/storage/cloud/files/";
    prevIdMap = mediaScannerDb.GetIdsFromFilePath(path);
    EXPECT_GT(prevIdMap.size(), 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ReadAlbums_test_002, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    unordered_map<string, Metadata> albumMap_;
    string path = "/storage/cloud/files/";
    int32_t ret = mediaScannerDb.ReadAlbums(path, albumMap_);
    EXPECT_EQ(ret, E_OK);
    string pathTest = "";
    ret = mediaScannerDb.ReadAlbums(pathTest, albumMap_);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ReadError_test_002, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    vector<string> ret = mediaScannerDb.ReadError();
    EXPECT_NE(ret.size(), 0);
    MediaLibraryUnitTestUtils::Init();
    ret = mediaScannerDb.ReadError();
    EXPECT_NE(ret.size(), 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteError_test_002, TestSize.Level0)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaScannerDb mediaScannerDb;
    string err = "";
    int32_t ret = mediaScannerDb.DeleteError(err);
    EXPECT_EQ(ret, E_OK);
    string errTest = "DeleteError";
    ret = mediaScannerDb.DeleteError(err);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetFileDBUriFromPath_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    string path = "";
    string uri = mediaScannerDb.GetFileDBUriFromPath(path);
    EXPECT_EQ(uri, "");
    string pathTest = "/storage/cloud/files/";
    uri = mediaScannerDb.GetFileDBUriFromPath(pathTest);
    EXPECT_EQ(uri, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_InsertAlbum_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    Metadata metadata;
    int32_t ret = mediaScannerDb.InsertAlbum(metadata);
    EXPECT_NE(ret, 0);
    int32_t parentId = 1;
    string albumPath = "/storage/cloud/files/";
    string albumName = "InsertAlbum";
    int32_t albumId = UNKNOWN_ID;
    struct stat statInfo;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);
    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);
    metadata.SetFileId(albumId);
    ret = mediaScannerDb.InsertAlbum(metadata);
    EXPECT_NE(ret, 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateMetadata_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    Metadata metadata;
    bool setScannedId = false;
    string ret = mediaScannerDb.UpdateMetadata(metadata, setScannedId);
    EXPECT_EQ(ret, "");
    int32_t parentId = 1;
    string albumPath = "/storage/cloud/files/";
    string albumName = "UpdateMetadata";
    int32_t albumId = UNKNOWN_ID;
    struct stat statInfo;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);
    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);
    metadata.SetFileId(albumId);
    ret = mediaScannerDb.UpdateMetadata(metadata, setScannedId);
    EXPECT_EQ(ret, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetIdFromPath_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    unordered_map<string, Metadata> albumMap_;
    string pathTest = "";
    int32_t id = mediaScannerDb.GetIdFromPath(pathTest);
    EXPECT_EQ(id, -1);
    string path = "/storage/cloud/files/";
    id = mediaScannerDb.GetIdFromPath(path);
    EXPECT_EQ(id, -1);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_BatchInsert_test_001, TestSize.Level0)
{
    MediaScannerDb mediaScannerDb;
    vector<Metadata> metadataList;
    Metadata metadata;
    vector<string> ret = mediaScannerDb.BatchInsert(metadataList);
    EXPECT_EQ(ret.size(), 0);
}

} // namespace Media
} // namespace OHOS