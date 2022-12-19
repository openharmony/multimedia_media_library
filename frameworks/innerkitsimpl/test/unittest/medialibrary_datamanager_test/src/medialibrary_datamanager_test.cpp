/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FileExtUnitTest"

#include "medialibrary_datamanager_test.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "uri.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
    shared_ptr<FileAsset> g_pictures = nullptr;
    shared_ptr<FileAsset> g_download = nullptr;
}

void MediaLibraryDataManagerUnitTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryDataManagerUnitTest::TearDownTestCase(void) {}

void MediaLibraryDataManagerUnitTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::InitRootDirs();
    g_pictures = MediaLibraryUnitTestUtils::GetRootAsset(TEST_PICTURES);
    g_download = MediaLibraryUnitTestUtils::GetRootAsset(TEST_DOWNLOAD);
}

void MediaLibraryDataManagerUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_CreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_CreateAsset_Test_001::Start");
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "CreateAsset_Test_001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(createAssetUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_CreateAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_CloseAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_CloseAsset_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("OpenFile_test_001.jpg", g_pictures, fileAsset), true);
    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(closeAssetUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("DataManager_CloseAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_IsDirectory_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_IsDirectory_Test_001::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("IsDirectory_Test_001", g_pictures, albumAsset), true);
    Uri isDirectoryUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_ISDIRECTORY);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, albumAsset->GetId());
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(isDirectoryUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("DataManager_IsDirectory_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_IsDirectory_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_IsDirectory_Test_002::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("IsDirectory_Test_002.jpg", g_pictures, fileAsset), true);
    Uri isDirectoryUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_ISDIRECTORY);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(isDirectoryUri, valuesBucket);
    EXPECT_EQ(retVal, E_CHECK_DIR_FAIL);
    MEDIA_INFO_LOG("DataManager_IsDirectory_Test_002::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_CreateAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_CreateAlbum_Test_001::Start");
    Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
    DataShare::DataShareValuesBucket valuesBucket;
    string dirPath = ROOT_MEDIA_DIR + "Pictures/CreateAlbum_Test_001/";
    valuesBucket.Put(MEDIA_DATA_DB_NAME, "CreateAlbum_Test_001");
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, dirPath);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(createAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_CreateAlbum_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_CreateDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_CreateDir_Test_001::Start");
    Uri createDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/CreateDir_Test_001/";
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(createDirUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_CreateDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_TrashDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashDir_Test_001::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("TrashDir_Test_001", g_pictures, albumAsset), true);
    Uri trashDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_TRASHDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, albumAsset->GetId());
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(trashDirUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_TrashDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_Favorite_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_Favorite_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Favorite_Test_001.jpg", g_pictures, fileAsset), true);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, FAVOURITE_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileAsset->GetId());
    Uri addSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(addSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    Uri removeSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    retVal = MediaLibraryDataManager::GetInstance()->Insert(removeSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_Favorite_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_Trash_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_Trash_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Trash_Test_001.jpg", g_pictures, fileAsset), true);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileAsset->GetId());
    Uri addSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(addSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    Uri removeSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    retVal = MediaLibraryDataManager::GetInstance()->Insert(removeSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_Trash_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_Insert_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_Insert_Test_001::Start");
    Uri insertUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, "DataManager_Insert_Test_001");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(insertUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_Insert_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_DeleteAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_DeleteAsset_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("DeleteAsset_Test_001.jpg", g_pictures, fileAsset), true);
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET +
        '/' + to_string(fileAsset->GetId()));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(fileAsset->GetId()));
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(deleteAssetUri, predicates);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("DataManager_DeleteAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_QueryDirTable_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_QueryDirTable_Test_001::Start");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIATYPE_DIRECTORY_TABLE);
    auto resultSet = MediaLibraryDataManager::GetInstance()->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_QueryAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_QueryAlbum_Test_001::Start");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM);
    auto resultSet = MediaLibraryDataManager::GetInstance()->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_QueryVolume_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_QueryVolume_Test_001::Start");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    auto resultSet = MediaLibraryDataManager::GetInstance()->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_QueryFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_QueryFiles_Test_001::Start");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = MediaLibraryDataManager::GetInstance()->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_UpdateFileAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_UpdateFileAsset_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("UpdateFileAsset_Test_001.jpg", g_pictures, fileAsset), true);
    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_NAME, "UpdateAsset_Test_001.jpg");
    valuesBucketUpdate.Put(MEDIA_DATA_DB_TITLE, "UpdateAsset_Test_001");
    valuesBucketUpdate.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + to_string(fileAsset->GetId()));
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucketUpdate, predicates);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("DataManager_UpdateFileAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_UpdateAlbumAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_UpdateAlbumAsset_Test_001::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("UpdateAlbumAsset_Test_001", g_pictures, albumAsset), true);
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_ID + " = " + to_string(albumAsset->GetId());
    predicates.SetWhereClause(prefix);
    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.Put(MEDIA_DATA_DB_MEDIA_TYPE, albumAsset->GetMediaType());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_URI, albumAsset->GetUri());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_RELATIVE_PATH, albumAsset->GetRelativePath());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_ALBUM_NAME, "U" + albumAsset->GetDisplayName());
    MEDIA_INFO_LOG("DataManager_UpdateAlbumAsset_Test_001::GetUri = %{public}s", albumAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucketUpdate, predicates);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("DataManager_UpdateAlbumAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryDataManagerUnitTest, DataManager_OpenFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_OpenFile_Test_001::Start");
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("OpenFile_Test_001.jpg", g_pictures, fileAsset), true);
    string fileUri = fileAsset->GetUri();
    string mode = MEDIA_FILEMODE_READONLY;
    Uri openFileUri(fileUri);
    MEDIA_INFO_LOG("openFileUri = %{public}s", openFileUri.ToString().c_str());
    int32_t fd = MediaLibraryDataManager::GetInstance()->OpenFile(openFileUri, mode);
    EXPECT_EQ(fd > 0, true);
    if (fd > 0) {
        close(fd);
    }
    MEDIA_INFO_LOG("DataManager_OpenFile_Test_001::fd = %{public}d. End", fd);
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_File_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_001::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_File_001", g_download, albumAsset);
    shared_ptr<FileAsset> fileAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_001.txt", albumAsset, fileAsset);

    MediaLibraryUnitTestUtils::TrashFile(fileAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(fileAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_001::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_File_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_002::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_File_002", g_download, albumAsset);
    shared_ptr<FileAsset> fileAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_002.txt", albumAsset, fileAsset);

    MediaLibraryUnitTestUtils::TrashFile(fileAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_002.txt", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(fileAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_002::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_File_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_003::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_File_003", g_download, albumAsset);
    shared_ptr<FileAsset> fileAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_003.txt", albumAsset, fileAsset);

    MediaLibraryUnitTestUtils::TrashFile(fileAsset);
    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(fileAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_003::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_File_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_004::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_File_004", g_download, albumAsset);
    shared_ptr<FileAsset> fileAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_004.txt", albumAsset, fileAsset);

    MediaLibraryUnitTestUtils::TrashFile(fileAsset);
    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_File_004", g_download, tempAsset);
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_File_004.txt", tempAsset, tempAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(fileAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_File_Test_004::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_Dir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_001::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_001", g_download, albumAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_001.txt", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_001", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_001.txt", tempAsset, tempAsset);

    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(albumAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_001::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_Dir_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_002::Start");
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_002", g_download, albumAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_002.txt", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_002", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_002.txt", tempAsset, tempAsset);

    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_002", g_download, tempAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(albumAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_002::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_Dir_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_003::Start");
    shared_ptr<FileAsset> parentAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_003", g_download, parentAsset);
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_003", parentAsset, albumAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_003.txt", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_003", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_003.txt", tempAsset, tempAsset);

    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    MediaLibraryUnitTestUtils::TrashFile(parentAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(albumAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_003::End");
}

HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_TrashRecovery_Dir_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_004::Start");
    shared_ptr<FileAsset> parentAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_004", g_download, parentAsset);
    shared_ptr<FileAsset> albumAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_004", parentAsset, albumAsset);
    shared_ptr<FileAsset> tempAsset = nullptr;
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_004.txt", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_004", albumAsset, tempAsset);
    MediaLibraryUnitTestUtils::CreateFile("TrashRecovery_Dir_004.txt", tempAsset, tempAsset);

    MediaLibraryUnitTestUtils::TrashFile(albumAsset);
    MediaLibraryUnitTestUtils::TrashFile(parentAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_004", g_download, parentAsset);
    MediaLibraryUnitTestUtils::CreateAlbum("TrashRecovery_Dir_004", parentAsset, tempAsset);
    MediaLibraryUnitTestUtils::RecoveryFile(albumAsset);
    MEDIA_INFO_LOG("DataManager_TrashRecovery_Dir_Test_004::End");
}

/**
 * @tc.number    : DataManager_Delete_Dir_Test_001
 * @tc.name      : test delete dir: normal case
 * @tc.desc      : 1.Create the parent album to be deleted: Delete_Dir_001
 *                 2.Create album in Delete_Dir_002: Delete_Dir_002/dir1
 *                 3.Create file in dir1: Delete_Dir_002/dir1/file2.txt
 *                 4.Create album in dir1: Delete_Dir_002/dir1/dir2
 *                 5.Create file in dir2: Delete_Dir_002/dir1/dir2/file3.txt
 *                 6.Trash file3.txt
 *                 7.Trash dir1
 *                 8.Trash Delete_Dir_002
 *                 8.Delete Delete_Dir_002
 */
HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_Delete_Dir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_001::Start");
    shared_ptr<FileAsset> Delete_Dir_001 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("Delete_Dir_001", g_download, Delete_Dir_001));
    shared_ptr<FileAsset> dir1 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("Delete_Dir_001", Delete_Dir_001, dir1));
    shared_ptr<FileAsset> file2 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateFile("Delete_Dir_001.txt", dir1, file2));
    shared_ptr<FileAsset> dir2 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("Delete_Dir_001", dir1, dir2));
    shared_ptr<FileAsset> file3 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateFile("Delete_Dir_001.txt", dir2, file3));

    string deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + "/" +
        to_string(Delete_Dir_001->GetId());
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_001::deleteUri: %s", deleteUri.c_str());
    Uri deleteAssetUri(deleteUri);
    int retVal = MediaLibraryDataManager::GetInstance()->Delete(deleteAssetUri, {});
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_001::delete end, retVal: %d", retVal);
}

/**
 * @tc.number    : DataManager_Delete_Dir_Test_002
 * @tc.name      : test delete dir: exists trashed children
 * @tc.desc      : 1.Create the parent album to be deleted: Delete_Dir_002
 *                 2.Create album in Delete_Dir_002: Delete_Dir_002/dir1
 *                 3.Create file in dir1: Delete_Dir_002/dir1/file2.txt
 *                 4.Create album in dir1: Delete_Dir_002/dir1/dir2
 *                 5.Create file in dir2: Delete_Dir_002/dir1/dir2/file3.txt
 *                 6.Trash file3.txt
 *                 7.Trash dir1
 *                 8.Trash Delete_Dir_002
 *                 8.Delete Delete_Dir_002
 */
HWTEST_F( MediaLibraryDataManagerUnitTest, DataManager_Delete_Dir_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_002::Start");
    shared_ptr<FileAsset> Delete_Dir_002 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("Delete_Dir_002", g_download, Delete_Dir_002));
    shared_ptr<FileAsset> dir1 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("dir1", Delete_Dir_002, dir1));
    shared_ptr<FileAsset> file2 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateFile("file2.txt", dir1, file2));
    shared_ptr<FileAsset> dir2 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateAlbum("dir2", dir1, dir2));
    shared_ptr<FileAsset> file3 = nullptr;
    ASSERT_TRUE(MediaLibraryUnitTestUtils::CreateFile("file3.txt", dir2, file3));

    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_002::trash start");
    MediaLibraryUnitTestUtils::TrashFile(file3);
    MediaLibraryUnitTestUtils::TrashFile(dir1);
    MediaLibraryUnitTestUtils::TrashFile(Delete_Dir_002);

    string deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + "/" +
        to_string(Delete_Dir_002->GetId());
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_002::deleteUri: %s", deleteUri.c_str());
    Uri deleteAssetUri(deleteUri);
    int retVal = MediaLibraryDataManager::GetInstance()->Delete(deleteAssetUri, {});
    MEDIA_INFO_LOG("DataManager_Delete_Dir_Test_002::delete end, retVal: %d", retVal);
}
} // namespace Media
} // namespace OHOS
