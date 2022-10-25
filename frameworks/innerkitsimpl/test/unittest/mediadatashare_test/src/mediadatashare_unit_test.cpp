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
#define MLOG_TAG "DataShareUnitTest"

#include "mediadatashare_unit_test.h"

#include "datashare_helper.h"
#include "fetch_result.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "system_ability_definition.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper;

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

void MediaDataShareUnitTest::SetUpTestCase(void)
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaDataShareUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    MEDIA_INFO_LOG("SetUpTestCase invoked");
    g_mediaDataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_TRUE(g_mediaDataShareHelper != nullptr);

    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " <> 0 ";
    predicates.SetWhereClause(selections);
    int retVal = g_mediaDataShareHelper->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("SetUpTestCase Delete retVal: %{public}d", retVal);
    EXPECT_EQ((retVal >= 0), true);
}

int32_t CreateFile(string displayName)
{
    MEDIA_INFO_LOG("CreateFile::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/" + displayName + "/";
    displayName += ".jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    int32_t retVal = helper->Insert(createAssetUri, valuesBucket);
    MEDIA_INFO_LOG("CreateFile::File: %{public}s, retVal: %{public}d", (relativePath + displayName).c_str(), retVal);
    EXPECT_EQ((retVal > 0), true);
    if (retVal <= 0) {
        retVal = E_FAIL;
    }
    MEDIA_INFO_LOG("CreateFile::retVal = %{public}d. End", retVal);
    return retVal;
}

int32_t CreateAlbum(string displayName)
{
    MEDIA_INFO_LOG("CreateAlbum::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
    DataShare::DataShareValuesBucket valuesBucket;
    string dirPath = ROOT_MEDIA_DIR + "Pictures/" + displayName;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, dirPath);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    auto retVal = helper->Insert(createAlbumUri, valuesBucket);
    MEDIA_INFO_LOG("CreateAlbum::Album: %{public}s, retVal: %{public}d", dirPath.c_str(), retVal);
    EXPECT_EQ((retVal > 0), true);
    if (retVal <= 0) {
        retVal = E_FAIL;
    }
    MEDIA_INFO_LOG("CreateAlbum::retVal = %{public}d. End", retVal);
    return retVal;
}

bool GetFileAsset(unique_ptr<FileAsset> &fileAsset, bool isAlbum, string displayName)
{
    int32_t index = E_FAIL;
    if (isAlbum) {
        index = CreateAlbum(displayName);
    } else {
        index = CreateFile(displayName);
    }
    if (index == E_FAIL) {
        MEDIA_ERR_LOG("GetFileAsset failed");
        return false;
    }
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " = " + to_string(index);
    predicates.SetWhereClause(selections);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::resultSet == nullptr");
        return false;
    }

    // Create FetchResult object using the contents of resultSet
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    if (fetchFileResult->GetCount() <= 0) {
        MEDIA_ERR_LOG("GetFileAsset::GetCount <= 0");
        return false;
    }

    fileAsset = fetchFileResult->GetFirstObject();
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::fileAsset = nullptr.");
        return false;
    }
    return true;
}

void MediaDataShareUnitTest::TearDownTestCase(void) {}
void MediaDataShareUnitTest::SetUp(void) {}
void MediaDataShareUnitTest::TearDown(void) {}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "CreateAsset_Test_001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    auto retVal = helper->Insert(createAssetUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CloseAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CloseAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "CloseAsset_Test_001")) {
        return;
    }
    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = helper->Insert(closeAssetUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_CloseAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_IsDirectory_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_IsDirectory_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, true, "IsDirectory_Test_001")) {
        return;
    }
    Uri isDirectoryUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_ISDIRECTORY);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = helper->Insert(isDirectoryUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_IsDirectory_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_IsDirectory_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_IsDirectory_Test_002::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "IsDirectory_Test_002")) {
        return;
    }
    Uri isDirectoryUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_ISDIRECTORY);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = helper->Insert(isDirectoryUri, valuesBucket);
    EXPECT_EQ(retVal, E_CHECK_DIR_FAIL);
    MEDIA_INFO_LOG("MediaDataShare_IsDirectory_Test_002::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAlbum_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
    DataShare::DataShareValuesBucket valuesBucket;
    string dirPath = ROOT_MEDIA_DIR + "Pictures/CreateAlbum_Test_001/";
    valuesBucket.Put(MEDIA_DATA_DB_NAME, "CreateAlbum_Test_001");
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, dirPath);
    auto retVal = helper->Insert(createAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateAlbum_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_DeleteDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_DeleteDir_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, true, "DeleteDir_Test_001")) {
        return;
    }
    Uri deleteDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_DELETEDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_PARENT_ID, fileAsset->GetId());
    auto retVal = helper->Insert(deleteDirUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_DeleteDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CheckDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CheckDir_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "CheckDir_Test_001")) {
        return;
    }
    Uri checkDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    auto retVal = helper->Insert(checkDirUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_CheckDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateDir_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/CreateDir_Test_001/";
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    auto retVal = helper->Insert(createDirUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_FMSDeleteDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_FMSDeleteDir_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "FMSDeleteDir_Test_001")) {
        return;
    }
    Uri deleteDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_DELETEDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    auto retVal = helper->Insert(deleteDirUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_FMSDeleteDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_TrashDir_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_TrashDir_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, true, "TrashDir_Test_001")) {
        return;
    }
    Uri trashDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_TRASHDIR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = helper->Insert(trashDirUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_TrashDir_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_SmartAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_SmartAlbum_Test_001::Create Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMOPRN + "/" +
        MEDIA_SMARTALBUMOPRN_CREATEALBUM);
    DataShare::DataShareValuesBucket createValuesBucket;
    createValuesBucket.Put(SMARTALBUM_DB_ID, 3);
    createValuesBucket.Put(SMARTALBUM_DB_ALBUM_TYPE, 3);
    createValuesBucket.Put(SMARTALBUM_DB_NAME, "TestAlbum001");
    auto retVal = helper->Insert(createSmartAlbumUri, createValuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_SmartAlbum_Test_001::Create End. retVal = %{public}d", retVal);
    MEDIA_INFO_LOG("MediaDataShare_SmartAlbum_Test_001::Delete Start");
    Uri deleteSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMOPRN + "/" +
        MEDIA_SMARTALBUMOPRN_DELETEALBUM);
    DataShare::DataShareValuesBucket deleteValuesBucket;
    deleteValuesBucket.Put(SMARTALBUM_DB_ID, 3);
    retVal = helper->Insert(deleteSmartAlbumUri, deleteValuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_SmartAlbum_Test_001::Delete End. retVal = %{public}d", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_Favorite_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_Favorite_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "Favorite_Test_001")) {
        return;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, FAVOURITE_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileAsset->GetId());
    Uri addSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    auto retVal = helper->Insert(addSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    Uri removeSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    retVal = helper->Insert(removeSmartAlbumUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_Favorite_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_Trash_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_Trash_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "Trash_Test_001")) {
        return;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileAsset->GetId());
    Uri addSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    auto retVal = helper->Insert(addSmartAlbumUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    Uri removeSmartAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    retVal = helper->Insert(removeSmartAlbumUri, valuesBucket);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_Trash_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_Insert_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_Insert_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri insertUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, "MediaDataShare_Insert_Test_001");
    auto retVal = helper->Insert(insertUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_Insert_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_DeleteAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_DeleteAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "DeleteAsset_Test_001")) {
        return;
    }
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET +
        '/' + to_string(fileAsset->GetId()));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(fileAsset->GetId()));
    auto retVal = helper->Delete(deleteAssetUri, predicates);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_DeleteAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_DeleteAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_DeleteAlbum_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, true, "DeleteAlbum_Test_001")) {
        return;
    }
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_DELETEALBUM +
        '/' + to_string(fileAsset->GetId()));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, fileAsset->GetId());
    auto retVal = helper->Delete(deleteAssetUri, predicates);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_DeleteAlbum_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryDirTable_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryDirTable_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIATYPE_DIRECTORY_TABLE);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryAlbum_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryVolume_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryVolume_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_UpdateFileAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_UpdateFileAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "UpdateFileAsset_Test_001")) {
        return;
    }
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
    auto retVal = helper->Update(updateAssetUri, predicates, valuesBucketUpdate);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("MediaDataShare_UpdateFileAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_UpdateAlbumAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_UpdateAlbumAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, true, "UpdateAlbumAsset_Test_001")) {
        return;
    }
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_ID + " = " + to_string(fileAsset->GetId());
    predicates.SetWhereClause(prefix);
    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    valuesBucketUpdate.Put(MEDIA_DATA_DB_ALBUM_NAME, "U" + fileAsset->GetDisplayName());
    MEDIA_INFO_LOG("MediaDataShare_UpdateAlbumAsset_Test_001::GetUri = %{public}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);
    auto retVal = helper->Update(updateAssetUri, predicates, valuesBucketUpdate);
    EXPECT_EQ(retVal, E_SUCCESS);
    MEDIA_INFO_LOG("MediaDataShare_UpdateAlbumAsset_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_OpenFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_OpenFile_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, false, "OpenFile_Test_001")) {
        return;
    }
    string fileUri = fileAsset->GetUri();
    string mode = MEDIA_FILEMODE_READONLY;
    Uri openFileUri(fileUri);
    MEDIA_INFO_LOG("openFileUri = %{public}s", openFileUri.ToString().c_str());
    int32_t fd = helper->OpenFile(openFileUri, mode);
    EXPECT_EQ(fd > 0, true);
    if (fd > 0) {
        close(fd);
    }
    MEDIA_INFO_LOG("MediaDataShare_OpenFile_Test_001::fd = %{public}d. End", fd);
}
} // namespace Media
} // namespace OHOS
