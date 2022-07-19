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

#include "mediadatashare_unit_test.h"
#include "datashare_helper.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "system_ability_definition.h"
#include "media_data_ability_const.h"
#include "media_library_manager.h"
#include "fetch_result.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
string g_createUri1, g_createUri2;
int g_uid = 5003;
std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper;
MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();
int g_fd1 = E_FAIL;
int g_fd2 = E_FAIL;
int g_albumId1 = E_FAIL;
int g_albumId2 = E_FAIL;

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

void MediaDataShareUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("SetUpTestCase invoked");
    g_mediaDataShareHelper = CreateDataShareHelper(g_uid);
}

void MediaDataShareUnitTest::TearDownTestCase(void) {}
void MediaDataShareUnitTest::SetUp(void) {}
void MediaDataShareUnitTest::TearDown(void) {}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_DeleteAllFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::helper->Query before");
    resultSet = helper->Query(queryFileUri, predicates, columns);
    MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::helper->Query after");
    EXPECT_NE((resultSet == nullptr), true);
    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET +
            '/' + fileAsset->GetUri());
        DataShare::DataSharePredicates deletePredicates;
        MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::uri :%{public}s", fileAsset->GetUri().c_str());
        MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::helper->Insert before");
        int retVal = helper->Delete(deleteAssetUri, deletePredicates);
        MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::helper->Insert after");
        EXPECT_NE((retVal < 0), true);

        fileAsset = fetchFileResult->GetNextObject();
    }

    MEDIA_INFO_LOG("MediaDataShare_DeleteAllFiles_Test_001::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "gtest_new_file001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_001::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_002::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "gtest_new_file_0102.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_002::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_003::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    string displayName = "gtest_new_file0103.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_003::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_004::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    string displayName = ".gtest_new_file0103.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    EXPECT_NE((index <= 0), false);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_004::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CreateAsset_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_005::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    EXPECT_NE((index <= 0), false);
    MEDIA_INFO_LOG("MediaDataShare_CreateAsset_Test_005::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_DeleteAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_DeleteAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int index = E_FAIL;
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "gtest_delete_file001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);

    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET +
        '/' + to_string(index));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(index));
    int retVal = helper->Delete(deleteAssetUri, predicates);
    EXPECT_NE((retVal < 0), true);
    MEDIA_INFO_LOG("MediaDataShare_DeleteAsset_Test_001::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_001::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_QueryFiles_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_002::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_002::resultSet != nullptr");

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_002::GetCount > 0");

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);
    MEDIA_INFO_LOG("MediaDataShare_QueryFiles_Test_002::fileAsset != nullptr. End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_UpdateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_TITLE, "UpdateAsset_Test_001.jpg");
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());

    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_001::GetId = %{public}d, GetUri = %{public}s",
                   fileAsset->GetId(),
                   fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, predicates, valuesBucketUpdate);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_001::changedRows = %{public}d. End", changedRows);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_UpdateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_002::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    valuesBucketUpdate.PutInt(MEDIA_DATA_DB_ORIENTATION, 1);

    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_002::GetName = %{public}s, GetRelPath = %{public}s",
                   fileAsset->GetDisplayName().c_str(),
                   fileAsset->GetRelativePath().c_str());
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_002::GetUri = %{public}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, predicates, valuesBucketUpdate);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_002::changedRows = %{public}d. End", changedRows);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_UpdateAsset_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_003::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    DataShare::DataShareValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, "U" + fileAsset->GetDisplayName());

    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_003::GetUri = %{public}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, predicates, valuesBucketUpdate);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataShare_UpdateAsset_Test_003::changedRows = %{public}d. End", changedRows);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_OpenFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_OpenFile_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    string fileUri = fileAsset->GetUri();
    string mode = MEDIA_FILEMODE_READONLY;

    Uri openFileUri(fileUri);
    MEDIA_INFO_LOG("openFileUri = %{public}s", openFileUri.ToString().c_str());
    int32_t fd = helper->OpenFile(openFileUri, mode);

    EXPECT_NE(fd <= 0, true);
    MEDIA_INFO_LOG("MediaDataShare_OpenFile_Test_001::fd = %{public}d. End", fd);
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_CloseFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataShare_CloseFile_Test_001::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    string fileUri = fileAsset->GetUri();
    string mode = MEDIA_FILEMODE_READWRITE;

    Uri openFileUri(fileUri);
    MEDIA_INFO_LOG("openFileUri = %{public}s", openFileUri.ToString().c_str());
    int32_t fd = helper->OpenFile(openFileUri, mode);

    EXPECT_NE(fd <= 0, true);
    MEDIA_INFO_LOG("MediaDataShare_CloseFile_Test_001::fd = %{public}d", fd);

    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);

    int32_t retVal = close(fd);
    EXPECT_NE(retVal != E_SUCCESS, true);

    DataShare::DataShareValuesBucket valuesBucketClose;
    valuesBucketClose.PutString(MEDIA_DATA_DB_URI, fileUri);
    int32_t retValClose = helper->Insert(closeAssetUri, valuesBucketClose);
    EXPECT_NE(retValClose != E_SUCCESS, true);

    MEDIA_INFO_LOG("MediaDataShare_CloseFile_Test_001::End");
}

HWTEST_F(MediaDataShareUnitTest, MediaDataShare_GetAlbum_Test_001, TestSize.Level0)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_ALBUMOPRN_QUERYALBUM;
    Uri createAssetUri(abilityUri);
    string queryAssetUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri1(queryAssetUri);
    DataShare::DataShareValuesBucket valuesBucket;
    DataSharePredicates predicates1;
    std::vector<std::string> columns;
    helper->Query(createAssetUri, predicates1, columns);

    DataSharePredicates queryPredicates;
    queryPredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    std::vector<std::string> queryColumns;
    helper->Query(createAssetUri1, queryPredicates, queryColumns);

    DataSharePredicates predicates2;
    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.PutString(MEDIA_DATA_DB_TITLE, "newTest");
    predicates2.EqualTo(MEDIA_DATA_DB_ID, std::to_string(1));
    Uri uri(MEDIALIBRARY_DATA_URI);
    helper->Update(uri, predicates2, valuesBucket1);

    DataSharePredicates filePredicates;
    DataShare::DataShareValuesBucket fileValuesBucket;
    fileValuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, "newTest");
    filePredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    helper->Update(uri, filePredicates, fileValuesBucket);
}
} // namespace Media
} // namespace OHOS
