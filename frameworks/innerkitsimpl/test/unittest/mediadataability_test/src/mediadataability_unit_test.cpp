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

#include "mediadataability_unit_test.h"
#include "data_ability_helper.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "permission/permission_kit.h"
#include "system_ability_definition.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
MediaLibraryDataAbility g_rdbStoreTest;
string g_createUri1, g_createUri2;
int uid = 5010;
std::shared_ptr<AppExecFwk::DataAbilityHelper> medialibraryDataAbilityHelper = nullptr;
int g_fd1 = DATA_ABILITY_FAIL;
int g_fd2 = DATA_ABILITY_FAIL;
int g_albumId1 = DATA_ABILITY_FAIL;
int g_albumId2 = DATA_ABILITY_FAIL;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet1 = nullptr;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet2 = nullptr;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet3 = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> CreateDataAHelper(
    int32_t systemAbilityId, std::shared_ptr<Uri> dataAbilityUri)
{
    MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateDataAHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return AppExecFwk::DataAbilityHelper::Creator(remoteObj, dataAbilityUri);
}
std::shared_ptr<AppExecFwk::DataAbilityHelper> CreateMediaLibraryHelper()
{
    if (medialibraryDataAbilityHelper == nullptr) {
        MEDIA_INFO_LOG("CreateMediaLibraryHelper ::medialibraryDataAbilityHelper == nullptr");
        std::shared_ptr<Uri> dataAbilityUri = std::make_shared<Uri>("dataability:///media");
        medialibraryDataAbilityHelper = CreateDataAHelper(uid, dataAbilityUri);
    }
    MEDIA_INFO_LOG("CreateMediaLibraryHelper ::medialibraryDataAbilityHelper != nullptr");
    return medialibraryDataAbilityHelper;
}
void MediaDataAbilityUnitTest::SetUpTestCase(void)
{}

void MediaDataAbilityUnitTest::TearDownTestCase(void) {}
void MediaDataAbilityUnitTest::SetUp(void) {}
void MediaDataAbilityUnitTest::TearDown(void) {}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAllFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::helper->Query before");
    resultSet = helper->Query(queryFileUri, columns, predicates);
    MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::helper->Query after");
    EXPECT_NE((resultSet == nullptr), true);
    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET +
            '/' + fileAsset->GetUri());
        DataShare::DataSharePredicates deletePredicates;
        MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::uri :%{private}s", fileAsset->GetUri().c_str());
        MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::helper->Insert before");
        int retVal = helper->Delete(deleteAssetUri, deletePredicates);
        MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::helper->Insert after");
        EXPECT_NE((retVal < 0), true);

        fileAsset = fetchFileResult->GetNextObject();
    }

    MEDIA_INFO_LOG("MediaDataAbility_DeleteAllFiles_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "gtest_new_file001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_002::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "gtest_new_file_0102.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_002::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_003::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    string displayName = "gtest_new_file0103.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_003::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_004::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    string displayName = ".gtest_new_file0103.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    EXPECT_NE((index <= 0), false);
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_004::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_005::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "Pictures/createAsset/";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = helper->Insert(createAssetUri, valuesBucket);
    EXPECT_NE((index <= 0), false);
    MEDIA_INFO_LOG("MediaDataAbility_CreateAsset_Test_005::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_DeleteAsset_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    int index = DATA_ABILITY_FAIL;
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
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
        "/" + to_string(index));
    DataAbilityPredicates predicates;
    int retVal = helper->Delete(deleteAssetUri, predicates);
    EXPECT_NE((retVal < 0), true);
    MEDIA_INFO_LOG("MediaDataAbility_DeleteAsset_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_QueryFiles_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_QueryFiles_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_002::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_002::resultSet != nullptr");

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_002::GetCount > 0");

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_002::fileAsset != nullptr");
    MEDIA_INFO_LOG("MediaDataAbility_QueryFiles_Test_002::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_UpdateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    NativeRdb::ValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_TITLE, "UpdateAsset_Test_001");
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());

    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_001::GetId = %{private}d", fileAsset->GetId());
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_001::GetUri = %{private}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, valuesBucketUpdate, predicates);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_001::changedRows = %{private}d", changedRows);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_UpdateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_002::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    NativeRdb::ValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    valuesBucketUpdate.PutInt(MEDIA_DATA_DB_ORIENTATION, 1);

    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_002::GetUri = %{private}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, valuesBucketUpdate, predicates);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_002::changedRows = %{private}d", changedRows);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_002::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_UpdateAsset_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_003::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    // Create FetchResult object using the contents of resultSet
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    EXPECT_NE((fileAsset == nullptr), true);

    NativeRdb::ValuesBucket valuesBucketUpdate;
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    valuesBucketUpdate.PutString(MEDIA_DATA_DB_NAME, "U" + fileAsset->GetDisplayName());

    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_003::GetUri = %{private}s", fileAsset->GetUri().c_str());
    Uri updateAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = helper->Update(updateAssetUri, valuesBucketUpdate, predicates);
    EXPECT_NE(changedRows < 0, true);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_003::changedRows = %{private}d", changedRows);
    MEDIA_INFO_LOG("MediaDataAbility_UpdateAsset_Test_003::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_OpenFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_OpenFile_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
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
    MEDIA_INFO_LOG("openFileUri = %{private}s", openFileUri.ToString().c_str());
    int32_t fd = helper->OpenFile(openFileUri, mode);

    EXPECT_NE(fd <= 0, true);
    MEDIA_INFO_LOG("MediaDataAbility_OpenFile_Test_001::fd = %{private}d", fd);
    MEDIA_INFO_LOG("MediaDataAbility_OpenFile_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CloseFile_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaDataAbility_CloseFile_Test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
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
    MEDIA_INFO_LOG("openFileUri = %{private}s", openFileUri.ToString().c_str());
    int32_t fd = helper->OpenFile(openFileUri, mode);

    EXPECT_NE(fd <= 0, true);
    MEDIA_INFO_LOG("MediaDataAbility_CloseFile_Test_001::fd = %{private}d", fd);

    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);

    int32_t retVal = close(fd);
    EXPECT_NE(retVal != DATA_ABILITY_SUCCESS, true);

    NativeRdb::ValuesBucket valuesBucketClose;
    valuesBucketClose.PutString(MEDIA_DATA_DB_URI, fileUri);
    int32_t retValClose = helper->Insert(closeAssetUri, valuesBucketClose);
    EXPECT_NE(retValClose != DATA_ABILITY_SUCCESS, true);

    MEDIA_INFO_LOG("MediaDataAbility_CloseFile_Test_001::End");
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetAlbum_Test_001, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    string abilityUri = Media::MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_ALBUMOPRN_QUERYALBUM;
    Uri createAssetUri(abilityUri);
    string queryAssetUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri1(queryAssetUri);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns;
    helper->Query(createAssetUri, columns, predicates1);

    NativeRdb::DataAbilityPredicates queryPredicates;
    queryPredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    std::vector<std::string> queryColumns;
    helper->Query(createAssetUri1, queryColumns, queryPredicates);

    NativeRdb::DataAbilityPredicates predicates2;
    NativeRdb::ValuesBucket valuesBucket1;
    valuesBucket1.PutString(MEDIA_DATA_DB_TITLE, "newTest");
    predicates2.EqualTo(MEDIA_DATA_DB_ID, std::to_string(1));
    Uri uri(MEDIALIBRARY_DATA_URI);
    helper->Update(uri, valuesBucket1, predicates2);

    NativeRdb::DataAbilityPredicates filePredicates;
    NativeRdb::ValuesBucket fileValuesBucket;
    fileValuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, "newTest");
    filePredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    helper->Update(uri, fileValuesBucket, filePredicates);
}
} // namespace Media
} // namespace OHOS
