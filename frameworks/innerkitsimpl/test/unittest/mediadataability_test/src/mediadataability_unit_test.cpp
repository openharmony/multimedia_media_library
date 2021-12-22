/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "media_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
MediaLibraryDataAbility g_rdbStoreTest;
string g_createUri1, g_createUri2;
int g_fd1 = DATA_ABILITY_FAIL;
int g_fd2 = DATA_ABILITY_FAIL;
int g_albumId1 = DATA_ABILITY_FAIL;
int g_albumId2 = DATA_ABILITY_FAIL;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet1 = nullptr;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet2 = nullptr;
shared_ptr<NativeRdb::AbsSharedResultSet> g_resultSet3 = nullptr;

void MediaDataAbilityUnitTest::SetUpTestCase(void)
{
    g_rdbStoreTest.InitMediaLibraryRdbStore();
}

void MediaDataAbilityUnitTest::TearDownTestCase(void)
{
    if (remove("/data/media/media_library.db") != 0
        || remove("/data/media/media_library.db-shm") != 0
        || remove("/data/media/media_library.db-wal") != 0) {
        MEDIA_ERR_LOG("Db deletion failed");
    }
}

void MediaDataAbilityUnitTest::SetUp(void) {}

void MediaDataAbilityUnitTest::TearDown(void) {}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAlbum_Test_001, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string albumPath = "/data/media/gtest";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, albumPath);

    g_albumId1 = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket);
    EXPECT_NE((g_albumId1 <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_001, TestSize.Level0)
{
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string path = "/data/media/gtest/gtest_new_file001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;

    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);

    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_OpenAsset_Test_001, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri openFileUri(g_createUri1);
    g_fd1 = g_rdbStoreTest.OpenFile(openFileUri, "r");
    EXPECT_NE((g_fd1 <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CloseAsset_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, g_createUri1);

    ret = close(g_fd1);
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket);
    EXPECT_NE((ret != 0), true);

    // Timer for scan file to finish after close asset
    std::this_thread::sleep_for(2000ms);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_ModifyAsset_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    string newPath = "/data/media/gtest/gtest_modified_file001.jpg";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, g_createUri1);
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newPath);

    ret = g_rdbStoreTest.Insert(updateAssetUri, valuesBucket);
    EXPECT_EQ((ret < 0), false);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAlbum_Test_002, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string albumPath = "/data/media/gtest/gtest_new_album001";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, albumPath);

    g_albumId2 = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket);
    EXPECT_NE((g_albumId2 <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_ModifyAlbum_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri modifyAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_MODIFYALBUM);
    string albumName = "gtest_modified_album001";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, g_albumId2);
    valuesBucket.PutString(MEDIA_DATA_DB_ALBUM_NAME, albumName);

    ret = g_rdbStoreTest.Insert(modifyAlbumUri, valuesBucket);
    EXPECT_NE((ret < 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetFileAssets_Test_001, TestSize.Level0)
{
    int count = 0;
    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? ";
    vector<string> selectionArgs = { "/data/media/gtest/%", to_string(MEDIA_TYPE_IMAGE) };
    string order = MEDIA_DATA_DB_ID + " ASC";

    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    selection = prefix + "AND " + selection;
    selectionArgs.insert(selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    predicates.SetOrder(order);

    g_resultSet1 = g_rdbStoreTest.Query(uri, columns, predicates);
    if (g_resultSet1 != nullptr) {
        fetchFileResult = make_unique<FetchResult>(move(g_resultSet1));
        if (fetchFileResult != nullptr) {
            count = fetchFileResult->GetCount();
        }
    }
    EXPECT_EQ((count == 1), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetFirstObject_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    EXPECT_NE(g_resultSet1, nullptr);

    ret = g_resultSet1->GoToFirstRow();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;

    ret = g_resultSet1->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet1->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(2, intVal);

    ret = g_resultSet1->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet1->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("gtest_modified_file001.jpg", strVal);

    ret = g_resultSet1->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet1->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("/data/media/gtest/gtest_modified_file001.jpg", strVal);

    ret = g_resultSet1->GetColumnIndex(MEDIA_DATA_DB_URI, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet1->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("dataability:///com.ohos.medialibrary.MediaLibraryDataAbility/image", strVal);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetAlbums_Test_001, TestSize.Level0)
{
    int count = 0;
    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? AND " + MEDIA_DATA_DB_RELATIVE_PATH + " = ? ";
    vector<string> selectionArgs = { "/data/media/gtest/%", "/data/media/gtest" };

    selection = MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + selection;
    selectionArgs.insert(selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);

    g_resultSet2 = g_rdbStoreTest.Query(uri, columns, predicates);
    if (g_resultSet2 != nullptr) {
        while (g_resultSet2->GoToNextRow() == NativeRdb::E_OK) {
            count++;
        }
    }
    EXPECT_EQ((count == 1), true);
}


HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetAlbumInformation_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    EXPECT_NE(g_resultSet2, nullptr);

    ret = g_resultSet2->GoToRow(0);
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;

    ret = g_resultSet2->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet2->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(3, intVal);

    ret = g_resultSet2->GetColumnIndex(MEDIA_DATA_DB_ALBUM_NAME, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet2->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("gtest_modified_album001", strVal);

    ret = g_resultSet2->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet2->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("/data/media/gtest/gtest_modified_album001", strVal);

    ret = g_resultSet2->GetColumnIndex(MEDIA_DATA_DB_RELATIVE_PATH, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet2->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("/data/media/gtest", strVal);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAssetInAlbum_Test_002, TestSize.Level0)
{
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string path = "/data/media/gtest/gtest_modified_album001/gtest_new_file002.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;

    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);

    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    g_createUri2 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_OpenAssetInAlbum_Test_002, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri openFileUri(g_createUri2);
    g_fd2 = g_rdbStoreTest.OpenFile(openFileUri, "r");
    EXPECT_NE((g_fd2 <= 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CloseAssetInAlbum_Test_002, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, g_createUri2);

    ret = close(g_fd2);
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket);
    EXPECT_NE((ret != 0), true);

    // Timer for scan file to finish after close asset
    std::this_thread::sleep_for(2000ms);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetAlbumFileAssets_Test_001, TestSize.Level0)
{
    int count = 0;
    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    string selection = MEDIA_DATA_DB_MEDIA_TYPE + " = ? ";
    vector<string> selectionArgs = { to_string(MEDIA_TYPE_IMAGE) };

    string prefix = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    selection = prefix + "AND " + selection;
    selectionArgs.insert(selectionArgs.begin(), std::to_string(MEDIA_TYPE_ALBUM));
    selectionArgs.insert(selectionArgs.begin(), std::to_string(g_albumId2));

    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);

    g_resultSet3 = g_rdbStoreTest.Query(uri, columns, predicates);
    if (g_resultSet3 != nullptr) {
        fetchFileResult = make_unique<FetchResult>(move(g_resultSet3));
        if (fetchFileResult != nullptr) {
            count = fetchFileResult->GetCount();
        }
    }
    EXPECT_EQ((count == 1), true);

    NativeRdb::DataAbilityPredicates predicates2;
    predicates2.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(g_albumId2));
    predicates2.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));

    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet4 = g_rdbStoreTest.Query(uri, columns, predicates2);
    if (resultSet4 != nullptr) {
        unique_ptr<FetchResult> fetchFileResult2 = make_unique<FetchResult>(move(resultSet4));
        if (fetchFileResult2 != nullptr) {
            int count2 = fetchFileResult2->GetCount();
            EXPECT_EQ((count2 == 1), true);
        }
    }
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetPositionObject_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    EXPECT_NE(g_resultSet3, nullptr);

    ret = g_resultSet3->GoToRow(0);
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;

    ret = g_resultSet3->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet3->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(4, intVal);

    ret = g_resultSet3->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet3->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("gtest_new_file002.jpg", strVal);

    ret = g_resultSet3->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet3->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("/data/media/gtest/gtest_modified_album001/gtest_new_file002.jpg", strVal);

    ret = g_resultSet3->GetColumnIndex(MEDIA_DATA_DB_URI, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = g_resultSet3->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("dataability:///com.ohos.medialibrary.MediaLibraryDataAbility/image", strVal);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAsset_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri deleteAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_DELETEASSET);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, g_createUri1);

    ret = g_rdbStoreTest.Insert(deleteAssetUri, valuesBucket);
    EXPECT_NE((ret < 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAsset_Test_002, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri deleteAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_DELETEASSET);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, g_createUri2);

    ret = g_rdbStoreTest.Insert(deleteAssetUri, valuesBucket);
    EXPECT_NE((ret < 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAlbum_Test_001, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri deleteAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_DELETEALBUM);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, g_albumId2);

    ret = g_rdbStoreTest.Insert(deleteAlbumUri, valuesBucket);
    EXPECT_NE((ret < 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_DeleteAlbum_Test_002, TestSize.Level0)
{
    int ret = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri deleteAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_DELETEALBUM);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, g_albumId1);

    ret = g_rdbStoreTest.Insert(deleteAlbumUri, valuesBucket);
    EXPECT_NE((ret < 0), true);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityInsertTest_001, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test0"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 0);
    Uri uri(MEDIALIBRARY_DATA_URI);
    ret = g_rdbStoreTest.Insert(uri, values);
    EXPECT_EQ(ret, 5);

    NativeRdb::ValuesBucket values1;
    values1.PutString(MEDIA_DATA_DB_NAME, std::string("test1"));
    values1.PutInt(MEDIA_DATA_DB_SIZE, 10);
    ret = g_rdbStoreTest.Insert(uri, values1);
    EXPECT_EQ(ret, 6);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityInsertTest_002, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test2"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 11);
    Uri uri(MEDIALIBRARY_DATA_URI);
    ret = g_rdbStoreTest.Insert(uri, values);
    EXPECT_EQ(ret, 7);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityDeleteTest_001, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test2");
    Uri uri(MEDIALIBRARY_DATA_URI);
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityDeleteTest_002, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test-uk");
    Uri uri(MEDIALIBRARY_DATA_URI);
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityDeleteTest_003, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIALIBRARY_DATA_URI + "/abc");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, FAIL);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityDeleteTest_004, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIALIBRARY_DATA_URI + "/5");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityDeleteTest_005, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    Uri uri(MEDIALIBRARY_DATA_URI + "/1ab2");
    ret = g_rdbStoreTest.Delete(uri, predicates1);
    EXPECT_EQ(ret, FAIL);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityUpdateTest_001, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test1");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI);
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test3"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 12);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityUpdateTest_002, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test2");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI);
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("test4"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityUpdateTest_003, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/a2b");
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, FAIL);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityUpdateTest_004, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/abc");
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, FAIL);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityUpdateTest_005, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1("");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/6");
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, std::string("new-modify"));
    values.PutInt(MEDIA_DATA_DB_SIZE, 13);
    ret = g_rdbStoreTest.Update(uri, values, predicates1);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityQueryTest_001, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1;
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "new-modify");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;
    ret = resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(6, intVal);

    ret = resultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("new-modify", strVal);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityQueryTest_002, TestSize.Level1)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1;
    predicates1.EqualTo(MEDIA_DATA_DB_NAME, "test4");
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityQueryTest_003, TestSize.Level1)
{
    NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/abc");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_EQ(resultSet, nullptr);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityQueryTest_004, TestSize.Level1)
{
    NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_EQ(resultSet, nullptr);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityQueryTest_005, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_SIZE};
    Uri uri(MEDIALIBRARY_DATA_URI + "/6");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet;
    resultSet = g_rdbStoreTest.Query(uri, columns, predicates1);
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t columnIndex;
    int32_t intVal;
    std::string strVal;
    ret = resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(6, intVal);

    ret = resultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ("new-modify", strVal);
}

HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbilityBatchInsertTest_001, TestSize.Level0)
{
    int32_t ret = -1;
    NativeRdb::ValuesBucket values1;
    values1.PutString(MEDIA_DATA_DB_NAME, std::string("test11"));
    values1.PutInt(MEDIA_DATA_DB_SIZE, 11);

    NativeRdb::ValuesBucket values2;
    values2.PutString(MEDIA_DATA_DB_NAME, std::string("test10"));
    values2.PutInt(MEDIA_DATA_DB_SIZE, 10);

    NativeRdb::ValuesBucket values3;
    values3.PutString(MEDIA_DATA_DB_NAME, std::string("test12"));
    values3.PutInt(MEDIA_DATA_DB_SIZE, 12);

    std::vector<NativeRdb::ValuesBucket> values;
    values.push_back(values1);
    values.push_back(values2);
    values.push_back(values3);
    Uri uri(MEDIALIBRARY_DATA_URI);
    ret = g_rdbStoreTest.BatchInsert(uri, values);
    EXPECT_EQ(ret, 3);
}
} // namespace Media
} // namespace OHOS
