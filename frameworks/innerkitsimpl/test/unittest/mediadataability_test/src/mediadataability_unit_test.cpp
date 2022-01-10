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

void MediaDataAbilityUnitTest::TearDownTestCase(void) {}
void MediaDataAbilityUnitTest::SetUp(void) {}
void MediaDataAbilityUnitTest::TearDown(void) {}
HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_001, TestSize.Level0)
{
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "test/";
    string displayName = "gtest_new_file001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
}
HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_003, TestSize.Level0)
{
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "test1/";
    string displayName = "gtest_new_file_0102.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
}
HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_CreateAsset_Test_004, TestSize.Level0)
{
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "test/createAsset/";
    string displayName = "gtest_new_file0103.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    g_createUri1 = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);
}
HWTEST_F(MediaDataAbilityUnitTest, MediaDataAbility_GetAlbum_Test_001, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI +"/"+Media::MEDIA_ALBUMOPRN_QUERYALBUM;
    Uri createAssetUri(abilityUri);
    string queryAssetUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri1(queryAssetUri);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::DataAbilityPredicates predicates1;
    std::vector<std::string> columns;
    g_rdbStoreTest.Query(createAssetUri, columns, predicates1);

    NativeRdb::DataAbilityPredicates queryPredicates;
    queryPredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    std::vector<std::string> queryColumns;
    g_rdbStoreTest.Query(createAssetUri1, queryColumns, queryPredicates);
    NativeRdb::DataAbilityPredicates predicates2;
    NativeRdb::ValuesBucket valuesBucket1;
    valuesBucket1.PutString(MEDIA_DATA_DB_TITLE, "newTest");
    predicates2.EqualTo(MEDIA_DATA_DB_ID, std::to_string(1));
    Uri uri(MEDIALIBRARY_DATA_URI);
    g_rdbStoreTest.Update(uri, valuesBucket1, predicates2);
    
    NativeRdb::DataAbilityPredicates filePredicates;
    NativeRdb::ValuesBucket fileValuesBucket;
    fileValuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, "newTest");
    filePredicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(1));
    g_rdbStoreTest.Update(uri, fileValuesBucket, filePredicates);
}
} // namespace Media
} // namespace OHOS
