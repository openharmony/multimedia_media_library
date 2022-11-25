/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "fetch_result_test_cb.h"
#include "medialibrary_helper_test.h"

#include "datashare_result_set.h"
#include "fetch_result.h"
#include "media_log.h"
#include "rdb_helper.h"
#include "rdb_store_config.h"
#include "rdb_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
shared_ptr<NativeRdb::RdbStore> rdbStore = nullptr;

static const int32_t TEST_IS_TRASH = 0;
static const int64_t TEST_SIZE = 0;
static const string TEST_PATH = "/data/test";
static const string TEST_URI = MEDIALIBRARY_DATA_URI;

void MediaLibraryHelperUnitTest::SetUpTestCase(void)
{
    static const string DATABASE_PATH = "/data/test/test.db";
    NativeRdb::RdbHelper::DeleteRdbStore(DATABASE_PATH);

    NativeRdb::RdbStoreConfig config(DATABASE_PATH);
    FetchResultTestCB callback;
    int errCode = -1;
    rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_EQ(errCode, NativeRdb::E_OK);
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    for (int32_t mediaType = MediaType::MEDIA_TYPE_FILE; mediaType <= MEDIA_TYPE_MEDIA; mediaType ++) {
        int64_t rowId = -1;
        valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
        valuesBucket.PutInt(MEDIA_DATA_DB_IS_TRASH, TEST_IS_TRASH);
        valuesBucket.PutLong(MEDIA_DATA_DB_SIZE, TEST_SIZE);
        valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, TEST_PATH);
        valuesBucket.PutString(MEDIA_DATA_DB_URI, TEST_URI);
        rdbStore->Insert(rowId, MEDIALIBRARY_TABLE, valuesBucket);
        valuesBucket.Clear();
        EXPECT_EQ(rowId > 0, true);
    }
}

void MediaLibraryHelperUnitTest::TearDownTestCase(void) {}
void MediaLibraryHelperUnitTest::SetUp(void) {}
void MediaLibraryHelperUnitTest::TearDown(void) {}

shared_ptr<DataShare::DataShareResultSet> GetFetchResult()
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_SIZE, to_string(0))->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(0));
    shared_ptr<NativeRdb::AbsSharedResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    shared_ptr<DataShare::ResultSetBridge> result = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(queryResultSet);
    return make_shared<DataShare::DataShareResultSet>(result);
}

shared_ptr<DataShare::DataShareResultSet> GetEmptyFetchResult()
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_ID, to_string(0));
    shared_ptr<NativeRdb::AbsSharedResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    shared_ptr<DataShare::ResultSetBridge> result = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(queryResultSet);
    return make_shared<DataShare::DataShareResultSet>(result);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_SetGet_Test_001, TestSize.Level0)
{
    shared_ptr<DataShare::DataShareResultSet> datashareResultSet = nullptr;
    shared_ptr<FetchResult<FileAsset>> fetchResult = make_shared<FetchResult<FileAsset>>(datashareResultSet);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_SetGet_Test_002, TestSize.Level0)
{
    shared_ptr<FetchResult<FileAsset>> fetchResult = make_shared<FetchResult<FileAsset>>();
    fetchResult->Close();
    EXPECT_EQ(fetchResult->IsClosed(), true);

    EXPECT_EQ(fetchResult->IsContain(), false);

    EXPECT_EQ(fetchResult->GetCount(), 0);

    auto result = make_unique<FetchResult<FileAsset>>(GetFetchResult());
    fetchResult->SetInfo(result);

    const string TEST_NETWORKID = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    fetchResult->SetNetworkId(TEST_NETWORKID);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectAtPosition_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetObjectAtPosition(1), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectAtPosition_Test_002, TestSize.Level0)
{
    shared_ptr<DataShare::DataShareResultSet> datashareResultSet = nullptr;
    shared_ptr<FetchResult<FileAsset>> fetchResult = make_shared<FetchResult<FileAsset>>(datashareResultSet);

    const int32_t TEST_INVALID_INDEX = -1;
    EXPECT_EQ(fetchResult->GetObjectAtPosition(TEST_INVALID_INDEX), nullptr);

    fetchResult->count_ = 0;
    const int32_t TEST_INDEX_LARGE_THAN_ROWS = 100;
    EXPECT_EQ(fetchResult->GetObjectAtPosition(TEST_INDEX_LARGE_THAN_ROWS), nullptr);

    fetchResult->count_ = TEST_INDEX_LARGE_THAN_ROWS + 1;
    EXPECT_EQ(fetchResult->GetObjectAtPosition(TEST_INDEX_LARGE_THAN_ROWS), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetFirstObject_Test_001, TestSize.Level0)
{
    auto fileFetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    fileFetchResult->resultNapiType_ = ResultNapiType::TYPE_USERFILE_MGR;
    auto fileAsset = fileFetchResult->GetFirstObject();
    EXPECT_EQ(fileAsset->GetPath(), TEST_PATH);

    auto albumFetchResult = make_shared<FetchResult<AlbumAsset>>(GetFetchResult());
    albumFetchResult->resultNapiType_ = ResultNapiType::TYPE_USERFILE_MGR;
    auto albumAsset = albumFetchResult->GetFirstObject();
    EXPECT_EQ(albumAsset->GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);

    auto smartAlbumFetchResult = make_shared<FetchResult<SmartAlbumAsset>>(GetFetchResult());
    smartAlbumFetchResult->resultNapiType_ = ResultNapiType::TYPE_USERFILE_MGR;
    auto smartAlbumAsset = smartAlbumFetchResult->GetFirstObject();
    EXPECT_EQ(smartAlbumAsset->GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetFirstObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetFirstObject_Test_002, TestSize.Level0)
{
    auto fileFetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    auto fileAsset = fileFetchResult->GetFirstObject();
    EXPECT_EQ(fileAsset->GetPath(), TEST_PATH);

    auto albumFetchResult = make_shared<FetchResult<AlbumAsset>>(GetFetchResult());
    auto albumAsset = albumFetchResult->GetFirstObject();
    EXPECT_EQ(albumAsset->GetResultNapiType(), ResultNapiType::TYPE_NAPI_MAX);

    auto smartAlbumFetchResult = make_shared<FetchResult<SmartAlbumAsset>>(GetFetchResult());
    auto smartAlbumAsset = smartAlbumFetchResult->GetFirstObject();
    EXPECT_EQ(smartAlbumAsset->GetResultNapiType(), ResultNapiType::TYPE_NAPI_MAX);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetFirstObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetFirstObject_Test_003, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetFirstObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetNextObject_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetNextObject(), nullptr);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetNextObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetNextObject_Test_002, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetNextObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetLastObject_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetLastObject(), nullptr);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetLastObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetLastObject_Test_002, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetLastObject(), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_IsAtLastRow_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_EQ(fetchResult->IsAtLastRow(), false);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->IsAtLastRow(), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_001, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_SIZE, to_string(0))->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(0));
    shared_ptr<NativeRdb::AbsSharedResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    auto fileAsset = result->GetObjectFromRdb(queryResultSet, 1);
    EXPECT_NE(fileAsset, nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_002, TestSize.Level0)
{
    auto result = make_shared<FetchResult<FileAsset>>();
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    auto fileAsset = result->GetObjectFromRdb(resultSet, 1);
    EXPECT_EQ(fileAsset, nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_003, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_ID, to_string(0));
    shared_ptr<NativeRdb::AbsSharedResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetObjectFromRdb(queryResultSet, 1), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_004, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_SIZE, to_string(0))->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(0));
    shared_ptr<NativeRdb::AbsSharedResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    const int32_t TEST_INDEX_LARGE_THAN_ROWS = 100;
    EXPECT_EQ(result->GetObjectFromRdb(queryResultSet, TEST_INDEX_LARGE_THAN_ROWS), nullptr);
}

HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_SetFileAsset_Test_001, TestSize.Level0)
{
    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetObject()->GetAlbumUri(), DEFAULT_MEDIA_ALBUM_URI);
}
} // namespace Media
} // namespace OHOS
