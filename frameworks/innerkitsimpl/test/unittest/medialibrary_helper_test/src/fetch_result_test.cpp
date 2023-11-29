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
#include "media_log.h"
#include "rdb_helper.h"
#include "rdb_store_config.h"
#include "rdb_utils.h"
#define private public
#include "base_column.h"
#include "fetch_result.h"
#include "media_column.h"
#include "result_set_utils.h"
#undef private
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
    std::shared_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    shared_ptr<DataShare::ResultSetBridge> result = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(queryResultSet);
    return make_shared<DataShare::DataShareResultSet>(result);
}

shared_ptr<DataShare::DataShareResultSet> GetEmptyFetchResult()
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_ID, to_string(0));
    std::shared_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    shared_ptr<DataShare::ResultSetBridge> result = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(queryResultSet);
    return make_shared<DataShare::DataShareResultSet>(result);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check set get function
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_SetGet_Test_001, TestSize.Level0)
{
    shared_ptr<FetchResult<FileAsset>> fetchResult = make_shared<FetchResult<FileAsset>>();
    fetchResult->Close();
    EXPECT_EQ(fetchResult->GetCount(), 0);

    auto result = make_unique<FetchResult<FileAsset>>(GetFetchResult());
    fetchResult->SetInfo(result);

    const string TEST_NETWORKID = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    fetchResult->SetNetworkId(TEST_NETWORKID);
    shared_ptr<DataShare::DataShareResultSet> datashareResultSet = nullptr;
    shared_ptr<FetchResult<FileAsset>> fetchResultTest = make_shared<FetchResult<FileAsset>>(datashareResultSet);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectatposition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectAtPosition_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetObjectAtPosition(1), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectatposition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectAtPosition_Test_002, TestSize.Level0)
{
    shared_ptr<DataShare::DataShareResultSet> datashareResultSet = nullptr;
    shared_ptr<FetchResult<FileAsset>> fetchResult = make_shared<FetchResult<FileAsset>>(datashareResultSet);

    const int32_t TEST_INVALID_INDEX = -1;
    EXPECT_EQ(fetchResult->GetObjectAtPosition(TEST_INVALID_INDEX), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getfirstobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetFirstObject_Test_001, TestSize.Level0)
{
    auto fileFetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    fileFetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    auto fileAsset = fileFetchResult->GetFirstObject();
    EXPECT_EQ(fileAsset->GetPath(), TEST_PATH);

    auto albumFetchResult = make_shared<FetchResult<AlbumAsset>>(GetFetchResult());
    albumFetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    auto albumAsset = albumFetchResult->GetFirstObject();
    EXPECT_EQ(albumAsset->GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);

    auto smartAlbumFetchResult = make_shared<FetchResult<SmartAlbumAsset>>(GetFetchResult());
    smartAlbumFetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    auto smartAlbumAsset = smartAlbumFetchResult->GetFirstObject();
    EXPECT_EQ(smartAlbumAsset->GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetFirstObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getfirstobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
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

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getfirstobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetFirstObject_Test_003, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetFirstObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getnextobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetNextObject_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetNextObject(), nullptr);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetNextObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getnextobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetNextObject_Test_002, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetNextObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getlastobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetLastObject_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetLastObject(), nullptr);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetLastObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getlastobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetLastObject_Test_002, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_EQ(fetchResult->GetLastObject(), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObject_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_NE(fetchResult->GetObject(), nullptr);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_NE(result->GetObject(), nullptr);
    EXPECT_EQ(result->GetObject()->GetPath(), DEFAULT_MEDIA_PATH);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObject_Test_002, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    EXPECT_NE(fetchResult->GetObject(), nullptr);
    EXPECT_EQ(fetchResult->GetObject()->GetPath(), DEFAULT_MEDIA_PATH);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobject
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObject_Test_003, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    shared_ptr<NativeRdb::ResultSet> resultSet;
    auto ret = fetchResult->GetObject(resultSet);
    EXPECT_NE(ret, nullptr);
    fetchResult->SetFetchResType(FetchResType::TYPE_ALBUM);
    fetchResult->GetNetworkId();
    fetchResult->GetDataShareResultSet();
    fetchResult->GetFetchResType();
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check isatlastrow
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_IsAtLastRow_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetFetchResult());
    EXPECT_EQ(fetchResult->IsAtLastRow(), false);

    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->IsAtLastRow(), false);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectfromrdb
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_001, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_SIZE, to_string(0))->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(0));
    std::shared_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    auto fileAsset = result->GetObjectFromRdb(queryResultSet, 1);
    EXPECT_NE(fileAsset, nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectfromrdb
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_002, TestSize.Level0)
{
    auto result = make_shared<FetchResult<FileAsset>>();
    shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    auto fileAsset = result->GetObjectFromRdb(resultSet, 1);
    EXPECT_EQ(fileAsset, nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectfromrdb
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_003, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_ID, to_string(0));
    std::shared_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetObjectFromRdb(queryResultSet, 1), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check getobjectfromrdb
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetObjectFromRdb_Test_004, TestSize.Level0)
{
    vector<string> columns;
    NativeRdb::AbsRdbPredicates dirAbsPred(MEDIALIBRARY_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_SIZE, to_string(0))->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(0));
    std::shared_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(dirAbsPred, columns);
    auto result = make_shared<FetchResult<FileAsset>>();
    const int32_t TEST_INDEX_LARGE_THAN_ROWS = 100;
    EXPECT_EQ(result->GetObjectFromRdb(queryResultSet, TEST_INDEX_LARGE_THAN_ROWS), nullptr);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check SetFileAsset
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_SetFileAsset_Test_001, TestSize.Level0)
{
    auto result = make_shared<FetchResult<FileAsset>>();
    EXPECT_EQ(result->GetObject()->GetAlbumUri(), DEFAULT_MEDIA_ALBUM_URI);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check GetRowValFromColumn
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_GetRowValFromColumn_Test_001, TestSize.Level0)
{
    auto fetchResult = make_shared<FetchResult<FileAsset>>(GetEmptyFetchResult());
    shared_ptr<NativeRdb::ResultSet> resultSet;
    string columnName = "GetRowValFromColumn";
    ResultSetDataType dataType = TYPE_STRING;
    variant<int32_t, int64_t, string, double> ret = fetchResult->GetRowValFromColumn(columnName, dataType, resultSet);
    EXPECT_EQ(get<string>(ret), "");
    fetchResult->Close();
    ret = fetchResult->GetRowValFromColumn(columnName, dataType, resultSet);
    EXPECT_EQ(get<string>(ret), "");
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check base
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_base_Test_001, TestSize.Level0)
{
    string ret = BaseColumn::CreateIndex();
    EXPECT_EQ(ret, "CREATE INDEX IF NOT EXISTS ");
    ret = BaseColumn::CreateTable();
    EXPECT_EQ(ret, "CREATE TABLE IF NOT EXISTS ");
    ret = BaseColumn::CreateTrigger();
    EXPECT_EQ(ret, "CREATE TRIGGER IF NOT EXISTS ");
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check media_column
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, FetchResult_media_column_Test_001, TestSize.Level0)
{
    bool ret = PhotoColumn::IsPhotoColumn(PhotoColumn::PHOTO_ORIENTATION);
    EXPECT_EQ(ret, true);
    ret = PhotoColumn::IsPhotoColumn("media_column");
    EXPECT_EQ(ret, false);
    ret = AudioColumn::IsAudioColumn(AudioColumn::AUDIO_ALBUM);
    EXPECT_EQ(ret, true);
    ret = AudioColumn::IsAudioColumn("media_column");
    EXPECT_EQ(ret, false);
}
} // namespace Media
} // namespace OHOS
