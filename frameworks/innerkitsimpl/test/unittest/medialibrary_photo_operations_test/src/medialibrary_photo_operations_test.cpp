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

#include <chrono>
#define MLOG_TAG "PhotoOperationsTest"

#include "medialibrary_photo_operations_test.h"

#include <fstream>
#include <thread>
#include <unistd.h>
#include <unordered_map>

#include "abs_rdb_predicates.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "uri.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;

using ExceptIntFunction = void (*) (int32_t);
using ExceptLongFunction = void (*) (int64_t);
using ExceptBoolFunction = void (*) (bool);
using ExceptStringFunction = void (*) (const string&);

const unordered_map<string, int> FILEASSET_MEMBER_MAP = {
    { MediaColumn::MEDIA_ID, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_URI, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_FILE_PATH, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_SIZE, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_TITLE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_NAME, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_TYPE, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_MIME_TYPE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_OWNER_PACKAGE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_DEVICE_NAME, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_THUMBNAIL, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_DATE_ADDED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_MODIFIED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_TAKEN, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_DELETED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_TIME_VISIT, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DURATION, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_TIME_PENDING, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_IS_FAV, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_DATE_TRASHED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_HIDDEN, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_PARENT_ID, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_RELATIVE_PATH, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_ORIENTATION, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_LATITUDE, MEMBER_TYPE_DOUBLE },
    { PhotoColumn::PHOTO_LONGITUDE, MEMBER_TYPE_DOUBLE },
    { PhotoColumn::PHOTO_LCD, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_HEIGHT, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_WIDTH, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_LCD_VISIT_TIME, MEMBER_TYPE_INT64 },
    { AudioColumn::AUDIO_ALBUM, MEMBER_TYPE_STRING },
    { AudioColumn::AUDIO_ARTIST, MEMBER_TYPE_STRING },
    { DocumentColumn::DOCUMENT_LCD, MEMBER_TYPE_STRING },
    { DocumentColumn::DOCUMENT_LCD_VISIT_TIME, MEMBER_TYPE_INT64 }
};

namespace {
void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        AudioColumn::AUDIOS_TABLE,
        DocumentColumn::DOCUMENTS_TABLE,
        ASSET_UNIQUE_NUMBER_TABLE
        // todo: album tables
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

struct UniqueMemberValuesBucket {
    string assetMediaType;
    int32_t startNumber;
};

void PrepareUniqueNumberTable()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get g_rdbstore");
        return;
    }
    auto store = g_rdbStore->GetRaw();
    if (store == nullptr) {
        MEDIA_ERR_LOG("can not get store");
        return;
    }
    string queryRowSql = "SELECT COUNT(*) as count FROM " + ASSET_UNIQUE_NUMBER_TABLE;
    auto resultSet = store->QuerySql(queryRowSql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get AssetUniqueNumberTable count");
        return;
    }
    if (GetInt32Val("count", resultSet) != 0) {
        MEDIA_DEBUG_LOG("AssetUniqueNumberTable is already inited");
        return;
    }

    UniqueMemberValuesBucket imageBucket = { IMAGE_ASSET_TYPE, 1 };
    UniqueMemberValuesBucket videoBucket = { VIDEO_ASSET_TYPE, 1 };
    UniqueMemberValuesBucket audioBucket = { AUDIO_ASSET_TYPE, 1 };

    vector<UniqueMemberValuesBucket> uniqueNumberValueBuckets = {
        imageBucket, videoBucket, audioBucket
    };

    for (const auto& uniqueNumberValueBucket : uniqueNumberValueBuckets) {
        ValuesBucket valuesBucket;
        valuesBucket.PutString(ASSET_MEDIA_TYPE, uniqueNumberValueBucket.assetMediaType);
        valuesBucket.PutInt(UNIQUE_NUMBER, uniqueNumberValueBucket.startNumber);
        int64_t outRowId = -1;
        int32_t insertResult = store->Insert(outRowId, ASSET_UNIQUE_NUMBER_TABLE, valuesBucket);
        if (insertResult != NativeRdb::E_OK || outRowId <= 0) {
            MEDIA_ERR_LOG("Prepare smartAlbum failed");
        }
    }
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        AudioColumn::CREATE_AUDIO_TABLE,
        DocumentColumn::CREATE_DOCUMENT_TABLE,
        CREATE_ASSET_UNIQUE_NUMBER_TABLE
        // todo: album tables
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
    PrepareUniqueNumberTable();
}

void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    
    system("rm -rf /storage/media/local/files/*");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/media/100/local/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    SetTables();
}

string GetFileAssetValueToStr(FileAsset &fileAsset, const string &column)
{
    // judge type
    auto member = fileAsset.GetMemberValue(column);
    int type = -1;
    if (get_if<int32_t>(&member)) {
        type = MEMBER_TYPE_INT32;
    } else if (get_if<int64_t>(&member)) {
        type = MEMBER_TYPE_INT64;
    } else if (get_if<string>(&member)) {
        type = MEMBER_TYPE_STRING;
    } else {
        MEDIA_ERR_LOG("Can not find this type");
        return "";
    }

    auto res = fileAsset.GetMemberValue(column);
    switch (type) {
        case MEMBER_TYPE_INT32: {
            int32_t resInt = get<int32_t>(res);
            if (resInt != DEFAULT_INT32) {
                return to_string(resInt);
            }
            break;
        }
        case MEMBER_TYPE_INT64: {
            int64_t resLong = get<int64_t>(res);
            if (resLong != DEFAULT_INT64) {
                return to_string(resLong);
            }
            break;
        }
        case MEMBER_TYPE_STRING: {
            string resStr = get<string>(res);
            if (!resStr.empty()) {
                return resStr;
            }
            return "";
        }
        default: {
            return "";
        }
    }
    return "0";
}

bool QueryAndVerifyPhotoAsset(const string &columnName, const string &value,
    const unordered_map<string, string> &verifyColumnAndValuesMap)
{
    string querySql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
        columnName + "='" + value + "';";

    MEDIA_DEBUG_LOG("querySql: %{public}s", querySql.c_str());
    auto resultSet = g_rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Get resultSet failed");
        return false;
    }
    
    int32_t resultSetCount = 0;
    int32_t ret = resultSet->GetRowCount(resultSetCount);
    if (ret != NativeRdb::E_OK || resultSetCount <= 0) {
        MEDIA_ERR_LOG("resultSet row count is 0");
        return false;
    }

    shared_ptr<FetchResult<FileAsset>> fetchFileResult = make_shared<FetchResult<FileAsset>>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Get fetchFileResult failed");
        return false;
    }
    auto fileAsset = fetchFileResult->GetObjectFromRdb(resultSet, 0);
    if (fileAsset == nullptr || fileAsset->GetId() < 0) {
        return false;
    }
    if (fileAsset != nullptr) {
        for (const auto &iter : verifyColumnAndValuesMap) {
            string resStr = GetFileAssetValueToStr(*fileAsset, iter.first);
            if (resStr.empty()) {
                MEDIA_ERR_LOG("verify failed! Param %{public}s is empty", resStr.c_str());
                return false;
            }
            if (resStr != iter.second) {
                MEDIA_ERR_LOG("verify failed! Except %{public}s param %{public}s, actually %{public}s",
                    iter.first.c_str(), iter.second.c_str(), resStr.c_str());
                return false;
            }
        }
    }
    return true;
}

inline int32_t CreatePhotoApi10(int mediaType, const string &displayName)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    if (ret < 0) {
        MEDIA_ERR_LOG("Create Photo failed, errCode=%{public}d", ret);
        return ret;
    }
    return ret;
}

string GetFilePath(int fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return "";
    }

    vector<string> columns = { PhotoColumn::MEDIA_FILE_PATH };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return "";
    }
    auto resultSet = g_rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file Path");
        return "";
    }
    string path = GetStringVal(PhotoColumn::MEDIA_FILE_PATH, resultSet);
    return path;
}

int32_t MakePhotoUnpending(int fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_INVALID_FILEID;
    }

    string path = GetFilePath(fileId);
    if (path.empty()) {
        MEDIA_ERR_LOG("Get path failed");
        return E_INVALID_VALUES;
    }
    int32_t errCode = MediaFileUtils::CreateAsset(path);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Can not create asset");
        return errCode;
    }

    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket values;
    values.PutLong(PhotoColumn::MEDIA_TIME_PENDING, 0);
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t changedRows = -1;
    errCode = g_rdbStore->Update(cmd, changedRows);
    if (errCode != E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("Update pending failed, errCode = %{public}d, changeRows = %{public}d",
            errCode, changedRows);
        return errCode;
    }

    return E_OK;
}

int32_t SetDefaultPhotoApi10(int mediaType, const string &displayName)
{
    int fileId = CreatePhotoApi10(mediaType, displayName);
    if (fileId < 0) {
        MEDIA_ERR_LOG("create photo failed, res=%{public}d", fileId);
        return fileId;
    }
    int32_t errCode = MakePhotoUnpending(fileId);
    if (errCode != E_OK) {
        return errCode;
    }
    return fileId;
}

int32_t GetPhotoAssetCountIndb(const string &key, const string &value)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(key, value);
    vector<string> columns;
    auto resultSet = g_rdbStore->Query(cmd, columns);
    int count = -1;
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get result set count");
        return -1;
    }
    MEDIA_DEBUG_LOG("Get PhotoAsset count in db, key=%{public}s, value=%{public}s, count=%{public}d",
        key.c_str(), value.c_str(), count);
    return count;
}

void SetValuesBucketInUpdate(const string &columnKey, const string &columnValue,
    ValuesBucket &values)
{
    if (FILEASSET_MEMBER_MAP.find(columnKey) == FILEASSET_MEMBER_MAP.end()) {
        MEDIA_ERR_LOG("this columnKey %{public}s is not excepted", columnKey.c_str());
        return;
    }
    int type = FILEASSET_MEMBER_MAP.at(columnKey);
    switch (type) {
        case MEMBER_TYPE_INT32:
            values.PutInt(columnKey, stoi(columnValue));
            break;
        case MEMBER_TYPE_INT64:
            values.PutLong(columnKey, stol(columnValue));
            break;
        case MEMBER_TYPE_STRING:
            values.PutString(columnKey, columnValue);
            break;
        case MEMBER_TYPE_DOUBLE:
            values.PutDouble(columnKey, stod(columnValue));
            break;
        default:
            MEDIA_ERR_LOG("this column type %{public}s is not excepted", columnKey.c_str());
    }
}

static int32_t TestQueryAssetIntParams(int32_t intValue, const string &columnValue)
{
    int32_t columnIntValue = atoi(columnValue.c_str());
    if (columnIntValue == intValue) {
        return E_OK;
    } else {
        MEDIA_ERR_LOG("TestQueryAssetIntParams failed, intValue=%{public}d, columnValue=%{public}s",
            intValue, columnValue.c_str());
        return E_INVALID_VALUES;
    }
}

static int32_t TestQueryAssetLongParams(int64_t longValue, const string &columnValue)
{
    int64_t columnLongValue = atol(columnValue.c_str());
    if (columnLongValue == longValue) {
        return E_OK;
    } else {
        MEDIA_ERR_LOG("TestQueryAssetLongParams failed, intValue=%{public}ld, columnValue=%{public}s",
            (long) longValue, columnValue.c_str());
        return E_INVALID_VALUES;
    }
}

static int32_t TestQueryAssetDoubleParams(double doubleValue, const string &columnValue)
{
    double columnDoubleValue = stod(columnValue);
    if (columnDoubleValue == doubleValue) {
        return E_OK;
    } else {
        MEDIA_ERR_LOG("TestQueryAssetDoubleParams failed, intValue=%{public}lf, columnValue=%{public}s",
            doubleValue, columnValue.c_str());
        return E_INVALID_VALUES;
    }
}

static int32_t TestQueryAssetStringParams(const string &stringValue, const string &columnValue)
{
    if (columnValue == stringValue) {
        return E_OK;
    } else {
        MEDIA_ERR_LOG("TestQueryAssetStringParams failed, stringValue=%{public}s, columnValue=%{public}s",
            stringValue.c_str(), columnValue.c_str());
        return E_INVALID_VALUES;
    }
}

int32_t TestQueryAsset(const string &queryKey, const string &queryValue, const string &columnKey,
    const string &columnValue, MediaLibraryApi api)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY, api);
    cmd.GetAbsRdbPredicates()->EqualTo(queryKey, queryValue);
    vector<string> columns;
    columns.push_back(columnKey);
    auto queryResultSet = rdbStore->Query(cmd, columns);
    if (queryResultSet != nullptr && queryResultSet->GoToFirstRow() == NativeRdb::E_OK) {
        int type = FILEASSET_MEMBER_MAP.at(columnKey);
        switch (type) {
            case MEMBER_TYPE_INT32: {
                int intValue = GetInt32Val(columnKey, queryResultSet);
                return TestQueryAssetIntParams(intValue, columnValue);
            }
            case MEMBER_TYPE_INT64: {
                long longValue = GetInt64Val(columnKey, queryResultSet);
                return TestQueryAssetLongParams(longValue, columnValue);
            }
            case MEMBER_TYPE_STRING: {
                string value = GetStringVal(columnKey, queryResultSet);
                return TestQueryAssetStringParams(value, columnValue);
            }
            case MEMBER_TYPE_DOUBLE: {
                double doubleValue = get<double>(ResultSetUtils::GetValFromColumn(columnKey,
                    queryResultSet, TYPE_DOUBLE));
                return TestQueryAssetDoubleParams(doubleValue, columnValue);
            }
            default: {
                MEDIA_ERR_LOG("this column type %{public}s is not excepted", columnKey.c_str());
                return E_INVALID_VALUES;
            }
        }
    } else {
        MEDIA_ERR_LOG("Query Failed");
        return E_HAS_DB_ERROR;
    }
}
} // namespace

void TestPhotoCreateParamsApi10(const string &displayName, int32_t type, int32_t result)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(MediaColumn::MEDIA_TYPE, type);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    EXPECT_EQ(ret, result);
}

void TestPhotoDeleteParamsApi10(OperationObject oprnObject, int32_t fileId, ExceptIntFunction func)
{
    MediaLibraryCommand cmd(oprnObject, OperationType::DELETE, MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Delete(cmd);
    func(ret);
}

void TestPhotoUpdateParamsApi10(const string &predicateColumn, const string &predicateValue,
    const unordered_map<string, string> &updateColumns, ExceptIntFunction func)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    for (auto &iter : updateColumns) {
        SetValuesBucketInUpdate(iter.first, iter.second, values);
    }
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(predicateColumn, predicateValue);
    int32_t ret = MediaLibraryPhotoOperations::Update(cmd);
    func(ret);
}

void TestPhotoUpdateByQueryApi10(const string &predicateColumn, const string &predicateValue,
    const unordered_map<string, string> &checkColumns, int32_t result)
{
    for (auto &iter : checkColumns) {
        int32_t errCode = TestQueryAsset(predicateColumn, predicateValue, iter.first, iter.second,
            MediaLibraryApi::API_OLD);
        EXPECT_EQ(errCode, result);
    }
}

void TestPhotoUpdateParamsVerifyFunctionFailed(const string &predicateColumn, const string &predicateValue,
    const unordered_map<string, string> &updateColumns)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    for (auto &iter : updateColumns) {
        SetValuesBucketInUpdate(iter.first, iter.second, values);
    }
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(predicateColumn, predicateValue);
    int32_t ret = MediaLibraryAssetOperations::UpdateOperation(cmd);
    MEDIA_INFO_LOG("column:%{public}s, predicates:%{public}s, ret:%{public}d",
        predicateColumn.c_str(), predicateValue.c_str(), ret);
    EXPECT_EQ(ret, E_INVALID_VALUES);
}

void TestPhotoOpenParamsApi10(int32_t fileId, const string &mode, ExceptIntFunction func)
{
    string uriString = MediaFileUtils::GetMediaTypeUriV10(MediaType::MEDIA_TYPE_IMAGE);
    uriString += "/" + to_string(fileId);
    Uri uri(uriString);
    MediaLibraryCommand cmd(uri);
    int32_t fd = MediaLibraryPhotoOperations::Open(cmd, mode);
    func(fd);
    if (fd > 0) {
        close(fd);
        MediaLibraryInotify::GetInstance()->RemoveByFileUri(cmd.GetUriStringWithoutSegment(),
            MediaLibraryApi::API_10);
    }
}

void TestPhotoCloseParamsApi10(int32_t fileId, ExceptIntFunction func)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CLOSE);
    ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Close(cmd);
    func(ret);
}

void MediaLibraryPhotoOperationsTest::SetUpTestCase()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (g_rdbStore == nullptr || g_rdbStore->GetRaw() == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
}

void MediaLibraryPhotoOperationsTest::TearDownTestCase()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    
    system("rm -rf /storage/media/local/files/*");
    CleanTestTables();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(1));
    MEDIA_INFO_LOG("Clean is finish");
}

void MediaLibraryPhotoOperationsTest::SetUp()
{
    if (g_rdbStore == nullptr || g_rdbStore->GetRaw() == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    ClearAndRestart();
}

void MediaLibraryPhotoOperationsTest::TearDown()
{}

const string CHAR256_ENGLISH =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const string CHAR256_CHINESE =
    "中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中"
    "中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中";

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_create_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_create_api10_test_001");
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE,
        MediaLibraryApi::API_10);
    string name = "photo.jpg";
    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, name);
    values.PutInt(MediaColumn::MEDIA_TYPE, MediaType::MEDIA_TYPE_IMAGE);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    EXPECT_GE(ret, 0);
    unordered_map<string, string> verifyMap = {
        { PhotoColumn::MEDIA_TITLE, "photo" },
        { PhotoColumn::MEDIA_TYPE, to_string(MediaType::MEDIA_TYPE_IMAGE) }
    };
    bool res = QueryAndVerifyPhotoAsset(PhotoColumn::MEDIA_NAME, name, verifyMap);
    EXPECT_EQ(res, true);
    MEDIA_INFO_LOG("end tdd photo_oprn_create_api10_test_001");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_create_api10_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_create_api10_test_002");
    string defaultRelativePath = "Pictures/1/";
    TestPhotoCreateParamsApi10("", MediaType::MEDIA_TYPE_IMAGE, E_INVALID_DISPLAY_NAME);
    TestPhotoCreateParamsApi10("photo\"\".jpg", MediaType::MEDIA_TYPE_IMAGE, E_INVALID_DISPLAY_NAME);
    TestPhotoCreateParamsApi10(".photo.jpg", MediaType::MEDIA_TYPE_IMAGE, E_INVALID_DISPLAY_NAME);
    string englishLongString = CHAR256_ENGLISH + ".jpg";
    TestPhotoCreateParamsApi10(englishLongString, MediaType::MEDIA_TYPE_IMAGE,
        E_INVALID_DISPLAY_NAME);
    string chineseLongString = CHAR256_CHINESE + ".jpg";
    TestPhotoCreateParamsApi10(chineseLongString, MediaType::MEDIA_TYPE_IMAGE,
        E_INVALID_DISPLAY_NAME);
    
    TestPhotoCreateParamsApi10("photo", MediaType::MEDIA_TYPE_IMAGE, E_INVALID_DISPLAY_NAME);
    TestPhotoCreateParamsApi10("photo.", MediaType::MEDIA_TYPE_IMAGE, E_INVALID_DISPLAY_NAME);
    TestPhotoCreateParamsApi10("photo.abc", MediaType::MEDIA_TYPE_IMAGE,
        E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL);
    TestPhotoCreateParamsApi10("photo.mp3", MediaType::MEDIA_TYPE_IMAGE,
        E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL);
    MEDIA_INFO_LOG("end tdd photo_oprn_create_api10_test_002");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_delete_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_delete_api10_test_001");

    // set photo
    int fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < E_OK) {
        MEDIA_ERR_LOG("Set Default photo failed, ret = %{public}d", fileId);
        return;
    }
    string filePath = GetFilePath(fileId);
    if (filePath.empty()) {
        MEDIA_ERR_LOG("Get filePath failed");
        return;
    }

    EXPECT_EQ(MediaFileUtils::IsFileExists(filePath), true);
    int32_t count = GetPhotoAssetCountIndb(PhotoColumn::MEDIA_NAME, "photo.jpg");
    EXPECT_EQ(count, 1);

    // test delete
    static constexpr int LARGE_NUM = 1000;
    TestPhotoDeleteParamsApi10(OperationObject::ASSETMAP, fileId,
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_FILEID); });
    TestPhotoDeleteParamsApi10(OperationObject::FILESYSTEM_PHOTO, fileId + LARGE_NUM,
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_FILEID); });
    TestPhotoDeleteParamsApi10(OperationObject::FILESYSTEM_PHOTO, fileId,
        [] (int32_t result) { EXPECT_GT(result, 0); });

    // test delete result
    EXPECT_EQ(MediaFileUtils::IsFileExists(filePath), false);
    count = GetPhotoAssetCountIndb(PhotoColumn::MEDIA_NAME, "photo.jpg");
    EXPECT_EQ(count, 0);

    MEDIA_INFO_LOG("end tdd photo_oprn_delete_api10_test_001");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_query_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_query_api10_test_001");

    int32_t fileId1 = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo1.jpg");
    if (fileId1 < E_OK) {
        MEDIA_ERR_LOG("Set Default photo failed, ret = %{public}d", fileId1);
        return;
    }

    // Query
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId1));
    vector<string> columns;
    auto resultSet = MediaLibraryPhotoOperations::Query(cmd, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        string name = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        EXPECT_EQ(name, "photo1.jpg");
    } else {
        MEDIA_ERR_LOG("Test first tdd Query failed");
        return;
    }

    MEDIA_INFO_LOG("end tdd photo_oprn_query_api10_test_001");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_query_api10_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_query_api10_test_002");

    int32_t fileId1 = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo1.jpg");
    if (fileId1 < E_OK) {
        MEDIA_ERR_LOG("Set Default photo failed, ret = %{public}d", fileId1);
        return;
    }
    int32_t fileId2 = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo2.jpg");
    if (fileId2 < E_OK) {
        MEDIA_ERR_LOG("Set Default photo failed, ret = %{public}d", fileId2);
        return;
    }

    // Query
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->BeginWrap()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId1))->
        Or()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId2))->EndWrap()->
        OrderByAsc(MediaColumn::MEDIA_ID);
    vector<string> columns;
    auto resultSet = MediaLibraryPhotoOperations::Query(cmd, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        string name = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        EXPECT_EQ(name, "photo1.jpg");
    } else {
        MEDIA_ERR_LOG("Test first tdd Query failed");
        return;
    }

    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string name = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        EXPECT_EQ(name, "photo2.jpg");
    } else {
        MEDIA_ERR_LOG("Test second tdd Query failed");
        return;
    }

    MEDIA_INFO_LOG("end tdd photo_oprn_query_api10_test_002");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_query_api10_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_query_api10_test_003");

    int32_t fileId1 = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo1.jpg");
    if (fileId1 < E_OK) {
        MEDIA_ERR_LOG("Set Default photo failed, ret = %{public}d", fileId1);
        return;
    }

    // Query
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId1));
    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_NAME);
    columns.push_back(MediaColumn::MEDIA_DATE_ADDED);
    auto resultSet = MediaLibraryPhotoOperations::Query(cmd, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        string name = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        EXPECT_EQ(name, "photo1.jpg");
        int64_t dateAdded = GetInt64Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);
        EXPECT_GE(dateAdded, 0L);
        int64_t dateModified = GetInt64Val(MediaColumn::MEDIA_DATE_MODIFIED, resultSet);
        EXPECT_EQ(dateModified, 0L);
    } else {
        MEDIA_ERR_LOG("Test first tdd Query failed");
        return;
    }
    MEDIA_INFO_LOG("end tdd photo_oprn_query_api10_test_003");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_001");
    int32_t fileId = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }

    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "pic.jpg" } },
        [] (int32_t result) { EXPECT_GE(result, E_OK); });
    TestPhotoUpdateByQueryApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "pic.jpg" } }, E_OK);
    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_001");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_002");
    int32_t fileId = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }

    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "" } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "photo\"\".jpg" } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, ".photo.jpg" } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });

    string englishLongString = CHAR256_ENGLISH + ".jpg";
    string chineseLongString = CHAR256_CHINESE + ".jpg";
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, englishLongString } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, chineseLongString } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });

    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "photo" } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "photo." } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "photo.abc" } },
        [] (int32_t result) { EXPECT_EQ(result, E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL); });
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, "photo.mp4" } },
        [] (int32_t result) { EXPECT_EQ(result, E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL); });

    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_002");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_003");
    int32_t fileId = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }

    unordered_map<string, string> updateMap1 = {
        { PhotoColumn::MEDIA_TITLE, "photo1" },
        { PhotoColumn::MEDIA_NAME, "photo2.jpg" }
    };
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId), updateMap1,
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_DISPLAY_NAME); });

    unordered_map<string, string> updateMap2 = {
        { PhotoColumn::MEDIA_TITLE, "photo2" },
        { PhotoColumn::MEDIA_NAME, "photo2.jpg" }
    };
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId), updateMap2,
    [] (int32_t result) { EXPECT_GE(result, E_OK); });

    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_003");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_004");
    int32_t fileId1 = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId1 < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId1);
        return;
    }

    int32_t fileId2 = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "pic.jpg");
    if (fileId2 < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId2);
        return;
    }

    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId1),
        { { PhotoColumn::MEDIA_TITLE, "photo1" } },
        [] (int32_t result) { EXPECT_GE(result, E_OK); });
    TestPhotoUpdateByQueryApi10(PhotoColumn::MEDIA_ID, to_string(fileId1),
        { { PhotoColumn::MEDIA_NAME, "photo1.jpg" } }, E_OK);

    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId2),
        { { PhotoColumn::MEDIA_NAME, "photo2.jpg" } },
        [] (int32_t result) { EXPECT_GE(result, E_OK); });
    TestPhotoUpdateByQueryApi10(PhotoColumn::MEDIA_ID, to_string(fileId2),
        { { PhotoColumn::MEDIA_TITLE, "photo2" } }, E_OK);
    
    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_004");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_005");
    int32_t fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }
    
    MediaLibraryCommand queryPathCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    queryPathCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    vector<string> columns = { PhotoColumn::MEDIA_FILE_PATH };
    auto resultSet = g_rdbStore->Query(queryPathCmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get resultSet");
        return;
    }
    string path = GetStringVal(PhotoColumn::MEDIA_FILE_PATH, resultSet);
    if (path.empty()) {
        MEDIA_ERR_LOG("Get Path failed");
        return;
    }

    string moveToPath = "/storage/media/local/files/Pictures/1.jpg";
    static constexpr int LARGE_NUM = 1000;
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId + LARGE_NUM),
        { { PhotoColumn::MEDIA_FILE_PATH, moveToPath } },
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_VALUES); });
    EXPECT_EQ(MediaFileUtils::IsFileExists(moveToPath), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(path), true);
    TestPhotoUpdateParamsApi10(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_FILE_PATH, moveToPath } },
        [] (int32_t result) { EXPECT_GE(result, E_OK); });
    EXPECT_EQ(MediaFileUtils::IsFileExists(moveToPath), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(path), false);

    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_005");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_006");
    int32_t fileId = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }

    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_ID, "1"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_URI, "datashare:///media/image/1"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_FILE_PATH, ""} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { { PhotoColumn::MEDIA_FILE_PATH, ""}, { PhotoColumn::MEDIA_TITLE, "123" } } });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_SIZE, "12345"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_TITLE, ""} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_NAME, ""} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_THUMBNAIL, "abc"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DATE_MODIFIED, "1000000"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DATE_ADDED, "1000000"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DATE_TAKEN, "1000000"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DURATION, "1000000"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_TIME_PENDING, "1000000"}, { PhotoColumn::MEDIA_TITLE, "123" } });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DATE_TRASHED, "1000000"}, { PhotoColumn::MEDIA_TITLE, "123" } });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_DATE_DELETED, "1000000"}, { PhotoColumn::MEDIA_TITLE, "123" } });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_HIDDEN, "1"}, { PhotoColumn::MEDIA_TITLE, "123" } });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::MEDIA_IS_FAV, "1"}, { PhotoColumn::MEDIA_TITLE, "123" } });

    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_006");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_update_api10_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_update_api10_test_007");
    int32_t fileId = CreatePhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("CreatePhoto In APi10 failed, ret=%{public}d", fileId);
        return;
    }

    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_ORIENTATION, "1"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_LATITUDE, "1"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_LONGITUDE, "1"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_LCD, "12345"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_HEIGHT, "12345"} });
    TestPhotoUpdateParamsVerifyFunctionFailed(PhotoColumn::MEDIA_ID, to_string(fileId),
        { { PhotoColumn::PHOTO_WIDTH, "12345"} });

    MEDIA_INFO_LOG("end tdd photo_oprn_update_api10_test_007");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_open_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_open_api10_test_001");

    int fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("Create photo failed error=%{public}d", fileId);
        return;
    }
    
    static constexpr int LARGE_NUM = 1000;
    TestPhotoOpenParamsApi10(fileId, "",
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_MODE); });
    TestPhotoOpenParamsApi10(fileId, "m",
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_MODE); });
    TestPhotoOpenParamsApi10(fileId + LARGE_NUM, "rw",
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_URI); });
    TestPhotoOpenParamsApi10(fileId, "rw",
        [] (int32_t result) { EXPECT_GE(result, E_OK); });

    MEDIA_INFO_LOG("end tdd photo_oprn_open_api10_test_001");
}

HWTEST_F(MediaLibraryPhotoOperationsTest, photo_oprn_close_api10_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd photo_oprn_close_api10_test_001");

    int fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, "photo.jpg");
    if (fileId < 0) {
        MEDIA_ERR_LOG("Create photo failed error=%{public}d", fileId);
        return;
    }

    static constexpr int LARGE_NUM = 1000;
    TestPhotoCloseParamsApi10(fileId + LARGE_NUM,
        [] (int32_t result) { EXPECT_EQ(result, E_INVALID_FILEID); });

    MEDIA_INFO_LOG("end tdd photo_oprn_close_api10_test_001");
}
} // namespace Media
} // namespace OHOS