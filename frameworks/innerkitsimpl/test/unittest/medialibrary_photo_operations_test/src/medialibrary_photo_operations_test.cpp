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

#define MLOG_TAG "PhotoOperationsTest"

#include "medialibrary_photo_operations_test.h"

#include <fstream>
#include <unistd.h>
#include <unordered_map>

#include "abs_rdb_predicates.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
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
    TestPhotoCloseParamsApi10(fileId,
        [] (int32_t result) { EXPECT_EQ(result, E_OK); });

    MEDIA_INFO_LOG("end tdd photo_oprn_close_api10_test_001");
}
} // namespace Media
} // namespace OHOS