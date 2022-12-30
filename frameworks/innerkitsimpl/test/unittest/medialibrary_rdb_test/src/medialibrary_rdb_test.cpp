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
#define MLOG_TAG "FileExtUnitTest"

#include "medialibrary_rdb_test.h"

#include "appkit/ability_runtime/context/context.h"
#include "medialibrary_rdbstore.h"
#include "ability_context_impl.h"
#include "js_runtime.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_device.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
shared_ptr <MediaLibraryRdbStore> rdbStorePtr = nullptr;
void MediaLibraryExtUnitTest::SetUpTestCase(void)
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    rdbStorePtr = std::make_shared<MediaLibraryRdbStore>(abilityContextImpl);
}

void MediaLibraryExtUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Insert_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    ValuesBucket values;
    string name = "test name";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    string data = "medialib_Insert_test_001";
    values.PutString(MEDIA_DATA_DB_FILE_PATH, data);
    string title = "insert test";
    values.PutString(MEDIA_DATA_DB_TITLE, title);
    int32_t fileId = 1;
    values.PutInt(MEDIA_DATA_DB_ID, fileId);
    cmd.SetValueBucket(values);
    int64_t rowId = 1;
    rdbStorePtr->Init();
    int32_t ret = rdbStorePtr->Insert(cmd, rowId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Insert_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    ValuesBucket values;
    string name = "medialib_Insert_test_002";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    string displayname = "medialib_Insert_test_002/test";
    values.PutString(MEDIA_DATA_DB_NAME, displayname);
    cmd.SetValueBucket(values);
    int64_t rowId = 1;
    int32_t ret = rdbStorePtr->Insert(cmd, rowId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Insert_test_003, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    int64_t rowId = 1;
    int32_t ret = rdbStorePtr->Insert(cmd, rowId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Insert_test_004, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    ValuesBucket values;
    string name = "medialib_Insert_test_004";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    cmd.SetValueBucket(values);
    int64_t rowId = 1;
    rdbStorePtr->Stop();
    int32_t ret = rdbStorePtr->Insert(cmd, rowId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Query_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_RECYCLE_PATH);
    rdbStorePtr->Init();
    auto queryResultSet = rdbStorePtr->Query(cmd, columns);
    EXPECT_NE(queryResultSet, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Query_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_DATE_TRASHED);
    rdbStorePtr->Stop();
    auto queryResultSet = rdbStorePtr->Query(cmd, columns);
    EXPECT_EQ(queryResultSet, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Delete_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    string selection = MEDIA_DATA_DB_ID + " = ? OR "+ MEDIA_DATA_DB_PARENT_ID + " = ?";
    cmd.GetAbsRdbPredicates()->SetWhereClause(selection);
    vector<string> selectionArgs;
    int32_t rowId = 1;
    selectionArgs.push_back(to_string(rowId));
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);
    rdbStorePtr->Init();
    int32_t ret = rdbStorePtr->Delete(cmd, rowId);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Delete_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Stop();
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::DELETE);
    int32_t rowId = 1;
    int32_t ret = rdbStorePtr->Delete(cmd, rowId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Update_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    ValuesBucket valuesBucket;
    string title = "medialib_Update_test_001";
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, title);
    cmd.SetValueBucket(valuesBucket);
    int32_t updatedRows = E_HAS_DB_ERROR;
    rdbStorePtr->Init();
    int32_t ret = rdbStorePtr->Update(cmd, updatedRows);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Update_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    int32_t updatedRows = -1;
    int32_t ret = rdbStorePtr->Update(cmd, updatedRows);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Update_test_003, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Stop();
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    int32_t updatedRows = E_HAS_DB_ERROR;
    int32_t ret = rdbStorePtr->Update(cmd, updatedRows);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QuerySql_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Init();
    auto queryResultSet = rdbStorePtr->QuerySql(QUERY_MEDIA_VOLUME);
    EXPECT_NE(queryResultSet, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QuerySql_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Stop();
    auto queryResultSet = rdbStorePtr->QuerySql(QUERY_MEDIA_VOLUME);
    EXPECT_EQ(queryResultSet, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPullAllTableByDeviceId_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    vector<string> devices;
    devices.push_back("MediaLibrary");
    string testName = "medialib_SyncPullAllTableByDeviceId_test_001";
    rdbStorePtr->Init();
    bool ret = rdbStorePtr->SyncPullAllTableByDeviceId(testName, devices);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPullTable_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    vector<string> devices;
    devices.push_back("SyncPullTable");
    string bundleName = "medialib_SyncPullTable_test_001";
    string tableName = "tableTest";
    bool ret = rdbStorePtr->SyncPullTable(bundleName, tableName, devices, false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPushTable_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    vector<string> devices;
    devices.push_back("SyncPushTable");
    string bundleName = "medialib_SyncPullTable_test_001";
    string tableName = "tableTest";
    bool ret = rdbStorePtr->SyncPushTable(bundleName, tableName, devices, false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_HasDistributedTables_test_001, TestSize.Level0)
{
    MediaLibraryDataCallBack rdbDataCallBack;
    bool ret = rdbDataCallBack.HasDistributedTables();
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_MediaLibraryRdbStoreObserver_test_001, TestSize.Level0)
{
    string bundleName = "medialib_MediaLibraryRdbStoreObserver_test_001";
    std::shared_ptr<MediaLibraryRdbStoreObserver> test = make_shared<MediaLibraryRdbStoreObserver>(bundleName);
    EXPECT_NE(test, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ObtainTableName_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    auto data = rdbStorePtr->ObtainTableName(cmd);
    EXPECT_NE(data, "");
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ExecuteSql_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
    int32_t ret = rdbStorePtr->ExecuteSql(modifySql);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ExecuteSql_test_002, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Stop();
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
    int32_t ret = rdbStorePtr->ExecuteSql(modifySql);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_Stop_test_001, TestSize.Level0)
{
    if (rdbStorePtr == nullptr) {
        exit(1);
    }
    rdbStorePtr->Stop();
    EXPECT_NE(rdbStorePtr, nullptr);
}

} // namespace Media
} // namespace OHOS