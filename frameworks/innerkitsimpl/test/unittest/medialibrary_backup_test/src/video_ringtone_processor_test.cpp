/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "VideoRingtoneProcessorTest"

#include "video_ringtone_processor_test.h"

#include <string>
#include <memory>
#include <vector>

#include "video_ringtone_processor.h"
#include "media_old_photos_column.h"
#include "backup_database_utils.h"
#include "media_app_uri_permission_column.h"

#include "medialibrary_errno.h"
#include "media_log.h"
#include "rdb_store.h"
#include "rdb_open_callback.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "result_set.h"
#include "values_bucket.h"
#include "abs_shared_result_set.h"
#include "os_account_manager.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS::Media {

static const std::string TEST_OLD_DATA_MP4 = "/storage/emulated/0/Ringtones/test_ringtone.mp4";
static const std::string TEST_OLD_DATA_NON_MP4 = "/storage/emulated/0/Ringtones/test_ringtone.avi";
static const std::string TEST_NEW_DATA = "/storage/cloud/files/Photo/1/test_ringtone.mp4";
static const int32_t TEST_MEDIA_ID = 1001;
static const std::string TEST_APP_ID = "com.ohos.ringtonelibrary.ringtonelibrarydata";
static const uint32_t TEST_TOKEN_ID = 12345678;
static const int32_t TEST_USER_ID = 100;

static bool g_mockQueryActiveOsAccountIds = true;
static bool g_mockQueryActiveOsAccountIdsEmpty = false;
} // namespace OHOS::Media

namespace OHOS::AccountSA {
ErrCode OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    using namespace OHOS::Media;
    if (g_mockQueryActiveOsAccountIds) {
        if (!g_mockQueryActiveOsAccountIdsEmpty) {
            ids.push_back(TEST_USER_ID);
        }
        return ERR_OK;
    }
    return E_ERR;
}
}

namespace OHOS::Media {

class MockDataShareHelper : public DataShare::DataShareHelper {
public:
    MockDataShareHelper() = default;
    ~MockDataShareHelper() override = default;

    std::shared_ptr<DataShareResultSet> Query(Uri &uri, const DataSharePredicates &predicates,
        std::vector<std::string> &columns, DatashareBusinessError *error) override
    {
        return mockResultSet_;
    }

    MOCK_METHOD(int, Insert, (Uri &, const DataShare::DataShareValuesBucket &), (override));
    MOCK_METHOD(int, Update, (Uri &, const DataSharePredicates &,
        const DataShare::DataShareValuesBucket &), (override));
    MOCK_METHOD(int, Delete, (Uri &, const DataSharePredicates &), (override));
    MOCK_METHOD(std::shared_ptr<DataShareResultSet>, Query, (Uri &, const DataSharePredicates &,
        std::vector<std::string> &, DataShareOption &, DatashareBusinessError *), (override));
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(std::vector<std::string>, GetFileTypes, (Uri &, const std::string &), (override));
    MOCK_METHOD(int, OpenFile, (Uri &, const std::string &), (override));
    MOCK_METHOD(int, OpenFileWithErrCode, (Uri &, const std::string &, int32_t &), (override));
    MOCK_METHOD(int, OpenRawFile, (Uri &, const std::string &), (override));
    MOCK_METHOD(int, InsertExt, (Uri &, const DataShare::DataShareValuesBucket &, std::string &), (override));
    MOCK_METHOD(int, BatchUpdate, (const UpdateOperations &, std::vector<BatchUpdateResult> &), (override));
    MOCK_METHOD(std::string, GetType, (Uri &), (override));
    MOCK_METHOD(int, BatchInsert, (Uri &, const std::vector<DataShare::DataShareValuesBucket> &), (override));
    MOCK_METHOD(int, ExecuteBatch, (const std::vector<OperationStatement> &, ExecResultSet &), (override));
    MOCK_METHOD(int, RegisterObserver, (const Uri &, const sptr<AAFwk::IDataAbilityObserver> &), (override));
    MOCK_METHOD(int, UnregisterObserver, (const Uri &, const sptr<AAFwk::IDataAbilityObserver> &), (override));
    MOCK_METHOD(void, NotifyChange, (const Uri &), (override));
    MOCK_METHOD(int, RegisterObserverExtProvider, (const Uri &, std::shared_ptr<DataShareObserver>, bool), (override));
    MOCK_METHOD(int, UnregisterObserverExtProvider, (const Uri &, std::shared_ptr<DataShareObserver>), (override));
    MOCK_METHOD(void, NotifyChangeExtProvider, (const DataShareObserver::ChangeInfo &), (override));
    MOCK_METHOD(Uri, NormalizeUri, (Uri &), (override));
    MOCK_METHOD(Uri, DenormalizeUri, (Uri &), (override));
    MOCK_METHOD(int, AddQueryTemplate, (const std::string &, int64_t, Template &), (override));
    MOCK_METHOD(int, DelQueryTemplate, (const std::string &, int64_t), (override));
    MOCK_METHOD(std::vector<OperationResult>, Publish, (const Data &, const std::string &), (override));
    MOCK_METHOD(Data, GetPublishedData, (const std::string &, int &), (override));
    MOCK_METHOD(std::vector<OperationResult>, SubscribeRdbData, (const std::vector<std::string> &,
        const TemplateId &, const std::function<void(const RdbChangeNode &)> &), (override));
    MOCK_METHOD(std::vector<OperationResult>, UnsubscribeRdbData, (const std::vector<std::string> &,
        const TemplateId &), (override));
    MOCK_METHOD(std::vector<OperationResult>, EnableRdbSubs, (const std::vector<std::string> &,
        const TemplateId &), (override));
    MOCK_METHOD(std::vector<OperationResult>, DisableRdbSubs, (const std::vector<std::string> &,
        const TemplateId &), (override));
    MOCK_METHOD(std::vector<OperationResult>, SubscribePublishedData, (const std::vector<std::string> &,
        int64_t, const std::function<void(const PublishedDataChangeNode &)> &), (override));
    MOCK_METHOD(std::vector<OperationResult>, UnsubscribePublishedData, (const std::vector<std::string> &,
        int64_t), (override));
    MOCK_METHOD(std::vector<OperationResult>, EnablePubSubs, (const std::vector<std::string> &, int64_t), (override));
    MOCK_METHOD(std::vector<OperationResult>, DisablePubSubs, (const std::vector<std::string> &, int64_t), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), InsertEx, (Uri &, const DataShareValuesBucket &), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), UpdateEx, (Uri &, const DataSharePredicates &,
        const DataShareValuesBucket &), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), DeleteEx, (Uri &, const DataSharePredicates &), (override));
    MOCK_METHOD(int32_t, UserDefineFunc, (MessageParcel &, MessageParcel &, MessageOption &), (override));

    void SetMockResultSet(std::shared_ptr<DataShareResultSet> resultSet)
    {
        mockResultSet_ = resultSet;
    }

    std::shared_ptr<DataShareResultSet> mockResultSet_;
};

class MockDataShareResultSet : public DataShare::DataShareResultSet {
public:
    MockDataShareResultSet() = default;
    ~MockDataShareResultSet() override = default;

    int GoToFirstRow() override
    {
        return goFirstRowResult_;
    }

    int GetRowCount(int &count) override
    {
        count = rowCount_;
        return E_OK;
    }

    int GetColumnIndex(const std::string &name, int &index) override
    {
        index = 0;
        return E_OK;
    }

    int GetColumnName(int index, std::string &name) override
    {
        name = mockColumnName_;
        return E_OK;
    }

    int GetString(int index, std::string &value) override
    {
        value = mockStringValue_;
        return E_OK;
    }

    MOCK_METHOD(int, GoToNextRow, (), (override));
    MOCK_METHOD(int, GoToPreviousRow, (), (override));
    MOCK_METHOD(int, GoToRow, (int), (override));
    MOCK_METHOD(int, GetColumnCount, (int &), (override));
    MOCK_METHOD(int, GetInt, (int, int &), (override));
    MOCK_METHOD(int, GetLong, (int, int64_t &), (override));
    MOCK_METHOD(int, GetDouble, (int, double &), (override));
    MOCK_METHOD(int, GetBlob, (int, std::vector<uint8_t> &), (override));
    MOCK_METHOD(int, Close, (), (override));
    MOCK_METHOD(bool, IsClosed, (), (const, override));
    MOCK_METHOD(int, GetRowIndex, (int &), (const, override));
    MOCK_METHOD(int, GoTo, (int), (override));
    MOCK_METHOD(int, GoToLastRow, (), (override));
    MOCK_METHOD(int, IsAtFirstRow, (bool &), (const, override));
    MOCK_METHOD(int, IsAtLastRow, (bool &), (override));
    MOCK_METHOD(int, IsStarted, (bool &), (const, override));
    MOCK_METHOD(int, IsEnded, (bool &), (override));
    MOCK_METHOD(int, GetAllColumnNames, (std::vector<std::string> &), (override));

    void SetGoFirstRowResult(int result)
    {
        goFirstRowResult_ = result;
    }

    void SetRowCount(int count)
    {
        rowCount_ = count;
    }

    void SetColumnName(const std::string &name)
    {
        mockColumnName_ = name;
    }

    void SetStringValue(const std::string &value)
    {
        mockStringValue_ = value;
    }

    int goFirstRowResult_ = E_OK;
    int rowCount_ = 0;
    std::string mockColumnName_;
    std::string mockStringValue_;
};

class MockRdbStore : public NativeRdb::RdbStore {
public:
    MockRdbStore() = default;
    ~MockRdbStore() override = default;

    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(const AbsRdbPredicates &predicates,
        const Fields &fields) override
    {
        return mockResultSet_;
    }

    int BatchInsert(int64_t &outRowId, const std::string &table, const Rows &values) override
    {
        outRowId = batchInsertResult_;
        return batchInsertReturnCode_;
    }

    MOCK_METHOD(int, Insert, (int64_t &, const std::string &, const Row &), (override));
    MOCK_METHOD(int, Replace, (int64_t &, const std::string &, const Row &), (override));
    MOCK_METHOD(int, InsertWithConflictResolution, (int64_t &, const std::string &,
        const Row &, Resolution), (override));
    MOCK_METHOD(int, Update, (int &, const std::string &, const Row &, const std::string &,
        const Values &), (override));
    MOCK_METHOD(int, Update, (int &, const Row &, const AbsRdbPredicates &), (override));
    MOCK_METHOD(int, UpdateWithConflictResolution, (int &, const std::string &, const Row &,
        const std::string &, const Olds &, Resolution), (override));
    MOCK_METHOD(int, UpdateWithConflictResolution, (int &, const std::string &, const Row &,
        const std::string &, const Values &, Resolution), (override));
    MOCK_METHOD(int, Delete, (int &, const std::string &, const std::string &, const Olds &), (override));
    MOCK_METHOD(int, Delete, (int &, const std::string &, const std::string &, const Values &), (override));
    MOCK_METHOD(int, ExecuteSql, (const std::string &, const Values &), (override));
    MOCK_METHOD(int, ExecuteAndGetLong, (int64_t &, const std::string &, const Values &), (override));
    MOCK_METHOD(int, ExecuteAndGetString, (std::string &, const std::string &, const Values &), (override));
    MOCK_METHOD(int, ExecuteForLastInsertedRowId, (int64_t &, const std::string &, const Values &), (override));
    MOCK_METHOD(int, ExecuteForChangedRowCount, (int64_t &, const std::string &, const Values &), (override));
    MOCK_METHOD(int, Backup, (const std::string &, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(int, Backup, (const std::string &, const std::vector<uint8_t> &, bool), (override));
    MOCK_METHOD(int, Backup, (), (override));
    MOCK_METHOD(int, Count, (int64_t &, const AbsRdbPredicates &), (override));
    MOCK_METHOD(std::shared_ptr<AbsSharedResultSet>, Query, (int &, bool, const std::string &,
        const Fields &, const std::string &, const Values &, const std::string &, const std::string &,
        const std::string &, const int &, const int &), (override));
    MOCK_METHOD(std::shared_ptr<AbsSharedResultSet>, QuerySql, (const std::string &, const Olds &), (override));
    MOCK_METHOD(std::shared_ptr<AbsSharedResultSet>, QuerySql, (const std::string &, const Values &), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, QueryByStep, (const std::string &, const Olds &), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, QueryByStep, (const std::string &,
        const Values &, bool), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, QueryByStep, (const AbsRdbPredicates &,
        const Fields &, bool), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, QueryByStep, (const AbsRdbPredicates &, const Fields &,
        const QueryOptions &), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, QueryByStep, (const std::string &, const Values &,
        const QueryOptions &), (override));
    MOCK_METHOD(std::shared_ptr<NativeRdb::ResultSet>, RemoteQuery, (const std::string &, const AbsRdbPredicates &,
        const Fields &, int &), (override));
    MOCK_METHOD(int, BeginTransaction, (), (override));
    MOCK_METHOD(int, RollBack, (), (override));
    MOCK_METHOD(int, RollBack, (int64_t), (override));
    MOCK_METHOD(int, Commit, (), (override));
    MOCK_METHOD(int, Commit, (int64_t), (override));
    MOCK_METHOD(bool, IsInTransaction, (), (override));
    MOCK_METHOD(std::string, GetPath, (), (override));
    MOCK_METHOD(bool, IsHoldingConnection, (), (override));
    MOCK_METHOD(bool, IsOpen, (), (const, override));
    MOCK_METHOD(bool, IsReadOnly, (), (const, override));
    MOCK_METHOD(bool, IsMemoryRdb, (), (const, override));
    MOCK_METHOD(int, Restore, (const std::string &, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(int, GetVersion, (int &), (override));
    MOCK_METHOD(int, SetVersion, (int), (override));
    MOCK_METHOD((std::pair<int, int64_t>), Insert, (const std::string &, const Row &, Resolution), (override));
    MOCK_METHOD((std::pair<int, int64_t>), BatchInsert, (const std::string &, const RefRows &), (override));
    MOCK_METHOD((std::pair<int, int64_t>), BatchInsert, (const std::string &, const RefRows &,
        Resolution), (override));
    MOCK_METHOD((std::pair<int32_t, Results>), BatchInsert, (const std::string &, const RefRows &,
        const ReturningConfig &, Resolution), (override));
    MOCK_METHOD((std::pair<int, int>), Update, (const std::string &, const Row &, const std::string &,
        const Values &, Resolution), (override));
    MOCK_METHOD((std::pair<int32_t, Results>), Update, (const Row &, const AbsRdbPredicates &,
        const ReturningConfig &, Resolution), (override));
    MOCK_METHOD(int, Delete, (int &, const AbsRdbPredicates &), (override));
    MOCK_METHOD((std::pair<int32_t, Results>), Delete, (const AbsRdbPredicates &,
        const ReturningConfig &), (override));
    MOCK_METHOD((std::pair<int32_t, ValueObject>), Execute, (const std::string &,
        const Values &, int64_t), (override));
    MOCK_METHOD((std::pair<int32_t, Results>), ExecuteExt, (const std::string &, const Values &), (override));
    MOCK_METHOD((std::pair<int32_t, std::shared_ptr<NativeRdb::ResultSet>>),
        QuerySharingResource, (const AbsRdbPredicates &, const Fields &), (override));
    MOCK_METHOD((std::pair<int32_t, std::shared_ptr<Transaction>>), CreateTransaction, (int32_t), (override));
    MOCK_METHOD((std::pair<int, int64_t>), BeginTrans, (), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), Attach, (const RdbStoreConfig &,
        const std::string &, int32_t), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), Detach, (const std::string &, int32_t), (override));
    MOCK_METHOD(int, ModifyLockStatus, (const AbsRdbPredicates &, bool), (override));
    MOCK_METHOD(int, SetSearchable, (bool), (override));
    MOCK_METHOD(int, CleanDirtyData, (const std::string &, uint64_t), (override));
    MOCK_METHOD(int, InitKnowledgeSchema, (const RdbKnowledgeSchema &), (override));
    MOCK_METHOD(int, ConfigLocale, (const std::string &), (override));
    MOCK_METHOD(int32_t, SetTokenizer, (Tokenizer), (override));
    MOCK_METHOD(int, RegisterAlgo, (const std::string &, ClusterAlgoFunc), (override));
    MOCK_METHOD(int, CleanDirtyLog, (const std::string &, uint64_t), (override));
    MOCK_METHOD(bool, IsSlaveDiffFromMaster, (), (const, override));
    MOCK_METHOD(int32_t, GetDbType, (), (const, override));
    MOCK_METHOD((std::pair<int32_t, uint32_t>), LockCloudContainer, (), (override));
    MOCK_METHOD(int32_t, UnlockCloudContainer, (), (override));
    MOCK_METHOD(int, InterruptBackup, (), (override));
    MOCK_METHOD(int32_t, GetBackupStatus, (), (const, override));
    MOCK_METHOD(ModifyTime, GetModifyTime, (const std::string &, const std::string &,
        std::vector<PRIKey> &), (override));
    MOCK_METHOD(int, GetRebuilt, (RebuiltType &), (override));
    MOCK_METHOD(int, SetDistributedTables, (const std::vector<std::string> &, int32_t,
        const DistributedRdb::DistributedConfig &), (override));
    MOCK_METHOD(std::string, ObtainDistributedTableName, (const std::string &,
        const std::string &, int &), (override));
    MOCK_METHOD(int, Sync, (const SyncOption &, const AbsRdbPredicates &, const AsyncBrief &), (override));
    MOCK_METHOD(int, Sync, (const SyncOption &, const std::vector<std::string> &, const AsyncDetail &), (override));
    MOCK_METHOD(int, Sync, (const SyncOption &, const AbsRdbPredicates &, const AsyncDetail &), (override));
    MOCK_METHOD(int, Subscribe, (const SubscribeOption &, std::shared_ptr<RdbStoreObserver>), (override));
    MOCK_METHOD(int, UnSubscribe, (const SubscribeOption &, std::shared_ptr<RdbStoreObserver>), (override));
    MOCK_METHOD(int, SubscribeObserver, (const SubscribeOption &,
        const std::shared_ptr<RdbStoreObserver> &), (override));
    MOCK_METHOD(int, UnsubscribeObserver, (const SubscribeOption &,
        const std::shared_ptr<RdbStoreObserver> &), (override));
    MOCK_METHOD(int, RegisterAutoSyncCallback, (std::shared_ptr<DetailProgressObserver>), (override));
    MOCK_METHOD(int, UnregisterAutoSyncCallback, (std::shared_ptr<DetailProgressObserver>), (override));
    MOCK_METHOD(int, Notify, (const std::string &), (override));
    MOCK_METHOD(int32_t, Rekey, (const RdbStoreConfig::CryptoParam &), (override));
    MOCK_METHOD(int32_t, RekeyEx, (const RdbStoreConfig::CryptoParam &), (override));

    void SetMockResultSet(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet)
    {
        mockResultSet_ = resultSet;
    }

    void SetBatchInsertResult(int64_t result, int returnCode)
    {
        batchInsertResult_ = result;
        batchInsertReturnCode_ = returnCode;
    }

    std::shared_ptr<NativeRdb::AbsSharedResultSet> mockResultSet_;
    int64_t batchInsertResult_ = 1;
    int batchInsertReturnCode_ = E_OK;
};

class MockOldPhotosResultSet : public NativeRdb::AbsSharedResultSet {
public:
    MockOldPhotosResultSet() = default;
    ~MockOldPhotosResultSet() override = default;

    int GoToFirstRow() override
    {
        return goFirstRowResult_;
    }

    int GetRowCount(int &count) override
    {
        count = rowCount_;
        return E_OK;
    }

    int GetColumnCount(int &count) override
    {
        count = columnCount_;
        return E_OK;
    }

    int GetColumnIndex(const std::string &name, int &index) override
    {
        index = 0;
        return E_OK;
    }

    int GetColumnName(int index, std::string &name) override
    {
        name = columnName_;
        return E_OK;
    }

    int GetInt(int index, int &value) override
    {
        value = intValue_;
        return E_OK;
    }

    int GetString(int index, std::string &value) override
    {
        value = stringValue_;
        return E_OK;
    }

    MOCK_METHOD(int, GoToNextRow, (), (override));
    MOCK_METHOD(int, GoToPreviousRow, (), (override));
    MOCK_METHOD(int, GoToRow, (int), (override));
    MOCK_METHOD(int, GetLong, (int, int64_t &), (override));
    MOCK_METHOD(int, GetDouble, (int, double &), (override));
    MOCK_METHOD(int, GetBlob, (int, std::vector<uint8_t> &), (override));
    MOCK_METHOD(int, Close, (), (override));
    MOCK_METHOD(bool, IsClosed, (), (const, override));
    MOCK_METHOD(int, GetAllColumnNames, (std::vector<std::string> &), (override));
    MOCK_METHOD((std::pair<int, std::vector<std::string>>), GetWholeColumnNames, (), (override));
    MOCK_METHOD(int, GetAsset, (int32_t, ValueObject::Asset &), (override));
    MOCK_METHOD(int, GetAssets, (int32_t, ValueObject::Assets &), (override));
    MOCK_METHOD(int, GetFloat32Array, (int32_t, ValueObject::FloatVector &), (override));
    MOCK_METHOD(int, IsColumnNull, (int, bool &), (override));
    MOCK_METHOD(int, GetRow, (RowEntity &), (override));
    MOCK_METHOD((std::pair<int, std::vector<ValueObject>>), GetRowData, (), (override));
    MOCK_METHOD((std::pair<int, std::vector<std::vector<ValueObject>>>), GetRowsData, (int32_t, int32_t), (override));
    MOCK_METHOD(int, GetColumnType, (int, ColumnType &), (override));
    MOCK_METHOD(int, GetRowIndex, (int &), (const, override));
    MOCK_METHOD(int, GoTo, (int), (override));
    MOCK_METHOD(int, GoToLastRow, (), (override));
    MOCK_METHOD(int, IsAtFirstRow, (bool &), (const, override));
    MOCK_METHOD(int, IsAtLastRow, (bool &), (override));
    MOCK_METHOD(int, IsStarted, (bool &), (const, override));
    MOCK_METHOD(int, IsEnded, (bool &), (override));
    MOCK_METHOD(int, Get, (int32_t, ValueObject &), (override));
    MOCK_METHOD(int, GetSize, (int, size_t &), (override));
    MOCK_METHOD(std::shared_ptr<AppDataFwk::SharedBlock>, GetBlock, (), (override));
    MOCK_METHOD(int32_t, OnGo, (int, int), (override));
    MOCK_METHOD(void, SetBlock, (AppDataFwk::SharedBlock *), (override));

    void SetGoFirstRowResult(int result)
    {
        goFirstRowResult_ = result;
    }

    void SetRowCount(int count)
    {
        rowCount_ = count;
    }

    void SetColumnCount(int count)
    {
        columnCount_ = count;
    }

    void SetColumnName(const std::string &name)
    {
        columnName_ = name;
    }

    void SetIntValue(int value)
    {
        intValue_ = value;
    }

    void SetStringValue(const std::string &value)
    {
        stringValue_ = value;
    }

    int goFirstRowResult_ = E_OK;
    int rowCount_ = 0;
    int columnCount_ = 0;
    std::string columnName_;
    int intValue_ = 0;
    std::string stringValue_;
};

void VideoRingtoneProcessorTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("VideoRingtoneProcessorTest::SetUpTestCase");
}

void VideoRingtoneProcessorTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("VideoRingtoneProcessorTest::TearDownTestCase");
}

void VideoRingtoneProcessorTest::SetUp()
{
    MEDIA_INFO_LOG("VideoRingtoneProcessorTest::SetUp");
}

void VideoRingtoneProcessorTest::TearDown()
{
    MEDIA_INFO_LOG("VideoRingtoneProcessorTest::TearDown");
}

HWTEST_F(VideoRingtoneProcessorTest, QueryMp4RingtonePath_Success_MP4_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryMp4RingtonePath_Success_MP4_Test start");

    VideoRingtoneProcessor processor;

    auto mockHelper = std::make_shared<MockDataShareHelper>();
    auto mockResultSet = std::make_shared<MockDataShareResultSet>();
    
    mockResultSet->SetGoFirstRowResult(E_OK);
    mockResultSet->SetRowCount(1);
    mockResultSet->SetColumnName("VALUE");
    mockResultSet->SetStringValue(TEST_OLD_DATA_MP4);
    mockHelper->SetMockResultSet(mockResultSet);

    EXPECT_CALL(*mockResultSet, Close())
        .WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*mockHelper, Release())
        .WillRepeatedly(testing::Return(true));

    processor.dataShareHelper_ = mockHelper;
    processor.settingsDataUri_ = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100";

    std::string result = processor.QueryMp4RingtonePath("ringtone_path");

    EXPECT_EQ(result, TEST_OLD_DATA_MP4);

    MEDIA_INFO_LOG("QueryMp4RingtonePath_Success_MP4_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, QueryMp4RingtonePath_Empty_Result_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryMp4RingtonePath_Empty_Result_Test start");

    VideoRingtoneProcessor processor;

    auto mockHelper = std::make_shared<MockDataShareHelper>();
    auto mockResultSet = std::make_shared<MockDataShareResultSet>();
    
    mockResultSet->SetGoFirstRowResult(E_OK);
    mockResultSet->SetRowCount(1);
    mockResultSet->SetColumnName("VALUE");
    mockResultSet->SetStringValue("");
    mockHelper->SetMockResultSet(mockResultSet);

    EXPECT_CALL(*mockResultSet, Close())
        .WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*mockHelper, Release())
        .WillRepeatedly(testing::Return(true));

    processor.dataShareHelper_ = mockHelper;
    processor.settingsDataUri_ = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100";

    std::string result = processor.QueryMp4RingtonePath("ringtone_path");

    EXPECT_TRUE(result.empty());

    MEDIA_INFO_LOG("QueryMp4RingtonePath_Empty_Result_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, QueryMp4RingtonePath_Null_Helper_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("QueryMp4RingtonePath_Null_Helper_Test start");

    VideoRingtoneProcessor processor;
    processor.dataShareHelper_ = nullptr;

    std::string result = processor.QueryMp4RingtonePath("ringtone_path");

    EXPECT_TRUE(result.empty());

    MEDIA_INFO_LOG("QueryMp4RingtonePath_Null_Helper_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, IsMp4VideoFile_Valid_Mp4_Lowercase_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsMp4VideoFile_Valid_Mp4_Lowercase_Test start");

    VideoRingtoneProcessor processor;

    bool result = processor.IsMp4VideoFile("/storage/emulated/0/Ringtones/test.mp4");

    EXPECT_TRUE(result);

    MEDIA_INFO_LOG("IsMp4VideoFile_Valid_Mp4_Lowercase_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, IsMp4VideoFile_Invalid_Avi_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("IsMp4VideoFile_Invalid_Avi_Test start");

    VideoRingtoneProcessor processor;

    bool result = processor.IsMp4VideoFile("/storage/emulated/0/Ringtones/test.avi");

    EXPECT_FALSE(result);

    MEDIA_INFO_LOG("IsMp4VideoFile_Invalid_Avi_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, GetUrisByOldUrisInner_Success_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetUrisByOldUrisInner_Success_Test start");

    VideoRingtoneProcessor processor;

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    auto mockOldPhotosResultSet = std::make_shared<MockOldPhotosResultSet>();
    
    mockOldPhotosResultSet->SetGoFirstRowResult(E_OK);
    mockOldPhotosResultSet->SetRowCount(1);
    mockOldPhotosResultSet->SetColumnCount(2);
    mockOldPhotosResultSet->SetIntValue(TEST_MEDIA_ID);
    mockOldPhotosResultSet->SetStringValue(TEST_NEW_DATA);
    mockRdbStore->SetMockResultSet(mockOldPhotosResultSet);

    EXPECT_CALL(*mockOldPhotosResultSet, IsColumnNull(testing::_, testing::_))
        .WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*mockOldPhotosResultSet, Close())
        .WillRepeatedly(testing::Return(E_OK));

    processor.rdbStore_ = mockRdbStore;

    int32_t mediaId = -1;
    std::string newUri = processor.GetUrisByOldUrisInner(TEST_OLD_DATA_MP4, mediaId);

    EXPECT_EQ(mediaId, TEST_MEDIA_ID);
    EXPECT_EQ(newUri, TEST_NEW_DATA);

    MEDIA_INFO_LOG("GetUrisByOldUrisInner_Success_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, GetUrisByOldUrisInner_Null_RdbStore_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetUrisByOldUrisInner_Null_RdbStore_Test start");

    VideoRingtoneProcessor processor;
    processor.rdbStore_ = nullptr;

    int32_t mediaId = -1;
    std::string newUri = processor.GetUrisByOldUrisInner(TEST_OLD_DATA_MP4, mediaId);

    EXPECT_EQ(mediaId, -1);
    EXPECT_TRUE(newUri.empty());

    MEDIA_INFO_LOG("GetUrisByOldUrisInner_Null_RdbStore_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, SetPermissionForFile_Success_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("SetPermissionForFile_Success_Test start");

    VideoRingtoneProcessor processor;

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    
    mockRdbStore->SetBatchInsertResult(1, E_OK);
    
    processor.rdbStore_ = mockRdbStore;

    int32_t ret = processor.SetPermissionForFile(TEST_APP_ID, TEST_TOKEN_ID, TEST_MEDIA_ID);

    EXPECT_EQ(ret, E_OK);

    MEDIA_INFO_LOG("SetPermissionForFile_Success_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, SetPermissionForFile_Null_RdbStore_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("SetPermissionForFile_Null_RdbStore_Test start");

    VideoRingtoneProcessor processor;
    processor.rdbStore_ = nullptr;

    int32_t ret = processor.SetPermissionForFile(TEST_APP_ID, TEST_TOKEN_ID, TEST_MEDIA_ID);

    EXPECT_EQ(ret, E_FAIL);

    MEDIA_INFO_LOG("SetPermissionForFile_Null_RdbStore_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, GetActiveUserId_Success_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetActiveUserId_Success_Test start");

    VideoRingtoneProcessor processor;

    bool ret = processor.GetActiveUserId();

    EXPECT_TRUE(ret);
    EXPECT_GE(processor.userId_, 0);

    MEDIA_INFO_LOG("GetActiveUserId_Success_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, InitDataShareHelper_Success_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("InitDataShareHelper_Success_Test start");

    VideoRingtoneProcessor processor;
    processor.userId_ = TEST_USER_ID;

    int32_t ret = processor.InitDataShareHelper();

    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(processor.dataShareHelper_ != nullptr);
    EXPECT_FALSE(processor.settingsDataUri_.empty());

    MEDIA_INFO_LOG("InitDataShareHelper_Success_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, ConvertOldUriToNewUri_Success_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("ConvertOldUriToNewUri_Success_Test start");

    VideoRingtoneProcessor processor;

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    auto mockOldPhotosResultSet = std::make_shared<MockOldPhotosResultSet>();
    
    mockOldPhotosResultSet->SetGoFirstRowResult(E_OK);
    mockOldPhotosResultSet->SetRowCount(1);
    mockOldPhotosResultSet->SetColumnCount(2);
    mockOldPhotosResultSet->SetIntValue(TEST_MEDIA_ID);
    mockOldPhotosResultSet->SetStringValue(TEST_NEW_DATA);
    mockRdbStore->SetMockResultSet(mockOldPhotosResultSet);

    EXPECT_CALL(*mockOldPhotosResultSet, IsColumnNull(testing::_, testing::_))
        .WillRepeatedly(testing::Return(E_OK));
    EXPECT_CALL(*mockOldPhotosResultSet, Close())
        .WillRepeatedly(testing::Return(E_OK));

    processor.rdbStore_ = mockRdbStore;
    processor.userId_ = TEST_USER_ID;

    std::string newUri;
    int32_t ret = processor.ConvertOldUriToNewUri(TEST_OLD_DATA_MP4, newUri);

    processor.SetVideoFilePermission(TEST_OLD_DATA_MP4);

    std::shared_ptr<NativeRdb::RdbStore> rdbStore = mockRdbStore;

    processor.ProcessVideoRingtones(rdbStore);

    EXPECT_EQ(ret, E_OK);

    MEDIA_INFO_LOG("ConvertOldUriToNewUri_Success_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, ConvertOldUriToNewUri_Empty_OldUri_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("ConvertOldUriToNewUri_Empty_OldUri_Test start");

    VideoRingtoneProcessor processor;

    std::string newUri;
    int32_t ret = processor.ConvertOldUriToNewUri("", newUri);

    std::shared_ptr<NativeRdb::RdbStore> rdbStore = nullptr;

    processor.SetVideoFilePermission("");

    processor.ProcessVideoRingtones(rdbStore);

    EXPECT_EQ(ret, E_FAIL);

    MEDIA_INFO_LOG("ConvertOldUriToNewUri_Empty_OldUri_Test end");
}

HWTEST_F(VideoRingtoneProcessorTest, GetAppIdAndTokenId_Invalid_BundleName_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetAppIdAndTokenId_Invalid_BundleName_Test start");

    VideoRingtoneProcessor processor;

    std::string appId;
    uint32_t tokenId = 0;
    int32_t ret = processor.GetAppIdAndTokenId("invalid.bundle.name", TEST_USER_ID, appId, tokenId);

    EXPECT_EQ(ret, E_FAIL);

    MEDIA_INFO_LOG("GetAppIdAndTokenId_Invalid_BundleName_Test end");
}
} // namespace OHOS::Media
