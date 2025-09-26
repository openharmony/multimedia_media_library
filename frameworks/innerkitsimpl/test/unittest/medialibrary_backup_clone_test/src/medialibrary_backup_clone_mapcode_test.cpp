/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "BackupCloneTest"

#include "medialibrary_backup_clone_mapcode_test.h"

#define private public
#define protected public
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "clone_source.h"
#include "media_column.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "backup_restore_service.h"
#include "base_restore.h"
#include "clone_restore.h"
#include "clone_restore_analysis_data.h"
#include "clone_restore_geo.h"
#include "clone_restore_classify.h"
#include "video_face_clone.h"
#include "beauty_score_clone.h"
#include "search_index_clone.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "others_clone_restore.h"
#include "photos_dao.h"
#include "photos_data_handler.h"
#include "burst_key_generator.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdbstore.h"

#include "medialibrary_restore.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"
#include "restore_map_code_utils.h"
#include "map_code_upload_checker.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "medialibrary_data_manager.h"
#include "ability_context_impl.h"
#include "restore_map_code_utils.h"
#include "table_event_handler.h"
#undef protected
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const std::string RDB_CONFIG = "/data/storage/el2/base/preferences/rdb_config.xml";
static const std::string RDB_UPGRADE_EVENT = "/data/storage/el2/base/preferences/rdb_upgrade_events.xml";
const std::string RDB_OLD_VERSION = "rdb_old_version";

const int NUMBER_1 = 1;
const int NUMBER_10 = 10;
const int NUMBER_11 = 11;
const int NUMBER_15 = 15;
const int NUMBER_16 = 16;
const int NUMBER_20 = 20;
const int NUMBER_21 = 21;
const int NUMBER_25 = 25;

class RestoreMapCodeCallBack : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int RestoreMapCodeCallBack::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE);
}

int RestoreMapCodeCallBack::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb;

void SetTestTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static int32_t InsertDataToPhotos2()
{
    const std::string photoTable = PhotoColumn::PHOTOS_TABLE;
    int64_t rowId = -1;
    int32_t ret = E_OK;
    for (int i = NUMBER_16; i <= NUMBER_20; i++) {
        NativeRdb::ValuesBucket value;
        value.PutString(PhotoColumn::PHOTO_CLOUD_ID, std::to_string(i));
        value.PutInt(PhotoColumn::MEDIA_ID, -i);
        ret = g_rdbStore->Insert(rowId, photoTable, value);
        std::cout << "rowId: " << rowId << ", ret: " << ret << std::endl;
        if (ret != E_OK) {
            GTEST_LOG_(ERROR) << "insert photoTable table 2 failed";
        }
    }

    for (int i = NUMBER_21; i <= NUMBER_25; i++) {
        NativeRdb::ValuesBucket value;
        value.PutString(PhotoColumn::PHOTO_CLOUD_ID, std::to_string(i));
        value.PutInt(PhotoColumn::MEDIA_ID, i);
        value.PutDouble(PhotoColumn::PHOTO_LATITUDE, stod("0.0"));
        value.PutDouble(PhotoColumn::PHOTO_LONGITUDE, stod("0.0"));
        ret = g_rdbStore->Insert(rowId, photoTable, value);
        std::cout << "rowId: " << rowId << ", ret: " << ret << std::endl;
        if (ret != E_OK) {
            GTEST_LOG_(ERROR) << "insert photoTable table 2 failed";
        }
    }
    return E_OK;
}

static int32_t InsertDataToPhotos()
{
    const std::string photoTable = PhotoColumn::PHOTOS_TABLE;
    int64_t rowId = -1;
    int32_t ret = E_OK;
    for (int i = NUMBER_1; i <= NUMBER_10; i++) {
        NativeRdb::ValuesBucket value;
        value.PutString(PhotoColumn::PHOTO_CLOUD_ID, std::to_string(i));
        value.PutDouble(PhotoColumn::PHOTO_LATITUDE, stod("30.1"));
        value.PutDouble(PhotoColumn::PHOTO_LONGITUDE, stod("130.1"));

        ret = g_rdbStore->Insert(rowId, photoTable, value);
        std::cout << "rowId: " << rowId << ", ret: " << ret << std::endl;
        if (ret != E_OK) {
            GTEST_LOG_(ERROR) << "insert photoTable table 1 failed";
        }
    }

    for (int i = NUMBER_11; i <= NUMBER_15; i++) {
        NativeRdb::ValuesBucket value;
        value.PutString(PhotoColumn::PHOTO_CLOUD_ID, std::to_string(i));
        ret = g_rdbStore->Insert(rowId, photoTable, value);
        std::cout << "rowId: " << rowId << ", ret: " << ret << std::endl;
        if (ret != E_OK) {
            GTEST_LOG_(ERROR) << "insert photoTable table 2 failed";
        }
    }

    InsertDataToPhotos2();
    return E_OK;
}

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE,
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

static int32_t ClearTable(const string &table)
{
    NativeRdb::RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void MediaLibraryBackupCloneMapCodeTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    const string dbPath = "/data/test/medialibrary_map_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    RestoreMapCodeCallBack helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    EXPECT_EQ(ret, E_OK);
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "init g_rdbStore failed";
        exit(1);
    }
    mediaLibraryRdb = g_rdbStore->GetRaw();
    if (mediaLibraryRdb == nullptr) {
        GTEST_LOG_(ERROR) << "init mediaLibraryRdb failed";
        exit(1);
    }
    SetTestTables();
    ClearTable(PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE);
    InsertDataToPhotos();
}

void MediaLibraryBackupCloneMapCodeTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";

    ClearTable(PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);

    g_rdbStore = nullptr;
}

void MediaLibraryBackupCloneMapCodeTest::SetUp() {}

void MediaLibraryBackupCloneMapCodeTest::TearDown() {}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_upgrade_to_mapcode_test_001, TestSize.Level2)
{
    CleanTestTables();
    int32_t errCode = g_rdbStore->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    EXPECT_EQ(errCode, E_OK);

    InsertDataToPhotos();
    NativeRdb::RdbStore *rawPtr = mediaLibraryRdb.get();
    bool ret = MediaLibraryRdbStore::AddPhotoMapTable(*rawPtr);
    EXPECT_EQ(ret, true);

    errCode = E_ERR;
    shared_ptr<NativePreferences::Preferences> prefsEvent =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_UPGRADE_EVENT, errCode);
    MEDIA_INFO_LOG("rdb_upgrade_events prefs errCode: %{public}d", errCode);
    CHECK_AND_RETURN_LOG(prefsEvent != nullptr, "prefsEvent is nullptr");
    string versionKey = "VERSION_ADD_MAP_CODE_TABLE";
    prefsEvent->PutInt(versionKey, 0);
    prefsEvent->FlushSync();
    errCode = E_ERR;
    shared_ptr<NativePreferences::Preferences> prefsConf =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_CONFIG, errCode);
    EXPECT_EQ(errCode == E_OK, true);
    int32_t version = VERSION_ADD_MAP_CODE_TABLE - 1;
    prefsConf->PutInt(RDB_OLD_VERSION, version);
    prefsConf->FlushSync();
    TableEventHandler().OnUpgrade(g_rdbStore, version, MEDIA_RDB_VERSION);

    ret = MediaLibraryRdbStore::AddPhotoMapTableIndex(nullptr);
    EXPECT_EQ(ret, false);
    ret = MediaLibraryRdbStore::AddPhotoMapTableIndex(g_rdbStore);
    EXPECT_EQ(ret, true);
    ret = MediaLibraryRdbStore::AddPhotoMapTableData(nullptr);
    EXPECT_EQ(ret, false);
    ret = MediaLibraryRdbStore::AddPhotoMapTableData(g_rdbStore);
    EXPECT_EQ(ret, true);
}


HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_upgrade_to_mapcode_test_002, TestSize.Level2)
{
    CleanTestTables();
    int32_t errCode = g_rdbStore->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    EXPECT_EQ(errCode, E_OK);

    int32_t ret = PhotoMapCodeOperation::UpgradePhotoMapCode(g_rdbStore);
    EXPECT_EQ(ret, E_OK);

    InsertDataToPhotos();

    errCode = g_rdbStore->ExecuteSql(PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE);
    EXPECT_EQ(errCode, E_OK);

    ret = PhotoMapCodeOperation::UpgradePhotoMapCode(nullptr);
    EXPECT_EQ(ret, E_ERR);

    ret = PhotoMapCodeOperation::UpgradePhotoMapCode(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_upgrade_to_mapcode_test_003, TestSize.Level2)
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefsEvent =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_UPGRADE_EVENT, errCode);
    MEDIA_INFO_LOG("rdb_upgrade_events prefs errCode: %{public}d", errCode);
    CHECK_AND_RETURN_LOG(prefsEvent != nullptr, "prefsEvent is nullptr");
    string versionKey = "VERSION_ADD_MAP_CODE_TABLE";
    prefsEvent->PutInt(versionKey, 0);
    prefsEvent->FlushSync();

    shared_ptr<NativePreferences::Preferences> prefsConf =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_CONFIG, errCode);
    EXPECT_EQ(errCode == E_OK, true);
    int32_t version = VERSION_ADD_MAP_CODE_TABLE - 1;
    prefsConf->PutInt(RDB_OLD_VERSION, version);
    prefsConf->FlushSync();

    int32_t oldVersion = VERSION_ADD_MAP_CODE_TABLE - 1;
    prefsConf->GetInt(RDB_OLD_VERSION, oldVersion);
    EXPECT_EQ(oldVersion != VERSION_ADD_MAP_CODE_TABLE, true);

    if (oldVersion < VERSION_ADD_MAP_CODE_TABLE) {
        NativeRdb::RdbStore *rawPtr = mediaLibraryRdb.get();
        bool ret = MediaLibraryRdbStore::AddPhotoMapTable(*rawPtr);
        EXPECT_EQ(ret, true);
    }
    EXPECT_EQ(oldVersion != VERSION_ADD_MAP_CODE_TABLE, true);

    oldVersion = VERSION_ADD_MAP_CODE_TABLE - 1;
    if (oldVersion < VERSION_ADD_MAP_CODE_TABLE) {
        bool ret = MediaLibraryRdbStore::AddPhotoMapTableIndex(g_rdbStore);
        EXPECT_EQ(ret, true);
        ret = MediaLibraryRdbStore::AddPhotoMapTableData(g_rdbStore);
        EXPECT_EQ(ret, true);
        g_rdbStore->SetOldVersion(VERSION_ADD_MAP_CODE_TABLE);
    }
    prefsConf->GetInt(RDB_OLD_VERSION, oldVersion);
    EXPECT_NE(oldVersion == VERSION_ADD_MAP_CODE_TABLE, true);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_upgrade_to_mapcode_test_004, TestSize.Level2)
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_dirtydata_to_mapcode_test_001, TestSize.Level2)
{
    CleanTestTables();
    int32_t errCode = g_rdbStore->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    EXPECT_EQ(errCode, E_OK);
    InsertDataToPhotos();

    std::shared_ptr<MockMedialibrarySubscriber> subscriber = std::make_shared<MockMedialibrarySubscriber>();
    subscriber->currentStatus_ = false;
    bool ret = MapCodeUploadChecker::RepairNoMapCodePhoto();
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_dirtydata_to_mapcode_test_002, TestSize.Level2)
{
    CleanTestTables();
    int32_t errCode = g_rdbStore->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    EXPECT_EQ(errCode, E_OK);
    InsertDataToPhotos();

    std::shared_ptr<MockMedialibrarySubscriber> subscriber = std::make_shared<MockMedialibrarySubscriber>();
    EXPECT_CALL(*subscriber, IsCurrentStatusOn()).WillRepeatedly(testing::Return(true));
    subscriber->currentStatus_ = true;
    bool ret = MapCodeUploadChecker::RepairNoMapCodePhoto();
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_to_mapcode_test_001, TestSize.Level2)
{
    CleanTestTables();

    int32_t errCode = g_rdbStore->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    EXPECT_EQ(errCode, E_OK);

    g_rdbStore = nullptr;
    mediaLibraryRdb = nullptr;
    FileInfo fileInfo;
    fileInfo.fileIdNew = 31;
    fileInfo.latitude = 30.12;
    fileInfo.longitude = 130.11;
    vector<FileInfo> fileInfos;
    fileInfos.push_back(fileInfo);
    int32_t ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    mediaLibraryRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfos.clear();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfo.fileIdNew = 2;
    fileInfo.latitude = 0.0;
    fileInfo.longitude = 0.0;
    fileInfos.push_back(fileInfo);
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfos.clear();
    fileInfo.fileIdNew = -2;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    fileInfos.push_back(fileInfo);
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_to_mapcode_test_0011, TestSize.Level2)
{
    FileInfo fileInfo;
    vector<FileInfo> fileInfos;
    fileInfo.fileIdNew = 33;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    fileInfos.push_back(fileInfo);
    int32_t ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    ret = MapCodeUploadChecker::QueryMapCodeCount(1);
    EXPECT_EQ(ret > 0, E_OK);
    std::vector<CheckedMapCodeInfo> result1 = MapCodeUploadChecker::QueryMapCodeInfo(1);
    EXPECT_EQ(result1.size() > 0, true);

    int32_t curFileId = 1;
    MapCodeUploadChecker::HandleMapCodeInfos(result1, curFileId);
    EXPECT_EQ(curFileId > 1, true);

    ret = MapCodeUploadChecker::QueryMapCodeCount(100);
    EXPECT_NE(ret, E_OK);
    std::vector<CheckedMapCodeInfo> result100 = MapCodeUploadChecker::QueryMapCodeInfo(1);
    EXPECT_EQ(result100.size() > 0, false);
    curFileId = 100;
    MapCodeUploadChecker::HandleMapCodeInfos(result100, curFileId);
    EXPECT_EQ(curFileId == 100, true);

    int32_t errCode = g_rdbStore->ExecuteSql(PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_to_mapcode_test_0012, TestSize.Level2)
{
    InsertDataToPhotos();

    FileInfo fileInfo;
    vector<FileInfo> fileInfos;
    fileInfo.fileIdNew = 31;
    fileInfo.latitude = 30.12;
    fileInfo.longitude = 130.11;
    fileInfos.push_back(fileInfo);
    int32_t ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    mediaLibraryRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfos.clear();
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfo.fileIdNew = 2;
    fileInfo.latitude = 0.0;
    fileInfo.longitude = 0.0;
    fileInfos.push_back(fileInfo);
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    fileInfos.clear();
    fileInfo.fileIdNew = -2;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    fileInfos.push_back(fileInfo);
    ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_to_mapcode_test_0013, TestSize.Level2)
{
    InsertDataToPhotos();

    FileInfo fileInfo;
    vector<FileInfo> fileInfos;
    fileInfo.fileIdNew = 33;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    fileInfos.push_back(fileInfo);
    int32_t ret = RestoreMapCodeUtils::FileInfosToMapCode(mediaLibraryRdb, fileInfos);
    EXPECT_EQ(ret, E_OK);

    ret = MapCodeUploadChecker::QueryMapCodeCount(1);
    EXPECT_EQ(ret > 0, E_OK);
    std::vector<CheckedMapCodeInfo> result1 = MapCodeUploadChecker::QueryMapCodeInfo(1);
    EXPECT_EQ(result1.size() > 0, true);

    int32_t curFileId = 1;
    MapCodeUploadChecker::HandleMapCodeInfos(result1, curFileId);
    EXPECT_EQ(curFileId > 1, true);

    ret = MapCodeUploadChecker::QueryMapCodeCount(100);
    EXPECT_NE(ret, E_OK);
    std::vector<CheckedMapCodeInfo> result100 = MapCodeUploadChecker::QueryMapCodeInfo(1);
    EXPECT_EQ(result100.size() > 0, false);
    curFileId = 100;
    MapCodeUploadChecker::HandleMapCodeInfos(result100, curFileId);
    EXPECT_EQ(curFileId == 100, true);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_to_mapcode_test_002, TestSize.Level2)
{
    g_rdbStore = nullptr;
    mediaLibraryRdb = nullptr;
    FileInfo fileInfo;
    fileInfo.fileIdNew = 4;
    fileInfo.latitude = 30.12;
    fileInfo.longitude = 130.11;
    int32_t ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);

    mediaLibraryRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);

    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);

    fileInfo.fileIdNew = 5;
    fileInfo.latitude = 0.0;
    fileInfo.longitude = 0.0;
    ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);

    fileInfo.fileIdNew = -5;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);

    fileInfo.fileIdNew = 6;
    fileInfo.latitude = 10.0;
    fileInfo.longitude = 120.0;
    ret = RestoreMapCodeUtils::FileInfoToMapCode(fileInfo, mediaLibraryRdb);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryBackupCloneMapCodeTest, medialibrary_backup_files_delete_mapcode_test_001, TestSize.Level2)
{
    vector<string> idList;
    vector<string> idListTest = {"DeleteMetadata"};

    bool ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idList);
    EXPECT_NE(ret, true);

    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTest);
    EXPECT_NE(ret, true);

    vector<string> idListTestFive = {"7", "8"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestFive);
    EXPECT_NE(ret, true);

    vector<string> idListTestTwo = {"9"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestTwo);
    EXPECT_NE(ret, true);

    vector<string> idListTestThree = {"10", "99"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestThree);
    EXPECT_NE(ret, true);

    vector<string> idListTestFour = {"11", "DeleteMetadata"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestFour);
    EXPECT_NE(ret, true);

    vector<string> idListTestSix = {"99", "DeleteMetadata"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestSix);
    EXPECT_NE(ret, true);

    vector<string> idListTestSeven = {"12", "13", "14"};
    ret = RestoreMapCodeUtils::DeleteMapCodesByFileIds(idListTestSeven);
    EXPECT_NE(ret, true);
}
} // namespace Media
} // namespace OHOS