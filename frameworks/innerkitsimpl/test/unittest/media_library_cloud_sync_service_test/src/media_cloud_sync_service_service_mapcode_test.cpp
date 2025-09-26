/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaCloudSync"

#include "media_cloud_sync_service_service_mapcode_test.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <unistd.h>
#define private public
#include "cloud_media_album_service.h"
#include "medialibrary_unittest_utils.h"
#include "cloud_media_photos_service.h"
#undef private

#define private public
#define protected public
#include "file_utils.h"
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_callback.h"
#include "cloud_media_asset_observer.h"
#include "cloud_media_asset_types.h"
#undef private
#undef protected

#include "cloud_map_code_dao.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"
#include "cloud_media_pull_data_dto.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS::Media::CloudSync {
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

const int NUMBER_1 = 1;
const int NUMBER_10 = 10;
const int NUMBER_11 = 11;
const int NUMBER_15 = 15;
const int NUMBER_16 = 16;
const int NUMBER_20 = 20;
const int NUMBER_21 = 21;
const int NUMBER_25 = 25;

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

static int32_t InsertDataToMapCode()
{
    return E_OK;
}

void CloudMediaSyncServiceMapCodeTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "init g_rdbStore failed";
        exit(1);
    }
    SetTestTables();
    ClearTable(PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE);
    InsertDataToPhotos();

    InsertDataToMapCode();
}

void CloudMediaSyncServiceMapCodeTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    CleanTestTables();

    g_rdbStore = nullptr;
}

void CloudMediaSyncServiceMapCodeTest::SetUp() {}

void CloudMediaSyncServiceMapCodeTest::TearDown() {}

static std::atomic<int> number(0);

int GetNumber()
{
    return ++number;
}

std::string GetTitle(int64_t &timestamp)
{
    return "IMG_" + to_string(timestamp) + "_" + to_string(GetNumber());
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count() + GetNumber();
}

int32_t InsertCloudMapCodeINDb(int64_t &fileId, std::string &data)
{
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    data = "/storage/cloud/files/photo/1/" + title + ".jpg";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE));
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    valuesBucket.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    // 完善数据
    valuesBucket.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertCloudAsset fileId is %{public}s", to_string(fileId).c_str());
    return ret;
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_001, TestSize.Level1)
{
    CloudMediaPhotosService service;
    CloudMediaPullDataDto data1;
    data1.basicFileName = "name1";
    data1.basicFileType = -1;
    data1.hasProperties = true;
    data1.propertiesSourceFileName = "";
    data1.hasAttributes = false;
    std::vector<CloudMediaPullDataDto> pullDatas = {data1};
    std::vector<std::string> failedRecords;
    int32_t ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 0);
    pullDatas.clear();
    failedRecords.clear();
    data1.cloudId = "1";
    failedRecords.push_back("1");
    pullDatas = {data1};
    ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 1);
    pullDatas.clear();
    failedRecords.clear();
    data1.cloudId = "2";
    data1.latitude = 31.2;
    pullDatas = {data1};
    ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 0);
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_0011, TestSize.Level1)
{
    CloudMediaPhotosService service;
    CloudMediaPullDataDto data1;
    std::vector<CloudMediaPullDataDto> pullDatas;
    std::vector<std::string> failedRecords;

    data1.cloudId = "3";
    data1.latitude = 31.2;
    data1.longitude = 131.2;
    CloudMediaPullDataDto data2;
    data2.cloudId = "4";
    data2.latitude = 31.2;
    data2.longitude = 131.2;
    pullDatas = {data1, data2};
    int32_t ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 0);

    pullDatas.clear();
    failedRecords.clear();
    data1.cloudId = "5";
    data1.latitude = 31.2;
    data1.longitude = 131.2;
    pullDatas = {data1};
    ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 0);
    pullDatas.clear();
    failedRecords.clear();
    data1.cloudId = "6";
    data1.latitude = 31.2;
    data1.longitude = 131.2;
    data2.cloudId = "7";
    data2.latitude = 31.2;
    data2.longitude = 131.2;
    CloudMediaPullDataDto data3;
    data2.cloudId = "8";
    data2.latitude = 31.2;
    data2.longitude = 131.2;
    pullDatas = {data1, data2, data3};
    failedRecords = {"8"};
    ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 1);
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_0012, TestSize.Level1)
{
    CloudMediaPhotosService service;
    CloudMediaPullDataDto data1;
    std::vector<CloudMediaPullDataDto> pullDatas;
    std::vector<std::string> failedRecords;

    data1.cloudId = "99";
    data1.latitude = 31.2;
    data1.longitude = 131.2;
    pullDatas = {data1};
    int32_t ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 0);

    pullDatas.clear();
    failedRecords.clear();
    data1.cloudId = "99";
    data1.latitude = 31.2;
    data1.longitude = 131.2;
    pullDatas = {data1};
    failedRecords = {"99"};
    ret = service.MapInsert(pullDatas, failedRecords);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(failedRecords.size(), 1);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_002, TestSize.Level1)
{
    CloudMapCodeDao mapCodeDao;
    std::vector<CloudMediaPullDataDto> pullDatas;
    int32_t ret = mapCodeDao.InsertDatasToMapCode(pullDatas);
    EXPECT_EQ(ret, E_OK);
    CloudMediaPullDataDto data1;
    data1.cloudId = "99";
    pullDatas = {data1};
    ret = mapCodeDao.InsertDatasToMapCode(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    data1.cloudId = "1";
    pullDatas = {data1};
    ret = mapCodeDao.InsertDatasToMapCode(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    data1.cloudId = "11";
    pullDatas = {data1};
    ret = mapCodeDao.InsertDatasToMapCode(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    data1.cloudId = "16";
    pullDatas = {data1};
    ret = mapCodeDao.InsertDatasToMapCode(pullDatas);
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_003, TestSize.Level1)
{
    std::vector<PhotoMapData> photoMapDatas;
    int32_t result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
    EXPECT_EQ(result, E_OK);
    int32_t fileId = 20;
    double latitude = -50.0;
    double longitude = -130.0;
    PhotoMapData photoMapData(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData);
    result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
    EXPECT_EQ(result, E_OK);
    photoMapDatas.clear();
    fileId = -8;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData1(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData1);
    result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
    EXPECT_EQ(result, E_OK);
    photoMapDatas.clear();
    fileId = 21;
    latitude = 0.0;
    longitude = -130.0;
    PhotoMapData photoMapData2(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData2);
    result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
    EXPECT_EQ(result, E_OK);
    photoMapDatas.clear();
    fileId = 22;
    latitude = 0.0;
    longitude = 0.0;
    PhotoMapData photoMapData3(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData3);
    result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
    EXPECT_EQ(result, E_OK);


    photoMapDatas.clear();
    fileId = 23;
    latitude = 20.0;
    longitude = 130.0;
    PhotoMapData photoMapData4(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData4);
    result = PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, g_rdbStore->GetRaw());
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapInsert_Test_004, TestSize.Level1)
{
    std::function<int()> execSql;
    execSql = []() { return NativeRdb::E_OK; };
    int32_t result = PhotoMapCodeOperation::ExecSqlWithRetry(execSql);
    EXPECT_EQ(result, E_OK);
    bool firstCall = true;
    execSql = [&]() {
        if (firstCall) {
            firstCall = false;
            return NativeRdb::E_SQLITE_BUSY;
        } else {
            return NativeRdb::E_OK;
        }
    };
    result = PhotoMapCodeOperation::ExecSqlWithRetry(execSql);
    EXPECT_EQ(result, E_OK);

    execSql = []() { return NativeRdb::E_SQLITE_BUSY; };
    result = PhotoMapCodeOperation::ExecSqlWithRetry(execSql);
    EXPECT_NE(result, E_OK);

    execSql = []() { return NativeRdb::E_SQLITE_IOERR; };
    result = PhotoMapCodeOperation::ExecSqlWithRetry(execSql);
    EXPECT_NE(result, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapUpdate_Test_001, TestSize.Level1)
{
    CloudMediaPhotosService service;
    CloudMediaPullDataDto pullData;
    pullData.localDirty = 0;
    pullData.localDateModified = "";
    pullData.attributesEditedTimeMs = 1;
    pullData.localDateAdded = "";
    int32_t ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "99";
    ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "1";
    ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "11";
    ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "16";
    ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "21";
    ret = service.MapUpdate(pullData);
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapUpdate_Test_002, TestSize.Level1)
{
    CloudMapCodeDao mapCodeDao;
    CloudMediaPullDataDto pullData;

    int32_t ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.localDirty = 0;
    pullData.localDateModified = "";
    pullData.attributesEditedTimeMs = 1;
    pullData.localDateAdded = "";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "99";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "2";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "12";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "17";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "22";
    ret = mapCodeDao.UpdateDataToMapCode(pullData);
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapDelete_Test_001, TestSize.Level1)
{
    CloudMediaPhotosService service;
    CloudMediaPullDataDto pullData;
    pullData.localDirty = 0;
    pullData.localDateModified = "";
    pullData.attributesEditedTimeMs = 1;
    pullData.localDateAdded = "";
    int32_t ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "99";
    ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "1";
    ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "11";
    ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "16";
    ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "21";
    ret = service.MapDelete(pullData);
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapDelete_Test_002, TestSize.Level1)
{
    CloudMapCodeDao mapCodeDao;
    CloudMediaPullDataDto pullData;
    int32_t ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);
    pullData.localDirty = 0;
    pullData.localDateModified = "";
    pullData.attributesEditedTimeMs = 1;
    pullData.localDateAdded = "";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "99";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "2";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "12";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "17";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);

    pullData.cloudId = "22";
    ret = mapCodeDao.DeleteMapCodesByPullData(pullData);
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapDelete_Test_003, TestSize.Level1)
{
    CloudMapCodeDao mapCodeDao;
    std::vector<CloudSync::CloudMediaPullDataDto> pullDatas;

    int32_t ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);

    CloudMediaPullDataDto pullData;
    pullData.localDirty = 0;
    pullData.localDateModified = "";
    pullData.attributesEditedTimeMs = 1;
    pullData.localDateAdded = "";
    pullData.cloudId = "99";
    pullDatas.push_back(pullData);
    ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    pullData.cloudId = "3";
    pullDatas.push_back(pullData);
    ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    pullData.cloudId = "13";
    pullDatas.push_back(pullData);
    ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);
    pullDatas.clear();
    pullData.cloudId = "18";
    pullDatas.push_back(pullData);
    ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_MapDelete_Test_0031, TestSize.Level1)
{
    CloudMapCodeDao mapCodeDao;
    std::vector<CloudSync::CloudMediaPullDataDto> pullDatas;
    CloudMediaPullDataDto pullData;
    pullData.cloudId = "23";
    pullDatas.push_back(pullData);
    int32_t ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);

    pullDatas.clear();
    pullData.cloudId = "99";
    pullDatas.push_back(pullData);
    pullData.cloudId = "4";
    pullDatas.push_back(pullData);
    pullData.cloudId = "13";
    pullDatas.push_back(pullData);
    ret = mapCodeDao.DeleteMapCodesByPullDatas(pullDatas);
    EXPECT_EQ(ret, E_OK);

    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    ret = instance.UpdateCloudMediaAssets();
    EXPECT_EQ(ret, E_OK);

    int64_t fileId4 = 365;
    std::string data1 = "";
    ret = InsertCloudMapCodeINDb(fileId4, data1);
    EXPECT_EQ(ret, E_OK);
    ret = instance.ClearDeletedMapData();
    EXPECT_EQ(ret, E_OK);
}
HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_GetPhotosMapCodesMRS_Test_001, TestSize.Level1)
{
    std::vector<PhotoMapData> photoMapDatas;
    int32_t result = PhotoMapCodeOperation::GetPhotosMapCodesMRS(photoMapDatas, g_rdbStore);
    EXPECT_EQ(result, E_OK);
    int32_t fileId = 20;
    double latitude = -50.0;
    double longitude = -130.0;
    PhotoMapData photoMapData(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData);
    result = PhotoMapCodeOperation::GetPhotosMapCodesMRS(photoMapDatas, g_rdbStore);
    EXPECT_EQ(result, E_OK);
    fileId = 1;
    latitude = 50.0;
    longitude = 130.0;
    PhotoMapData photoMapData1(fileId, latitude, longitude);
    photoMapDatas.push_back(photoMapData1);
    result = PhotoMapCodeOperation::GetPhotosMapCodesMRS(photoMapDatas, nullptr);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::GetPhotosMapCodesMRS(photoMapDatas, g_rdbStore);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaSyncServiceMapCodeTest, CloudMediaPhotosService_DatasToMapCodes_Test_001, TestSize.Level1)
{
    int32_t result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 20, 2, 0);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 4, 26, 30);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 50, 1, 10);
    EXPECT_EQ(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 800, 11, 15);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 35000, 16, 20);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 4, 21, 25);
    EXPECT_NE(result, E_OK);

    result = PhotoMapCodeOperation::DatasToMapCodes(g_rdbStore, 10, 1, 25);
    EXPECT_NE(result, E_OK);
}

}  // namespace OHOS::Media::CloudSync