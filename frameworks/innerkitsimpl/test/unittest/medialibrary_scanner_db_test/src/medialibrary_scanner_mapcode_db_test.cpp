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
#include <cstdint>
#include <thread>

#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_scanner_mapcode_db_test.h"
#include "medialibrary_unittest_utils.h"
#include "thumbnail_utils.h"
#define private public
#include "media_scanner_db.h"
#undef private

#include "scanner_map_code_utils.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;

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

void MediaLibraryScannerMapCodeTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    SetTestTables();
    ClearTable(PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE);

    // MediaLibraryUnitTestUtils::CleanTestFiles();
    // MediaLibraryUnitTestUtils::CleanBundlePermission();
}

void MediaLibraryScannerMapCodeTest::TearDownTestCase(void)
{
    // std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    // 数据库数据清空
    ClearTable(PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE);
    ClearTable(PhotoColumn::PHOTOS_TABLE);
}

// SetUp:Execute before each test case
void MediaLibraryScannerMapCodeTest::SetUp() {}

void MediaLibraryScannerMapCodeTest::TearDown(void) {}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_DeleteMapCode_test_001, TestSize.Level1)
{
    vector<string> idList;
    vector<string> idListTest = {"DeleteMetadata"};

    bool ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idList);
    EXPECT_EQ(ret, true);

    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTest);
    EXPECT_EQ(ret, true);

    vector<string> idListTestFive = {"1", "2"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestFive);
    EXPECT_EQ(ret, true);

    vector<string> idListTestTwo = {"3"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestTwo);
    EXPECT_EQ(ret, true);

    vector<string> idListTestThree = {"4", "99"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestThree);
    EXPECT_EQ(ret, true);

    vector<string> idListTestFour = {"5", "DeleteMetadata"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestFour);
    EXPECT_EQ(ret, true);

    vector<string> idListTestSix = {"99", "DeleteMetadata"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestSix);
    EXPECT_EQ(ret, true);

    vector<string> idListTestSeven = {"6", "7", "8", "9", "10"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestSeven);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_InsertMapCode_test_001, TestSize.Level1)
{
    Metadata metadata;
    int32_t fileId = -1;
    metadata.SetFileId(fileId);
    bool ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 1;
    metadata.SetFileId(fileId);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = -1;
    double latitude = 0.0;
    double longitude = 0.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = -1;
    latitude = 30.0;
    longitude = 120.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 1;
    latitude = 30.0;
    longitude = 120.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 2;
    latitude = -30.0;
    longitude = 120.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_InsertMapCode_test_0011, TestSize.Level1)
{
    Metadata metadata;
    int32_t fileId = 3;
    double latitude = -30.0;
    double longitude = -120.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    bool ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 4;
    latitude = 0.0;
    longitude = 120.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 5;
    latitude = 30.0;
    longitude = 0.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 6;
    latitude = 0.0;
    longitude = 0.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 6;
    latitude = 40.0;
    longitude = 110.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_InsertMapCode_test_002, TestSize.Level1)
{
    int32_t fileId = -1;
    double latitude = -50.0;
    double longitude = -130.0;
    PhotoMapData photoMapData(fileId, latitude, longitude);
    int32_t result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData, PhotoMapType::UPDATE_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 8;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData1(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData1, PhotoMapType::UPDATE_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 9;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData2(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData2, PhotoMapType::QUERY_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 10;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData3(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData3, PhotoMapType::QUERY_AND_INSERT);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_UpdateMapCode_test_001, TestSize.Level1)
{
    Metadata metadata;
    int32_t fileId = 6;
    double latitude = 50.0;
    double longitude = 130.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    bool ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);

    fileId = 7;
    latitude = -50.0;
    longitude = -130.0;
    metadata.SetFileId(fileId);
    metadata.SetLatitude(latitude);
    metadata.SetLongitude(longitude);
    ret = ScannerMapCodeUtils::MetadataToMapCode(metadata);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_UpdateMapCode_test_002, TestSize.Level1)
{
    int32_t fileId = 8;
    double latitude = -50.0;
    double longitude = -130.0;
    PhotoMapData photoMapData(fileId, latitude, longitude);
    int32_t result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData, PhotoMapType::UPDATE_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 8;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData1(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData1, PhotoMapType::QUERY_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 9;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData2(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData2, PhotoMapType::UPDATE_AND_INSERT);
    EXPECT_EQ(result, E_OK);

    fileId = 9;
    latitude = -50.0;
    longitude = -130.0;
    PhotoMapData photoMapData3(fileId, latitude, longitude);
    result = PhotoMapCodeOperation::GetPhotoMapCode(photoMapData3, PhotoMapType::QUERY_AND_INSERT);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_DeleteMapCode_test_002, TestSize.Level1)
{
    MediaScannerDb mediaScannerDb;
    vector<string> idList;
    vector<string> idListTest = {"DeleteMetadata"};

    bool ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idList);
    EXPECT_EQ(ret, true);

    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTest);
    EXPECT_EQ(ret, true);

    vector<string> idListTestFive = {"1", "2"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestFive);
    EXPECT_EQ(ret, true);

    vector<string> idListTestTwo = {"3"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestTwo);
    EXPECT_EQ(ret, true);

    vector<string> idListTestThree = {"4", "99"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestThree);
    EXPECT_EQ(ret, true);

    vector<string> idListTestFour = {"5", "DeleteMetadata"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestFour);
    EXPECT_EQ(ret, true);

    vector<string> idListTestSix = {"99", "DeleteMetadata"};
    ret = ScannerMapCodeUtils::DeleteMapCodesByFileIds(idListTestSix);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryScannerMapCodeTest, medialib_DeleteMapCode_test_003, TestSize.Level1)
{
    MediaScannerDb mediaScannerDb;
    vector<string> idList;
    vector<string> idListTest = {"DeleteMetadata"};

    int32_t ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idList);
    EXPECT_EQ(ret, E_OK);

    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTest);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTest1 = {"1", "2"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTest1);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTest2 = {"3"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTest2);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTest3 = {"4", "99"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTest3);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTest4 = {"5", "DeleteMetadata"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTest4);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestFive = {"6", "7"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestFive);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestTwo = {"8"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestTwo);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestThree = {"9", "99"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestThree);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestFour = {"10", "DeleteMetadata"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestFour);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestSix = {"99", "DeleteMetadata"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestSix);
    EXPECT_EQ(ret, E_OK);

    vector<string> idListTestSeven = {"11", "12", "13"};
    ret = PhotoMapCodeOperation::RemovePhotosMapCodes(idListTestSeven);
    EXPECT_EQ(ret, E_OK);
}
} // namespace Media
} // namespace OHOS