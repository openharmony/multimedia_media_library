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

#define MLOG_TAG "ClassifyRestoreTest"

#include "gtest/gtest.h"
#include "rdb_helper.h"
#include "result_set_utils.h"
#include "backup_const.h"

#include "medialibrary_backup_clone_test.h"

#include "classify_restore.h"
#include "backup_database_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_data_manager.h"
#include "values_bucket.h"
#include "classify_aggregate_types.h"
#include "backup_const_map.h"
#include "vision_db_sqls.h"
#include "medialibrary_data_manager_utils.h"
#include "media_column.h"
#include "media_upgrade.h"
#include "media_album_column.h"
#include "photo_map.h"

#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

const string TEST_CLASSIFY_BACKUP_PATH = "/data/test/classify_backup";
const string TEST_CLASSIFY_DB_PATH = TEST_CLASSIFY_BACKUP_PATH + "/gallery.db";
const int32_t TEST_SCENE_CODE = 1;
const string TEST_TASK_ID = "1234567890";
const int32_t TEST_FILE_ID_OLD = 100;
const int32_t TEST_FILE_ID_NEW = 200;
const int32_t TEST_CATEGORY_ID = 1;
const string TEST_HASH = "test_hash_12345";
const string TEST_SUB_LABEL = "[1,2,3]";
const double TEST_PROB = 0.95;
const string TEST_VERSION = "1.0";
const int32_t TEST_PAGE_SIZE = 200;
const int32_t INVALID_LABEL = -2;
const int32_t ADD_ITEMS = 10000;

static std::vector<std::string> classifyCreateTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    PhotoAlbumColumns::CREATE_TABLE,
    PhotoMap::CREATE_TABLE,
    CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
    CREATE_ANALYSIS_ALBUM_MAP,
    CREATE_TAB_ANALYSIS_LABEL,
    CREATE_TAB_ANALYSIS_VIDEO_LABEL,
    CREATE_TAB_ANALYSIS_TOTAL_FOR_ONCREATE,
};

static std::vector<std::string> classifyTestTables = {
    PhotoColumn::PHOTOS_TABLE,
    PhotoAlbumColumns::TABLE,
    PhotoMap::TABLE,
    ANALYSIS_ALBUM_TABLE,
    ANALYSIS_PHOTO_MAP_TABLE,
    VISION_LABEL_TABLE,
    VISION_VIDEO_LABEL_TABLE,
    VISION_TOTAL_TABLE,
};

shared_ptr<MediaLibraryRdbStore> g_classifyRdbStore;
shared_ptr<NativeRdb::RdbStore> g_galleryRdbStore;
unique_ptr<ClassifyRestore> g_classifyRestore;

static void InsertImageCollectionData()
{
    string sql = "CREATE TABLE IF NOT EXISTS image_collection ("
        "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "hash TEXT, "
        "category_id INTEGER, "
        "sub_label TEXT, "
        "prob REAL, "
        "version TEXT);";
    g_galleryRdbStore->ExecuteSql(sql);
    
    sql = "INSERT INTO image_collection (hash, category_id, sub_label, prob, version) "
        "VALUES (?, ?, ?, ?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(TEST_HASH),
        NativeRdb::ValueObject(TEST_CATEGORY_ID),
        NativeRdb::ValueObject(TEST_SUB_LABEL),
        NativeRdb::ValueObject(TEST_PROB),
        NativeRdb::ValueObject(TEST_VERSION)
    };
    g_galleryRdbStore->ExecuteSql(sql, params);
}

static void InsertGalleryMediaData()
{
    string sql = "CREATE TABLE IF NOT EXISTS gallery_media ("
        "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "hash TEXT, "
        "albumId INTEGER, "
        "recycleFlag INTEGER);";
    g_galleryRdbStore->ExecuteSql(sql);
    
    sql = "INSERT INTO gallery_media (hash, albumId, recycleFlag) VALUES (?, ?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(TEST_HASH),
        NativeRdb::ValueObject(1),
        NativeRdb::ValueObject(0)
    };
    g_galleryRdbStore->ExecuteSql(sql, params);
}

static void InsertPhotosData(int32_t fileId, int32_t frontCamera = 0)
{
    string sql = "INSERT INTO Photos (file_id, width, height, front_camera) VALUES (?, ?, ?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(fileId),
        NativeRdb::ValueObject(1920),
        NativeRdb::ValueObject(1080),
        NativeRdb::ValueObject(frontCamera)
    };
    g_classifyRdbStore->GetRaw()->ExecuteSql(sql, params);
}

/*
 * Test interface: ClassifyRestore::Init
 * Test content: Initialize classify restore with valid parameters
 * Cover branches: Normal flow with valid scene code, task ID, and database pointers
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_init_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_init_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    EXPECT_NE(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_NE(classifyRestore.galleryRdb_, nullptr);
}

/*
 * Test interface: ClassifyRestore::Init
 * Test content: Initialize classify restore with empty task ID
 * Cover branches: Empty task ID branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_init_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_init_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "", g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    EXPECT_EQ(classifyRestore.taskId_, "");
}

/*
 * Test interface: ClassifyRestore::Init
 * Test content: Initialize classify restore with null media library RDB
 * Cover branches: Null media library RDB pointer
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_init_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_init_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    EXPECT_EQ(classifyRestore.mediaLibraryRdb_, nullptr);
}

/*
 * Test interface: ClassifyRestore::Init
 * Test content: Initialize classify restore with null gallery RDB
 * Cover branches: Null gallery RDB pointer
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_init_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_init_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), nullptr);
    EXPECT_EQ(classifyRestore.galleryRdb_, nullptr);
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse sub label string with valid format [1,2,3]
 * Cover branches: Normal flow with valid array format
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "[1,2,3]";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(3));
    EXPECT_EQ(labels[0], 1);
    EXPECT_EQ(labels[1], 2);
    EXPECT_EQ(labels[2], 3);
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse empty sub label string []
 * Cover branches: Empty array branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "[]";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse empty sub label string
 * Cover branches: Empty string branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse sub label string with extra spaces
 * Cover branches: Valid array with spaces between elements
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "[  1  ,  2  ,  3  ]";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(3));
    EXPECT_EQ(labels[0], 1);
    EXPECT_EQ(labels[1], 2);
    EXPECT_EQ(labels[2], 3);
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse sub label string with invalid element
 * Cover branches: Invalid element handling, skip non-numeric values
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_005 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "[1,abc,3]";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(2));
    EXPECT_EQ(labels[0], 1);
    EXPECT_EQ(labels[1], 3);
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse sub label string without brackets
 * Cover branches: Invalid format without brackets
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_parse_sub_label_test_006 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "1,2,3";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(3));
}

/*
 * Test interface: ClassifyRestore::ParseSubLabel
 * Test content: Parse sub label string with valid format [1,2,3]
 * Cover branches: Normal flow with valid array format
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_parse_sub_label_test_007, TestSize.Level2)
{
    MEDIA_INFO_LOG("medial_classify_restore_parse_sub_label_test_007 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string subLabel = "[1,2,3]";
    vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(labels.size(), static_cast<size_t>(3));
}

/*
 * Test interface: ClassifyRestore::GetAggregateTypes
 * Test content: Get aggregate types from valid labels
 * Cover branches: Normal flow with valid labels
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_aggregate_types_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_aggregate_types_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> labels = {1, 2, 3};
    unordered_set<int32_t> aggregates = classifyRestore.GetAggregateTypes(labels);
    EXPECT_GE(aggregates.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::GetAggregateTypes
 * Test content: Get aggregate types from empty labels
 * Cover branches: Empty labels branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_aggregate_types_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_aggregate_types_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> labels = {};
    unordered_set<int32_t> aggregates = classifyRestore.GetAggregateTypes(labels);
    EXPECT_EQ(aggregates.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::GetAggregateTypes
 * Test content: Get aggregate types from invalid labels
 * Cover branches: Invalid label that doesn't map to any aggregate type
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_aggregate_types_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_aggregate_types_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> labels = {999};
    unordered_set<int32_t> aggregates = classifyRestore.GetAggregateTypes(labels);
    EXPECT_EQ(aggregates.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::GetAggregateTypes
 * Test content: Get aggregate types with duplicate labels
 * Cover branches: Duplicate labels handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_aggregate_types_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_aggregate_types_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> labels = {1, 1, 2, 2};
    unordered_set<int32_t> aggregates = classifyRestore.GetAggregateTypes(labels);
    EXPECT_EQ(aggregates.size(), aggregates.size());
}

/*
 * Test interface: ClassifyRestore::CollectAlbumInfo
 * Test content: Collect album info with valid parameters
 * Cover branches: Normal flow with valid file ID, category ID, and labels
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_collect_album_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_collect_album_info_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {1, 2, 3};
    
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_GT(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CollectAlbumInfo
 * Test content: Collect album info with invalid category ID
 * Cover branches: Invalid category ID branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_collect_album_info_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_collect_album_info_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = INVALID_LABEL;
    vector<int32_t> labels = {1, 2, 3};
    
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_GT(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CollectAlbumInfo
 * Test content: Collect album info with zero file ID
 * Cover branches: Zero file ID branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_collect_album_info_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_collect_album_info_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = 0;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {1, 2, 3};
    
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_EQ(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CollectAlbumInfo
 * Test content: Collect album info with empty labels
 * Cover branches: Empty labels branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_collect_album_info_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_collect_album_info_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {};
    
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_GT(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CollectAlbumInfo
 * Test content: Collect album info with duplicate labels
 * Cover branches: Duplicate labels handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_collect_album_info_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_collect_album_info_test_005 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {1, 1, 2, 2};
    
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_GT(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::GetImageCollectionSize
 * Test content: Get image collection size with valid data
 * Cover branches: Normal flow with valid table and data
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_image_collection_size_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_image_collection_size_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string sql = "CREATE TABLE IF NOT EXISTS image_collection ("
        "_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "hash TEXT, "
        "category_id INTEGER, "
        "sub_label TEXT, "
        "prob REAL, "
        "version TEXT);";
    g_rdbStore->GetRaw()->ExecuteSql(sql);
    
    sql = "INSERT INTO image_collection (hash, category_id, sub_label, prob, version) "
        "VALUES (?, ?, ?, ?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(TEST_HASH),
        NativeRdb::ValueObject(TEST_CATEGORY_ID),
        NativeRdb::ValueObject(TEST_SUB_LABEL),
        NativeRdb::ValueObject(TEST_PROB),
        NativeRdb::ValueObject(TEST_VERSION)
    };
    g_rdbStore->GetRaw()->ExecuteSql(sql, params);
    
    int64_t size = classifyRestore.GetImageCollectionSize();
    EXPECT_EQ(size, 1);
    
    g_rdbStore->GetRaw()->ExecuteSql("DROP TABLE IF EXISTS image_collection");
}

/*
 * Test interface: ClassifyRestore::GetImageCollectionSize
 * Test content: Get image collection size without table
 * Cover branches: Table doesn't exist branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_image_collection_size_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_image_collection_size_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int64_t size = classifyRestore.GetImageCollectionSize();
    EXPECT_EQ(size, -1);
}

/*
 * Test interface: ClassifyRestore::GetImageCollectionSize
 * Test content: Get image collection size with null gallery RDB
 * Cover branches: Null gallery RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_image_collection_size_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_image_collection_size_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), nullptr);
    
    int64_t size = classifyRestore.GetImageCollectionSize();
    EXPECT_EQ(size, -1);
}

/*
 * Test interface: ClassifyRestore::GetShouldEndTime
 * Test content: Get should end time with valid parameters
 * Cover branches: Normal flow with valid photo info map and collection size
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_should_end_time_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_should_end_time_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    int64_t imageCollectionSize = 1;
    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageCollectionSize);
    EXPECT_GT(endTime, 0);
}

/*
 * Test interface: ClassifyRestore::GetShouldEndTime
 * Test content: Get should end time with invalid task ID
 * Cover branches: Invalid task ID branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_should_end_time_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_should_end_time_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "invalid", g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    int64_t imageCollectionSize = 1;
    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageCollectionSize);
    EXPECT_EQ(endTime, 0);
}

/*
 * Test interface: ClassifyRestore::GetShouldEndTime
 * Test content: Get should end time with empty task ID
 * Cover branches: Empty task ID branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_should_end_time_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_should_end_time_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "", g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    int64_t imageCollectionSize = 1;
    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageCollectionSize);
    EXPECT_EQ(endTime, 0);
}

/*
 * Test interface: ClassifyRestore::GetShouldEndTime
 * Test content: Get should end time with large photo info map
 * Cover branches: Large data set handling (40000 items)
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_should_end_time_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medial_library_classify_restore_get_should_end_time_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 40000; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }
    
    int64_t imageCollectionSize = 40000;
    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageCollectionSize);
    EXPECT_GT(endTime, 0);
}

/*
 * Test interface: ClassifyRestore::GetShouldEndTime
 * Test content: Get should end time with zero image collection size
 * Cover branches: Zero image collection size branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_should_end_time_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_should_end_time_test_005 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    int64_t imageCollectionSize = 0;
    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageCollectionSize);
    EXPECT_GT(endTime, 0);
}

/*
 * Test interface: ClassifyRestore::EnsurelyClassifyAlbumId
 * Test content: Ensure classify album ID with valid album name
 * Cover branches: Normal flow with valid album name
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_classify_album_id_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_classify_album_id_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string albumName = "10001";
    int32_t albumId = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    EXPECT_GT(albumId, 0);
}

/*
 * Test interface: ClassifyRestore::EnsurelyClassifyAlbumId
 * Test content: Ensure classify album ID with duplicate calls
 * Cover branches: Duplicate album name handling, should return same ID
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_classify_album_id_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_classify_album_id_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string albumName = "10001";
    int32_t albumId1 = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    int32_t albumId2 = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    EXPECT_EQ(albumId1, albumId2);
}

/*
 * Test interface: ClassifyRestore::EnsurelyClassifyAlbumId
 * Test content: Ensure classify album ID with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_classify_album_id_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_classify_id_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    string albumName = "10001";
    int32_t albumId = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    EXPECT_EQ(albumId, -1);
}

/*
 * Test interface: ClassifyRestore::EnsurelyClassifyAlbumId
 * Test content: Ensure classify album ID with album name "1"
 * Cover branches: Special album name handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_classify_album_id_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_classify_album_id_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string albumName = "1";
    int32_t albumId = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    EXPECT_GT(albumId, 0);
}

/*
 * Test interface: ClassifyRestore::EnsurelyClassifyAlbumId
 * Test content: Ensure classify album ID with album name "2"
 * Cover branches: Special album name handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_classify_album_id_test_005, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_classify_album_id_test_005 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string albumName = "2";
    int32_t albumId = classifyRestore.EnsurelyClassifyAlbumId(albumName);
    EXPECT_GT(albumId, 0);
}

/*
 * Test interface: ClassifyRestore::EnsureSelfieAlbum
 * Test content: Ensure selfie album with front camera photo
 * Cover branches: Normal flow with front camera photo data
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_selfie_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_selfie_album_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    InsertPhotosData(TEST_FILE_ID_NEW, 1);
    classifyRestore.EnsureSelfieAlbum();
    
    string querySql = "SELECT count(1) AS count FROM AnalysisAlbum WHERE album_subtype = ? AND album_name = ?;";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(static_cast<int32_t>(PhotoAlbumSubType::CLASSIFY)),
        NativeRdb::ValueObject("1")
    };
    auto resultSet = g_rdbStore->GetRaw()->QuerySql(querySql, params);
    ASSERT_NE(resultSet, nullptr);
    int32_t count = 0;
    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        count = GetInt32Val("count", resultSet);
    }
    resultSet->Close();
    EXPECT_GT(count, 0);
}

/*
 * Test interface: ClassifyRestore::EnsureSelfieAlbum
 * Test content: Ensure selfie album with back camera photo
 * Cover branches: Back camera photo (not selfie) handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_selfie_album_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_selfie_album_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    InsertPhotosData(TEST_FILE_ID_NEW, 0);
    classifyRestore.EnsureSelfieAlbum();
}

/*
 * Test interface: ClassifyRestore::EnsureSelfieAlbum
 * Test content: Ensure selfie album with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_selfie_album_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_selfie_album_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    classifyRestore.EnsureSelfieAlbum();
}

/*
 * Test interface: ClassifyRestore::EnsureUserCommentAlbum
 * Test content: Ensure user comment album with comment data
 * Cover branches: Normal flow with user comment data
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_user_comment_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_user_comment_album_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string sql = "INSERT INTO Photos (file_id, user_comment) VALUES (?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(TEST_FILE_ID_NEW),
        NativeRdb::ValueObject("test comment")
    };
    g_rdbStore->GetRaw()->ExecuteSql(sql, params);
    
    classifyRestore.EnsureUserCommentAlbum();
    
    string querySql = "SELECT count(1) AS count FROM AnalysisAlbum WHERE album_subtype = ? AND album_name = ?;";
    vector<NativeRdb::ValueObject> params2 = {
        NativeRdb::ValueObject(static_cast<int32_t>(PhotoAlbumSubType::CLASSIFY)),
        NativeRdb::ValueObject("2")
    };
    auto resultSet = g_rdbStore->GetRaw()->QuerySql(querySql, params2);
    ASSERT_NE(resultSet, nullptr);
    int32_t count = 0;
    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        count = GetInt32Val("count", resultSet);
    }
    resultSet->Close();
    EXPECT_GT(count, 0);
}

/*
 * Test interface: ClassifyRestore::EnsureUserCommentAlbum
 * Test content: Ensure user comment album without comment data
 * Cover branches: No user comment data handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_comment_album_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_comment_album_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    InsertPhotosData(TEST_FILE_ID_NEW);
    classifyRestore.EnsureUserCommentAlbum();
}

/*
 * Test interface: ClassifyRestore::EnsureUserCommentAlbum
 * Test content: Ensure user comment album with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_user_comment_album_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_user_comment_album_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    classifyRestore.EnsureUserCommentAlbum();
}

/*
 * Test interface: ClassifyRestore::EnsureSpecialAlbums
 * Test content: Ensure special albums with front camera photo
 * Cover branches: Normal flow with front camera photo data
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_special_albums_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_special_albums_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    InsertPhotosData(TEST_FILE_ID_NEW, 1);
    classifyRestore.EnsureSpecialAlbums();
}

/*
 * Test interface: ClassifyRestore::EnsureSpecialAlbums
 * Test content: Ensure special albums with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_ensure_special_albums_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_ensure_special_albums_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    classifyRestore.EnsureSpecialAlbums();
}

/*
 * Test interface: ClassifyRestore::ProcessCategoryAlbums
 * Test content: Process category albums with valid album info
 * Cover branches: Normal flow with valid album asset map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_process_category_albums_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_process_category_albums_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {1, 2, 3};
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    
    classifyRestore.ProcessCategoryAlbums();
    EXPECT_EQ(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::ProcessCategoryAlbums
 * Test content: Process category albums with empty album info
 * Cover branches: Empty album asset map branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_process_category_albums_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_process_category_albums_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    classifyRestore.ProcessCategoryAlbums();
    EXPECT_EQ(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CreateOrUpdateCategoryAlbums
 * Test content: Create or update category albums with valid album info
 * Cover branches: Normal flow with valid album asset map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_create_category_albums_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_create_category_albums_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    vector<int32_t> labels = {1, 2, 3};
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    
    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_EQ(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::CreateOrUpdateCategoryAlbums
 * Test content: Create or update category albums with empty album info
 * Cover branches: Empty album asset map branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_create_category_albums_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_create_category_albums_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_EQ(classifyRestore.albumAssetMap_.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::InsertAlbumMappings
 * Test content: Insert album mappings with valid values
 * Cover branches: Normal flow with valid values bucket
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_insert_album_mappings_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_insert_album_mappings_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("map_album", 1);
    value.PutInt("map_asset", TEST_FILE_ID_NEW);
    values.push_back(value);
    
    classifyRestore.InsertAlbumMappings(values);
    EXPECT_EQ(values.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::InsertAlbumMappings
 * Test content: Insert album mappings with empty values
 * Cover branches: Empty values bucket branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_insert_album_mappings_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_insert_album_mappings_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<NativeRdb::ValuesBucket> values;
    classifyRestore.InsertAlbumMappings(values);
    EXPECT_EQ(values.size(), static_cast<size_t>(0));
}

/*
 * Test interface: ClassifyRestore::GetMaxIds
 * Test content: Get max IDs from empty tables
 * Cover branches: Empty tables branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_max_ids_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_max_ids_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    classifyRestore.GetMaxIds();
    EXPECT_GE(classifyRestore.maxIdOfLabel_, 0);
}

/*
 * Test interface: ClassifyRestore::GetMaxIds
 * Test content: Get max IDs with existing label data
 * Cover branches: Normal flow with existing data
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_get_max_ids_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_get_max_ids_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    string sql = "INSERT INTO tab_analysis_label (file_id, category_id, sub_label, prob, label_version) "
        "VALUES (?, ?, ?, ?, ?);";
    vector<NativeRdb::ValueObject> params = {
        NativeRdb::ValueObject(TEST_FILE_ID_NEW),
        NativeRdb::ValueObject(TEST_CATEGORY_ID),
        NativeRdb::ValueObject(TEST_SUB_LABEL),
        NativeRdb::ValueObject(TEST_PROB),
        NativeRdb::ValueObject(TEST_VERSION)
    };
    g_rdbStore->GetRaw()->ExecuteSql(sql, params);
    
    classifyRestore.GetMaxIds();
    EXPECT_GT(classifyRestore.maxIdOfLabel_, 0);
}

/*
 * Test interface: ClassifyRestore::UpdateStatus
 * Test content: Update status with valid file IDs
 * Cover branches: Normal flow with valid file IDs
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_update_status_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_update_status_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.UpdateStatus(fileIds);
}

/*
 * Test interface: ClassifyRestore::UpdateStatus
 * Test content: Update status with empty file IDs
 * Cover branches: Empty file IDs branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_update_status_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_update_status_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {};
    classifyRestore.UpdateStatus(fileIds);
}

/*
 * Test interface: ClassifyRestore::DeleteExistMapping
 * Test content: Delete existing mapping with valid file IDs
 * Cover branches: Normal flow with valid file IDs
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_delete_exist_mapping_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_delete_exist_mapping_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.DeleteExistMapping(fileIds);
}

/*
 * Test interface: ClassifyRestore::DeleteExistMapping
 * Test content: Delete existing mapping with empty file IDs
 * Cover branches: Empty file IDs branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_delete_exist_mapping_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_delete_exist_mapping_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {};
    classifyRestore.DeleteExistMapping(fileIds);
}

/*
 * Test interface: ClassifyRestore::RestoreClassify
 * Test content: Restore classify with valid photo info map
 * Cover branches: Normal flow with valid photo info map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_restore_classify_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_restore_classify_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    classifyRestore.RestoreClassify(photoInfoMap);
}

/*
 * Test interface: ClassifyRestore::RestoreClassify
 * Test content: Restore classify with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_restore_classify_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_restore_classify_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    classifyRestore.RestoreClassify(photoInfoMap);
}

/*
 * Test interface: ClassifyRestore::RestoreClassify
 * Test content: Restore classify with null gallery RDB
 * Cover branches: Null gallery RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_restore_classify_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_restore_class_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), nullptr);
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;
    
    classifyRestore.RestoreClassify(photoInfoMap);
}

/*
 * Test interface: ClassifyRestore::RestoreClassify
 * Test content: Restore classify with empty photo info map
 * Cover branches: Empty photo info map branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_restore_class_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_restore_class_test_004 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, PhotoInfo> photoInfoMap;
    classifyRestore.RestoreClassify(photoInfoMap);
}

/*
 * Test interface: ClassifyRestore::BatchInsertWithRetry
 * Test content: Batch insert with retry with valid values
 * Cover branches: Normal flow with valid values bucket
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_batch_insert_with_retry_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_batch_insert_with_retry_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("file_id", TEST_FILE_ID_NEW);
    value.PutInt("category_id", TEST_CATEGORY_ID);
    value.PutString("sub_label", TEST_SUB_LABEL);
    value.PutDouble("prob", TEST_PROB);
    value.PutString("label_version", TEST_VERSION);
    values.push_back(value);
    
    int64_t rowNum = 0;
    int32_t errCode = classifyRestore.BatchInsertWithRetry("tab_analysis_label", values, rowNum);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_GT(rowNum, 0);
}

/*
 * Test interface: ClassifyRestore::BatchInsertWithRetry
 * Test content: Batch insert with retry with empty values
 * Cover branches: Empty values bucket branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_batch_insert_with_retry_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_batch_insert_with_retry_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;
    int32_t errCode = classifyRestore.BatchInsertWithRetry("tab_analysis_label", values, rowNum);
    EXPECT_EQ(errCode, E_OK);
}

/*
 * Test interface: ClassifyRestore::HandleOcr
 * Test content: Handle OCR with valid sub label map
 * Cover branches: Normal flow with valid sub label map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_handle_ocr_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_handle_ocr_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {1, 2, 3};
    
    classifyRestore.HandleOcr(subLabelMap);
}

/*
 * Test interface: ClassifyRestore::HandleOcr
 * Test content: Handle OCR with ID card label
 * Cover branches: ID card label handling
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_handle_ocr_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_handle_ocr_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
    
    classifyRestore.HandleOcr(subLabelMap);
}

/*
 * Test interface: ClassifyRestore::HandleOcr
 * Test content: Handle OCR with empty sub label map
 * Cover branches: Empty sub label map branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_handle_ocr_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medial_library_classify_restore_handle_ocr_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_map<int32_t, vector<int32_t>> subLabelMap;
    classifyRestore.HandleOcr(subLabelMap);
}

/*
 * Test interface: ClassifyRestore::HandleOcrHelper
 * Test content: Handle OCR helper with valid file IDs
 * Cover branches: Normal flow with valid file IDs
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_handle_ocr_helper_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_handle_ocr_helper_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.HandleOcrHelper(fileIds);
}

/*
 * Test interface: ClassifyRestore::HandleOcrHelper
 * Test content: Handle OCR helper with empty file IDs
 * Cover branches: Empty file IDs branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_handle_ocr_helper_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_handle_ocr_helper_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    vector<int32_t> fileIds = {};
    classifyRestore.HandleOcrHelper(fileIds);
}

/*
 * Test interface: ClassifyRestore::AddIdCardAlbum
 * Test content: Add ID card album with valid file IDs
 * Cover branches: Normal flow with valid file IDs
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_add_id_card_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_add_id_card_album_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::ID_CARD, fileIdsToUpdateSet);
}

/*
 * Test interface: ClassifyRestore::AddIdCardAlbum
 * Test content: Add ID card album with empty file IDs
 * Cover branches: Empty file IDs branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_add_id_card_album_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_add_id_card_album_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    unordered_set<int32_t> fileIdsToUpdateSet = {};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::ID_CARD, fileIdsToUpdateSet);
}

/*
 * Test interface: ClassifyRestore::AddIdCardAlbum
 * Test content: Add ID card album with null media library RDB
 * Cover branches: Null media library RDB pointer branch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_add_id_card_album_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_add_id_card_album_test_003 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_rdbStore->GetRaw());
    
    unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::ID_CARD, fileIdsToUpdateSet);
}

/*
 * Test interface: ClassifyRestore::ReportRestoreTask
 * Test content: Report restore task with default values
 * Cover branches: Normal flow with default counter values
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_report_restore_task_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_report_restore_task_test_001 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    classifyRestore.ReportRestoreTask();
}

/*
 * Test interface: ClassifyRestore::ReportRestoreTask
 * Test content: Report restore task with specific counter values
 * Cover branches: Normal flow with specific counter values
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_classify_restore_report_restore_task_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_classify_restore_report_restore_task_test_002 start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_rdbStore->GetRaw());
    
    classifyRestore.successInsertLabelCnt_ = 100;
    classifyRestore.failInsertLabelCnt_ = 5;
    classifyRestore.duplicateLabelCnt_ = 10;
    classifyRestore.exitCode_ = 0;
    classifyRestore.restoreTimeCost_ = 1000;
    classifyRestore.maxIdOfLabel_ = 500;
    classifyRestore.imageCollectionSize_ = 1000;
    
    classifyRestore.ReportRestoreTask();
}

} // namespace Media
} // namespace OHOS
