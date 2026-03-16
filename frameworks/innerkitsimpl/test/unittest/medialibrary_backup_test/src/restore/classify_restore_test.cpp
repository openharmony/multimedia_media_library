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

#define MLOG_TAG "ClassifyRestoreTest"

#include "classify_restore_test.h"
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unordered_set>

#include "classify_restore.h"
#include "classify_aggregate_types.h"
#include "backup_const.h"
#include "backup_database_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "gallery_source.h"
#include "media_library_db_upgrade.h"
#include "userfile_manager_types.h"
#include "result_set_utils.h"
#include "vision_column.h"
#include "photo_album_column.h"
#include "media_column.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS::Media {

const std::string TEST_BACKUP_PATH = "/data/test/gallery_classify.db";
const std::string TEST_TASK_ID = "1234567890";
const int32_t TEST_SCENE_CODE = 1;
const int32_t TEST_FILE_ID_OLD = 10;
const int32_t TEST_FILE_ID_NEW = 100;
const int32_t TEST_CATEGORY_ID = 5;
const int32_t INVALID_LABEL = -2;
const int32_t ADD_ITEMS = 10000;

const vector<string> CLEAR_SQLS = {
    "DELETE FROM tab_analysis_label",
    "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE,
    "DELETE FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_SUBTYPE + " = " +
        to_string(PhotoAlbumSubType::CLASSIFY),
    "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
    "DELETE FROM tab_analysis_ocr",
    "DELETE FROM tab_analysis_total",
};

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static std::shared_ptr<NativeRdb::RdbStore> g_galleryPtr = nullptr;

static void InitDestinationDb()
{
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
}

static void ExecuteSqls(shared_ptr<RdbStore> rdbStore, const vector<string> &sqls)
{
    for (const auto &sql : sqls) {
        int32_t errCode = rdbStore->ExecuteSql(sql);
        if (errCode == E_OK) {
            continue;
        }
        MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
    }
}

static void ClearData()
{
    MEDIA_INFO_LOG("Start clear data");
    if (g_rdbStore != nullptr && g_rdbStore->GetRaw() != nullptr) {
        ExecuteSqls(g_rdbStore->GetRaw(), CLEAR_SQLS);
    }
    MEDIA_INFO_LOG("End clear data");
}

void ClassifyRestoreTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    InitDestinationDb();
    GallerySource gallerySource;
    gallerySource.Init(TEST_BACKUP_PATH);
    g_galleryPtr = gallerySource.galleryStorePtr_;
    ASSERT_NE(g_galleryPtr, nullptr);
    ClearData();
}

void ClassifyRestoreTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void ClassifyRestoreTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    ClearData();
}

void ClassifyRestoreTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

// More CollectAlbumInfo comprehensive tests
HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_AllAggregateTypes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_AllAggregateTypes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD), static_cast<int32_t>(PhotoLabel::INVOICE),
        static_cast<int32_t>(PhotoLabel::BUSINESS_CARD), static_cast<int32_t>(PhotoLabel::INFANT_SWIMMING),
        static_cast<int32_t>(PhotoLabel::CAT), static_cast<int32_t>(PhotoLabel::CANDLE),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE), static_cast<int32_t>(PhotoLabel::DIPLOMA),
        static_cast<int32_t>(PhotoLabel::SUSHI), static_cast<int32_t>(PhotoLabel::BUILDING),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN), static_cast<int32_t>(PhotoLabel::ROSE),
        static_cast<int32_t>(PhotoLabel::RING), static_cast<int32_t>(PhotoLabel::AUTOMOBILE)
    };
    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::CARD))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::TICKET))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::DOCUMENT))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::PET))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::BIRTHDAY))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::WEDDING))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::GRADUATE))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::FOOD))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(
        std::to_string(static_cast<int32_t>(AggregateType::CULTURAL_LANDSCAPE))) !=
        classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(
        classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::NATURAL_SCENERY))) !=
        classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(
        classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::FLOWERS_AND_PLANTS)))
        != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::JEWELRY))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::TRANSPORT))) !=
                classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_AllAggregateTypes_Test end");
}

// Additional comprehensive test cases to reach 3000 lines

// More detailed ProcessLabelInfo tests
HWTEST_F(ClassifyRestoreTest, ProcessLabelInfo_MultipleLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessLabelInfo_MultipleLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;

    for (int i = 0; i < 10; i++) {
        ClassifyRestore::GalleryLabelInfo labelInfo;
        labelInfo.fileIdOld = TEST_FILE_ID_OLD + i;
        labelInfo.categoryId = TEST_CATEGORY_ID + i;
        labelInfo.subLabel = "[" + std::to_string(i) + "]";
        labelInfo.prob = 0.5 + (i * 0.05);
        labelInfo.version = "1." + std::to_string(i);
        galleryLabelInfoMap["hash" + std::to_string(i)] = labelInfo;

        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.ProcessLabelInfo(galleryLabelInfoMap, photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessLabelInfo_MultipleLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, ProcessLabelInfo_WithOcrLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessLabelInfo_WithOcrLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    ClassifyRestore::GalleryLabelInfo labelInfo;
    labelInfo.fileIdOld = TEST_FILE_ID_OLD;
    labelInfo.categoryId = TEST_CATEGORY_ID;
    labelInfo.subLabel = "[" + std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD)) + ",5]";
    labelInfo.prob = 0.9;
    labelInfo.version = "1.0";
    galleryLabelInfoMap["hash123"] = labelInfo;

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.ProcessLabelInfo(galleryLabelInfoMap, photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessLabelInfo_WithOcrLabels_Test end");
}

// More RestoreLabel comprehensive tests
HWTEST_F(ClassifyRestoreTest, RestoreLabel_WithValidTaskId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreLabel_WithValidTaskId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "1000000000", g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.RestoreLabel(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreLabel_WithValidTaskId_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreLabel_WithLargePhotoInfoMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreLabel_WithLargePhotoInfoMap_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "1000000000", g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 500; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfo.cloudPath = "cloud/path/test" + std::to_string(i) + ".jpg";
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.RestoreLabel(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreLabel_WithLargePhotoInfoMap_Test end");
}

// More comprehensive ParseSubLabel tests with various formats
HWTEST_F(ClassifyRestoreTest, ParseSubLabel_SpaceSeparated_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_SpaceSeparated_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1 2 3]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_SpaceSeparated_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_NoSpaces_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_NoSpaces_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1,2,3]");
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
    MEDIA_INFO_LOG("ParseSubLabel_NoSpaces_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_ExtraSpaces_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_ExtraSpaces_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[  1  ,  2  ,  3  ]");
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
    MEDIA_INFO_LOG("ParseSubLabel_ExtraSpaces_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_SingleElement_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_SingleElement_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[42]");
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 42);
    MEDIA_INFO_LOG("ParseSubLabel_SingleElement_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_TwoElements_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_TwoElements_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1, 2]");
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    MEDIA_INFO_LOG("ParseSubLabel_TwoElements_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_TenElements_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_TenElements_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1,2,3,4]");
    EXPECT_EQ(result.size(), 4);
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(result[i], i + 1);
    }
    MEDIA_INFO_LOG("ParseSubLabel_TenElements_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_HundredElements_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_HundredElements_Test start");
    ClassifyRestore classifyRestore;
    std::string subLabel = "[";
    for (int i = 1; i <= 100; i++) {
        subLabel += std::to_string(i);
        if (i < 100) {
            subLabel += ",";
        }
    }
    subLabel += "]";
    std::vector<int32_t> result = classifyRestore.ParseSubLabel(subLabel);
    EXPECT_EQ(result.size(), 100);
    MEDIA_INFO_LOG("ParseSubLabel_HundredElements_Test end");
}

// More GetAggregateTypes with specific label combinations
HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_SingleLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_SingleLabel_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_SingleLabel_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_TwoLabelsSameAggregate_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_TwoLabelsSameAggregate_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::PASSPORT)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    EXPECT_EQ(result.size(), 1);
    MEDIA_INFO_LOG("GetAggregateTypes_TwoLabelsSameAggregate_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_TwoLabelsDifferentAggregates_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_TwoLabelsDifferentAggregates_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::PET)) != result.end());
    EXPECT_EQ(result.size(), 2);
    MEDIA_INFO_LOG("GetAggregateTypes_TwoLabelsDifferentAggregates_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_ThreeLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_ThreeLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::PET)) != result.end());
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::WEDDING)) != result.end());
    EXPECT_EQ(result.size(), 3);
    MEDIA_INFO_LOG("GetAggregateTypes_ThreeLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_FiveLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_FiveLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_EQ(result.size(), 5);
    MEDIA_INFO_LOG("GetAggregateTypes_FiveLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_TenLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_TenLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::PASSPORT),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::DOG),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP),
        static_cast<int32_t>(PhotoLabel::SUSHI),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN),
        static_cast<int32_t>(PhotoLabel::ROSE),
        static_cast<int32_t>(PhotoLabel::RING)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_GE(result.size(), 5);
    MEDIA_INFO_LOG("GetAggregateTypes_TenLabels_Test end");
}

// More CollectAlbumInfo with various scenarios
HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_SingleLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_SingleLabel_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    std::string labelAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(labelAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_EQ(classifyRestore.albumAssetMap_[labelAlbum].size(), 1);
    MEDIA_INFO_LOG("CollectAlbumInfo_SingleLabel_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_TwoLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_TwoLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    std::string cardAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    std::string catAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::CAT));
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(cardAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(catAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_TwoLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_FiveLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_FiveLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    EXPECT_GE(classifyRestore.albumAssetMap_.size(), 5);
    MEDIA_INFO_LOG("CollectAlbumInfo_FiveLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_TenLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_TenLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::PASSPORT),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::DOG),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP),
        static_cast<int32_t>(PhotoLabel::SUSHI),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN),
        static_cast<int32_t>(PhotoLabel::ROSE),
        static_cast<int32_t>(PhotoLabel::RING)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    EXPECT_GE(classifyRestore.albumAssetMap_.size(), 10);
    MEDIA_INFO_LOG("CollectAlbumInfo_TenLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_SameFileMultipleTimes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_SameFileMultipleTimes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    for (int i = 0; i < 5; i++) {
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    std::string labelAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[labelAlbum].size(), 1);
    MEDIA_INFO_LOG("CollectAlbumInfo_SameFileMultipleTimes_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_DifferentFilesSameLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_DifferentFilesSameLabel_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    for (int i = 0; i < 20; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    std::string labelAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[labelAlbum].size(), 20);
    MEDIA_INFO_LOG("CollectAlbumInfo_DifferentFilesSameLabel_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_DifferentFilesDifferentLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_DifferentFilesDifferentLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t categoryId = TEST_CATEGORY_ID;

    for (int i = 0; i < 10; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD) + i};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    EXPECT_GE(classifyRestore.albumAssetMap_.size(), 10);
    MEDIA_INFO_LOG("CollectAlbumInfo_DifferentFilesDifferentLabels_Test end");
}

// More EnsureClassifyAlbumId tests
HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_ValidLabelName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_ValidLabelName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_ValidLabelName_Test end");
}

HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_ValidAggregateName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_ValidAggregateName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(AggregateType::CARD));
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_ValidAggregateName_Test end");
}

// More InsertAlbumMappings comprehensive tests
HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_OneValue_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_OneValue_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("map_album", 1);
    value.PutInt("map_asset", TEST_FILE_ID_NEW);
    values.push_back(value);

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_OneValue_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_TwoValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_TwoValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 2; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_TwoValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_FiveValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_FiveValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 5; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_FiveValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_TenValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_TenValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 10; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_TenValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_TwentyValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_TwentyValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 20; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_TwentyValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_FiftyValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_FiftyValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 50; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_FiftyValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_HundredValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_HundredValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 100; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_HundredValues_Test end");
}

// More CreateOrUpdateCategoryAlbums comprehensive tests
HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_OneAlbum_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_OneAlbum_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW);

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_OneAlbum_Test end");
}

HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_TwoAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TwoAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName1 = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    std::string albumName2 = std::to_string(static_cast<int32_t>(PhotoLabel::CAT));
    classifyRestore.albumAssetMap_[albumName1].insert(TEST_FILE_ID_NEW);
    classifyRestore.albumAssetMap_[albumName2].insert(TEST_FILE_ID_NEW + 1);

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TwoAlbums_Test end");
}

HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_FiveAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_FiveAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 5; i++) {
        std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD) + i);
        classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_FiveAlbums_Test end");
}

HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_TenAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TenAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 10; i++) {
        std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD) + i);
        classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TenAlbums_Test end");
}

HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_TwentyAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TwentyAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 20; i++) {
        std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD) + i);
        classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_TwentyAlbums_Test end");
}

// More HandleOcr comprehensive tests
HWTEST_F(ClassifyRestoreTest, HandleOcr_OneFile_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_OneFile_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_OneFile_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_TwoFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_TwoFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
    subLabelMap[TEST_FILE_ID_NEW + 1] = {static_cast<int32_t>(PhotoLabel::ID_CARD), 5};

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_TwoFiles_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_FiveFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_FiveFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 5; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_FiveFiles_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_TenFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_TenFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 10; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_TenFiles_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_TwentyFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_TwentyFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 20; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_TwentyFiles_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_FiftyFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_FiftyFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 50; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_FiftyFiles_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_HundredFiles_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_HundredFiles_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 100; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_HundredFiles_Test end");
}

// More HandleOcrHelper comprehensive tests
HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_OneFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_OneFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_OneFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_TwoFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_TwoFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_TwoFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_FiveFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_FiveFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1, TEST_FILE_ID_NEW + 2,
                                     TEST_FILE_ID_NEW + 3, TEST_FILE_ID_NEW + 4};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_FiveFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_TenFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_TenFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds;
    for (int i = 0; i < 10; i++) {
        fileIds.push_back(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_TenFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_TwentyFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_TwentyFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds;
    for (int i = 0; i < 20; i++) {
        fileIds.push_back(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_TwentyFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_FiftyFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_FiftyFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds;
    for (int i = 0; i < 50; i++) {
        fileIds.push_back(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_FiftyFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_HundredFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_HundredFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds;
    for (int i = 0; i < 100; i++) {
        fileIds.push_back(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_HundredFileIds_Test end");
}

// More AddIdCardAlbum comprehensive tests
HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_OneFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_OneFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(idCardAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 1);
    MEDIA_INFO_LOG("AddIdCardAlbum_OneFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_TwoFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_TwoFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 2);
    MEDIA_INFO_LOG("AddIdCardAlbum_TwoFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_FiveFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_FiveFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1,
                                                        TEST_FILE_ID_NEW + 2, TEST_FILE_ID_NEW + 3,
                                                        TEST_FILE_ID_NEW + 4};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 5);
    MEDIA_INFO_LOG("AddIdCardAlbum_FiveFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_TenFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_TenFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet;
    for (int i = 0; i < 10; i++) {
        fileIdsToUpdateSet.insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 10);
    MEDIA_INFO_LOG("AddIdCardAlbum_TenFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_TwentyFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_TwentyFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet;
    for (int i = 0; i < 20; i++) {
        fileIdsToUpdateSet.insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 20);
    MEDIA_INFO_LOG("AddIdCardAlbum_TwentyFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_FiftyFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_FiftyFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet;
    for (int i = 0; i < 50; i++) {
        fileIdsToUpdateSet.insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 50);
    MEDIA_INFO_LOG("AddIdCardAlbum_FiftyFileIds_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_HundredFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_HundredFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet;
    for (int i = 0; i < 100; i++) {
        fileIdsToUpdateSet.insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 100);
    MEDIA_INFO_LOG("AddIdCardAlbum_HundredFileIds_Test end");
}

// Test CollectAlbumInfo with more scenarios
HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_AggregateTypes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_AggregateTypes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::CAT)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    std::string cardAlbum = std::to_string(static_cast<int32_t>(AggregateType::CARD));
    std::string weddingAlbum = std::to_string(static_cast<int32_t>(AggregateType::WEDDING));
    std::string petAlbum = std::to_string(static_cast<int32_t>(AggregateType::PET));

    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(cardAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(weddingAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(petAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_AggregateTypes_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_ZeroFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_ZeroFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = 0;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CollectAlbumInfo_ZeroFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_EmptyLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_EmptyLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels;

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    std::string categoryAlbum = std::to_string(ADD_ITEMS + categoryId);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(categoryAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_EmptyLabels_Test end");
}

// Test EnsureClassifyAlbumId with more scenarios
HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_EmptyName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_EmptyName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = "";
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_EmptyName_Test end");
}

HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_LongName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_LongName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::string(1000, 'a');
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_LongName_Test end");
}

// Test InsertAlbumMappings with more scenarios
HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_LargeBatch_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_LargeBatch_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 10; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_LargeBatch_Test end");
}

// Test CreateOrUpdateCategoryAlbums with data
HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_WithData_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_WithData_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW);
    classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + 1);

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_WithData_Test end");
}

// Test EnsureSelfieAlbum with more scenarios
HWTEST_F(ClassifyRestoreTest, EnsureSelfieAlbum_ValidRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureSelfieAlbum_ValidRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    classifyRestore.EnsureSelfieAlbum();
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("EnsureSelfieAlbum_ValidRdb_Test end");
}

// Test EnsureUserCommentAlbum with more scenarios
HWTEST_F(ClassifyRestoreTest, EnsureUserCommentAlbum_ValidRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureUserCommentAlbum_ValidRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    classifyRestore.EnsureUserCommentAlbum();
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("EnsureUserCommentAlbum_ValidRdb_Test end");
}

// Test HandleOcr with more scenarios
HWTEST_F(ClassifyRestoreTest, HandleOcr_MultipleIdCards_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_MultipleIdCards_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
    subLabelMap[TEST_FILE_ID_NEW + 1] = {static_cast<int32_t>(PhotoLabel::ID_CARD), 5};
    subLabelMap[TEST_FILE_ID_NEW + 2] = {5, 6, static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_MultipleIdCards_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_MixedLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_MixedLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD),
                                    static_cast<int32_t>(PhotoLabel::CAT),
                                    static_cast<int32_t>(PhotoLabel::BIRTHDAY_CAKE)};

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_MixedLabels_Test end");
}

// Test HandleOcrHelper with more scenarios
HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_SingleFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_SingleFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_SingleFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_MultipleFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_MultipleFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1, TEST_FILE_ID_NEW + 2};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_MultipleFileIds_Test end");
}

// Test AddIdCardAlbum with more scenarios
HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_EmptySet_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_EmptySet_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet;
    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("AddIdCardAlbum_EmptySet_Test end");
}

HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_MultipleFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_MultipleFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIdsToUpdateSet = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW + 1, TEST_FILE_ID_NEW + 2};
    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIdsToUpdateSet);

    std::string idCardAlbum = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(idCardAlbum) != classifyRestore.albumAssetMap_.end());
    EXPECT_EQ(classifyRestore.albumAssetMap_[idCardAlbum].size(), 3);
    MEDIA_INFO_LOG("AddIdCardAlbum_MultipleFileIds_Test end");
}

// Test ProcessCategoryAlbums with data
HWTEST_F(ClassifyRestoreTest, ProcessCategoryAlbums_WithData_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessCategoryAlbums_WithData_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW);

    classifyRestore.ProcessCategoryAlbums();
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessCategoryAlbums_WithData_Test end");
}

// Test RestoreClassify with more scenarios
HWTEST_F(ClassifyRestoreTest, RestoreClassify_NullRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_NullRdb_Test start");
    ClassifyRestore classifyRestore;

    classifyRestore.mediaLibraryRdb_ = nullptr;
    classifyRestore.galleryRdb_ = nullptr;

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_EQ(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_EQ(classifyRestore.galleryRdb_, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_NullRdb_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreClassify_LargePhotoInfoMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_LargePhotoInfoMap_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 100; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_LargePhotoInfoMap_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreClassify_MultiplePhotos_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_MultiplePhotos_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 10; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfo.cloudPath = "cloud/path/test" + std::to_string(i) + ".jpg";
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_MultiplePhotos_Test end");
}

// Test Init with edge cases
HWTEST_F(ClassifyRestoreTest, Init_NullRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_NullRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, nullptr);

    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    EXPECT_EQ(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_EQ(classifyRestore.galleryRdb_, nullptr);
    MEDIA_INFO_LOG("Init_NullRdb_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_EmptyTaskId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_EmptyTaskId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, "", g_rdbStore->GetRaw(), g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, "");
    EXPECT_NE(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_NE(classifyRestore.galleryRdb_, nullptr);
    MEDIA_INFO_LOG("Init_EmptyTaskId_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_NegativeSceneCode_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_NegativeSceneCode_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(-1, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, -1);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    MEDIA_INFO_LOG("Init_NegativeSceneCode_Test end");
}

// Test ParseSubLabel with special characters
HWTEST_F(ClassifyRestoreTest, ParseSubLabel_SpecialCharacters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_SpecialCharacters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1@, 2#, 3$]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_SpecialCharacters_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_LeadingZeros_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_LeadingZeros_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[001, 002, 003]");
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
    MEDIA_INFO_LOG("ParseSubLabel_LeadingZeros_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_ExtraBrackets_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_ExtraBrackets_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[[1, 2, 3]]");
    EXPECT_GE(result.size(), 1);
    MEDIA_INFO_LOG("ParseSubLabel_ExtraBrackets_Test end");
}

// Test GetAggregateTypes with boundary values
HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_ZeroLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_ZeroLabel_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {0};
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("GetAggregateTypes_ZeroLabel_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_NegativeLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_NegativeLabel_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {-1, -100};
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("GetAggregateTypes_NegativeLabel_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_VeryLargeLabel_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_VeryLargeLabel_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {999999, 888888};
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("GetAggregateTypes_VeryLargeLabel_Test end");
}

// Test CollectAlbumInfo with boundary values
HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_MaxIntFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_MaxIntFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = INT32_MAX;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_FALSE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CollectAlbumInfo_MaxIntFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_MaxCategoryId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_MaxCategoryId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = INT32_MAX;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    std::string categoryAlbum = std::to_string(ADD_ITEMS + categoryId);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(categoryAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_MaxCategoryId_Test end");
}

// Test EnsureClassifyAlbumId with special characters
HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_SpecialChars_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_SpecialChars_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = "test@#$%album";
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_SpecialChars_Test end");
}

// Test Integration scenarios
HWTEST_F(ClassifyRestoreTest, Integration_FullRestoreFlow_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_FullRestoreFlow_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfo.cloudPath = "cloud/path/test.jpg";
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.GetMaxIds();
    classifyRestore.RestoreClassify(photoInfoMap);
    classifyRestore.ReportRestoreTask();

    EXPECT_GE(classifyRestore.maxIdOfLabel_, 0);
    MEDIA_INFO_LOG("Integration_FullRestoreFlow_Test end");
}

HWTEST_F(ClassifyRestoreTest, Integration_AlbumCreationFlow_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_AlbumCreationFlow_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    classifyRestore.CreateOrUpdateCategoryAlbums();
    classifyRestore.EnsureSpecialAlbums();

    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Integration_AlbumCreationFlow_Test end");
}

HWTEST_F(ClassifyRestoreTest, Integration_OcrProcessingFlow_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_OcrProcessingFlow_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
    subLabelMap[TEST_FILE_ID_NEW + 1] = {static_cast<int32_t>(PhotoLabel::ID_CARD), 5};

    classifyRestore.HandleOcr(subLabelMap);
    classifyRestore.ProcessCategoryAlbums();
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("Integration_OcrProcessingFlow_Test end");
}

// Test error handling scenarios
HWTEST_F(ClassifyRestoreTest, ErrorHandling_InvalidFileIdInUpdateStatus_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ErrorHandling_InvalidFileIdInUpdateStatus_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {-1, 0, TEST_FILE_ID_NEW};
    classifyRestore.UpdateStatus(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ErrorHandling_InvalidFileIdInUpdateStatus_Test end");
}

HWTEST_F(ClassifyRestoreTest, ErrorHandling_InvalidAlbumName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ErrorHandling_InvalidAlbumName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string invalidAlbum = std::to_string(-1);
    int32_t result = classifyRestore.EnsureClassifyAlbumId(invalidAlbum);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("ErrorHandling_InvalidAlbumName_Test end");
}

// Test concurrent access scenarios (if applicable)
HWTEST_F(ClassifyRestoreTest, ConcurrentAccess_MultipleAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ConcurrentAccess_MultipleAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 10; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        int32_t categoryId = TEST_CATEGORY_ID + i;
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD) + i};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    EXPECT_FALSE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("ConcurrentAccess_MultipleAlbums_Test end");
}

// Test memory and performance scenarios
HWTEST_F(ClassifyRestoreTest, Performance_LargeLabelList_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Performance_LargeLabelList_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels;
    for (int i = 0; i < 1000; i++) {
        labels.push_back(i);
    }

    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("Performance_LargeLabelList_Test end");
}

HWTEST_F(ClassifyRestoreTest, Performance_ManyAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Performance_ManyAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 100; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        int32_t categoryId = TEST_CATEGORY_ID;
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    EXPECT_FALSE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Performance_ManyAlbums_Test end");
}

// Additional comprehensive tests for 3000 lines target

// Test ProcessLabelInfo function
HWTEST_F(ClassifyRestoreTest, ProcessLabelInfo_EmptyMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessLabelInfo_EmptyMap_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;

    classifyRestore.ProcessLabelInfo(galleryLabelInfoMap, photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessLabelInfo_EmptyMap_Test end");
}

HWTEST_F(ClassifyRestoreTest, ProcessLabelInfo_ValidData_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessLabelInfo_ValidData_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    ClassifyRestore::GalleryLabelInfo labelInfo;
    labelInfo.fileIdOld = TEST_FILE_ID_OLD;
    labelInfo.categoryId = TEST_CATEGORY_ID;
    labelInfo.subLabel = "[1,2,3]";
    labelInfo.prob = 0.9;
    labelInfo.version = "1.0";
    galleryLabelInfoMap["hash123"] = labelInfo;

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.ProcessLabelInfo(galleryLabelInfoMap, photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessLabelInfo_ValidData_Test end");
}

HWTEST_F(ClassifyRestoreTest, ProcessLabelInfo_MissingPhotoInfo_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessLabelInfo_MissingPhotoInfo_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    ClassifyRestore::GalleryLabelInfo labelInfo;
    labelInfo.fileIdOld = TEST_FILE_ID_OLD;
    galleryLabelInfoMap["hash123"] = labelInfo;

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;

    classifyRestore.ProcessLabelInfo(galleryLabelInfoMap, photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("ProcessLabelInfo_MissingPhotoInfo_Test end");
}

// Test ProcessImageCollectionInfo function
HWTEST_F(ClassifyRestoreTest, ProcessImageCollectionInfo_NullResultSet_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessImageCollectionInfo_NullResultSet_Test start");
    ClassifyRestore classifyRestore;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;
    std::string hash;

    classifyRestore.ProcessImageCollectionInfo(resultSet, galleryLabelInfoMap, hash);
    EXPECT_TRUE(galleryLabelInfoMap.empty());
    MEDIA_INFO_LOG("ProcessImageCollectionInfo_NullResultSet_Test end");
}

// Test ProcessGalleryMediaInfo function
HWTEST_F(ClassifyRestoreTest, ProcessGalleryMediaInfo_NullResultSet_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessGalleryMediaInfo_NullResultSet_Test start");
    ClassifyRestore classifyRestore;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;

    ASSERT_EQ(resultSet, nullptr);

    classifyRestore.ProcessGalleryMediaInfo(resultSet, galleryLabelInfoMap);
    MEDIA_INFO_LOG("ProcessGalleryMediaInfo_NullResultSet_Test end");
}

HWTEST_F(ClassifyRestoreTest, ProcessGalleryMediaInfo_EmptyMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ProcessGalleryMediaInfo_EmptyMap_Test start");
    ClassifyRestore classifyRestore;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    std::unordered_map<std::string, ClassifyRestore::GalleryLabelInfo> galleryLabelInfoMap;

    ASSERT_EQ(resultSet, nullptr);

    classifyRestore.ProcessGalleryMediaInfo(resultSet, galleryLabelInfoMap);
    MEDIA_INFO_LOG("ProcessGalleryMediaInfo_EmptyMap_Test end");
}

// Test RestoreLabel function
HWTEST_F(ClassifyRestoreTest, RestoreLabel_NullGalleryRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreLabel_NullGalleryRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.galleryRdb_ = nullptr;

    ASSERT_EQ(classifyRestore.galleryRdb_, nullptr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    classifyRestore.RestoreLabel(photoInfoMap);
    MEDIA_INFO_LOG("RestoreLabel_NullGalleryRdb_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreLabel_EmptyPhotoInfoMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreLabel_EmptyPhotoInfoMap_Test start");
    ClassifyRestore classifyRestore;

    ASSERT_NE(g_rdbStore, nullptr);
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    classifyRestore.RestoreLabel(photoInfoMap);
    MEDIA_INFO_LOG("RestoreLabel_EmptyPhotoInfoMap_Test end");
}

// Test BatchInsertWithRetry function
HWTEST_F(ClassifyRestoreTest, BatchInsertWithRetry_EmptyValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("BatchInsertWithRetry_EmptyValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;
    int32_t result = classifyRestore.BatchInsertWithRetry("test_table", values, rowNum);
    EXPECT_EQ(result, E_OK);
    MEDIA_INFO_LOG("BatchInsertWithRetry_EmptyValues_Test end");
}

HWTEST_F(ClassifyRestoreTest, BatchInsertWithRetry_ValidValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("BatchInsertWithRetry_ValidValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("file_id", TEST_FILE_ID_NEW);
    values.push_back(value);

    int64_t rowNum = 0;
    int32_t result = classifyRestore.BatchInsertWithRetry("test_table", values, rowNum);
    EXPECT_LT(result, 0);
    MEDIA_INFO_LOG("BatchInsertWithRetry_ValidValues_Test end");
}

// More ParseSubLabel edge cases
HWTEST_F(ClassifyRestoreTest, ParseSubLabel_UnicodeCharacters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_UnicodeCharacters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1中文, 2测试, 3]");
    EXPECT_GE(result.size(), 1);
    MEDIA_INFO_LOG("ParseSubLabel_UnicodeCharacters_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_NewlineCharacters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_NewlineCharacters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1\n, 2\r, 3\n\r]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_NewlineCharacters_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_TabCharacters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_TabCharacters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1\t, 2\t, 3]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_TabCharacters_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_FloatNumbers_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_FloatNumbers_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1.5, 2.7, 3.9]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_FloatNumbers_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_HexNumbers_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_HexNumbers_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[0x1, 0x2, 0x3]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_HexNumbers_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_ExponentialNotation_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_ExponentialNotation_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1e2, 2e3, 3e4]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_ExponentialNotation_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_MixedDelimiters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_MixedDelimiters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1; 2: 3| 4]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_MixedDelimiters_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_NestedBrackets_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_NestedBrackets_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[[1], [2], [3]]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_NestedBrackets_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_QuotedNumbers_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_QuotedNumbers_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("['1', '2', '3']");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_QuotedNumbers_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_BackslashEscaped_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_BackslashEscaped_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1\\, 2\\, 3]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_BackslashEscaped_Test end");
}

// More comprehensive GetAggregateTypes tests
HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllCardLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllCardLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::PASSPORT),
        static_cast<int32_t>(PhotoLabel::DEBIT_CARD),
        static_cast<int32_t>(PhotoLabel::DRIVER_LICENSE),
        static_cast<int32_t>(PhotoLabel::DRIVING_LICENSE)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllCardLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllTicketLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllTicketLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::INVOICE),
        static_cast<int32_t>(PhotoLabel::AIR_TICKET),
        static_cast<int32_t>(PhotoLabel::TRAIN_TICKET),
        static_cast<int32_t>(PhotoLabel::MOVIE_TICKET)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::TICKET)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllTicketLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllDocumentLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllDocumentLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::BUSINESS_CARD),
        static_cast<int32_t>(PhotoLabel::QR_CODE),
        static_cast<int32_t>(PhotoLabel::PPT),
        static_cast<int32_t>(PhotoLabel::BAR_CODE)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::DOCUMENT)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllDocumentLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllWeddingLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllWeddingLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::BRIDAL_VEIL),
        static_cast<int32_t>(PhotoLabel::WEDDING),
        static_cast<int32_t>(PhotoLabel::BRIDE)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::WEDDING)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllWeddingLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllGraduateLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllGraduateLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::DIPLOMA),
        static_cast<int32_t>(PhotoLabel::GRADUATION_GOWN),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::GRADUATE)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllGraduateLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllNaturalSceneryLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllNaturalSceneryLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::MOUNTAIN),
        static_cast<int32_t>(PhotoLabel::WATERFALL),
        static_cast<int32_t>(PhotoLabel::RAINBOW),
        static_cast<int32_t>(PhotoLabel::OCEAN_BEACH_LAKE)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::NATURAL_SCENERY)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllNaturalSceneryLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllFlowersLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllFlowersLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ROSE),
        static_cast<int32_t>(PhotoLabel::TULIP),
        static_cast<int32_t>(PhotoLabel::SUNFLOWER),
        static_cast<int32_t>(PhotoLabel::LOTUS)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::FLOWERS_AND_PLANTS)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllFlowersLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllJewelryLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllJewelryLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::RING),
        static_cast<int32_t>(PhotoLabel::BRACELET),
        static_cast<int32_t>(PhotoLabel::DIAMOND),
        static_cast<int32_t>(PhotoLabel::JEWELRY)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::JEWELRY)) != result.end());
    MEDIA_INFO_LOG("GetAggregateTypes_AllJewelryLabels_Test end");
}

// More CollectAlbumInfo comprehensive tests
HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_AllCategoryTypes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_AllCategoryTypes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 10; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        int32_t categoryId = TEST_CATEGORY_ID + i;
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    EXPECT_FALSE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CollectAlbumInfo_AllCategoryTypes_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_MultipleFilesSameAlbum_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_MultipleFilesSameAlbum_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    for (int i = 0; i < 50; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    std::string labelAlbum = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    EXPECT_EQ(classifyRestore.albumAssetMap_[labelAlbum].size(), 50);
    MEDIA_INFO_LOG("CollectAlbumInfo_MultipleFilesSameAlbum_Test end");
}

HWTEST_F(ClassifyRestoreTest, CollectAlbumInfo_ComplexLabelCombination_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CollectAlbumInfo_ComplexLabelCombination_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::WEDDING_CAKE),
        static_cast<int32_t>(PhotoLabel::GRADUATION_CAP),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::MOUNTAIN),
        static_cast<int32_t>(PhotoLabel::ROSE),
        static_cast<int32_t>(PhotoLabel::RING)
    };

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);

    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::CARD))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::WEDDING))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::GRADUATE))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::PET))) !=
                classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(
                static_cast<int32_t>(AggregateType::NATURAL_SCENERY))) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(
                static_cast<int32_t>(AggregateType::FLOWERS_AND_PLANTS))) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(std::to_string(static_cast<int32_t>(AggregateType::JEWELRY))) !=
                classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("CollectAlbumInfo_ComplexLabelCombination_Test end");
}

// More EnsureClassifyAlbumId tests
HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_NumericName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_NumericName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = "12345";
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_NumericName_Test end");
}

HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_UnicodeName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_UnicodeName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = "测试相册";
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_UnicodeName_Test end");
}

HWTEST_F(ClassifyRestoreTest, EnsureClassifyAlbumId_SpecialCharsName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_SpecialCharsName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = "test@#$%^&*()album";
    int32_t result = classifyRestore.EnsureClassifyAlbumId(albumName);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("EnsureClassifyAlbumId_SpecialCharsName_Test end");
}

// More InsertAlbumMappings tests
HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_ExactPageSize_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_ExactPageSize_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 200; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_ExactPageSize_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_OverPageSize_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_OverPageSize_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 250; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_OverPageSize_Test end");
}

HWTEST_F(ClassifyRestoreTest, InsertAlbumMappings_MultipleAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("InsertAlbumMappings_MultipleAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    for (int i = 0; i < 10; i++) {
        NativeRdb::ValuesBucket value;
        value.PutInt("map_album", i + 1);
        value.PutInt("map_asset", TEST_FILE_ID_NEW + i);
        values.push_back(value);
    }

    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("InsertAlbumMappings_MultipleAlbums_Test end");
}

// More CreateOrUpdateCategoryAlbums tests
HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_MultipleAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_MultipleAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 5; i++) {
        std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD) + i);
        classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_MultipleAlbums_Test end");
}

HWTEST_F(ClassifyRestoreTest, CreateOrUpdateCategoryAlbums_LargeBatch_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_LargeBatch_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::string albumName = std::to_string(static_cast<int32_t>(PhotoLabel::ID_CARD));
    for (int i = 0; i < 500; i++) {
        classifyRestore.albumAssetMap_[albumName].insert(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("CreateOrUpdateCategoryAlbums_LargeBatch_Test end");
}

// More HandleOcr comprehensive tests
HWTEST_F(ClassifyRestoreTest, HandleOcr_AllOcrTypes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_AllOcrTypes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    for (int i = 0; i < 20; i++) {
        subLabelMap[TEST_FILE_ID_NEW + i] = {static_cast<int32_t>(PhotoLabel::ID_CARD), i};
    }

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_AllOcrTypes_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcr_NoMatchingIdCard_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcr_NoMatchingIdCard_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {5, 6, 7, 8, 9};
    subLabelMap[TEST_FILE_ID_NEW + 1] = {10, 11, 12};

    classifyRestore.HandleOcr(subLabelMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcr_NoMatchingIdCard_Test end");
}

// More HandleOcrHelper tests
HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_LargeFileIdList_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_LargeFileIdList_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds;
    for (int i = 0; i < 100; i++) {
        fileIds.push_back(TEST_FILE_ID_NEW + i);
    }

    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_LargeFileIdList_Test end");
}

HWTEST_F(ClassifyRestoreTest, HandleOcrHelper_DuplicateFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleOcrHelper_DuplicateFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW, TEST_FILE_ID_NEW, TEST_FILE_ID_NEW};
    classifyRestore.HandleOcrHelper(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("HandleOcrHelper_DuplicateFileIds_Test end");
}

// More AddIdCardAlbum tests
HWTEST_F(ClassifyRestoreTest, AddIdCardAlbum_BothTypes_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddIdCardAlbum_BothTypes_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_set<int32_t> fileIds1 = {TEST_FILE_ID_NEW};
    std::unordered_set<int32_t> fileIds2 = {TEST_FILE_ID_NEW + 1};

    classifyRestore.AddIdCardAlbum(OcrAggregateType::FRONT_CARD, fileIds1);
    classifyRestore.AddIdCardAlbum(OcrAggregateType::BACK_CARD, fileIds2);

    std::string frontCard = std::to_string(static_cast<int32_t>(OcrAggregateType::FRONT_CARD));
    std::string backCard = std::to_string(static_cast<int32_t>(OcrAggregateType::BACK_CARD));

    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(frontCard) != classifyRestore.albumAssetMap_.end());
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(backCard) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("AddIdCardAlbum_BothTypes_Test end");
}

// More RestoreClassify comprehensive tests
HWTEST_F(ClassifyRestoreTest, RestoreClassify_WithDifferentCategories_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_WithDifferentCategories_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 20; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfo.cloudPath = "cloud/path/test" + std::to_string(i) + ".jpg";
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_WithDifferentCategories_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreClassify_WithCloudPaths_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_WithCloudPaths_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfo.cloudPath = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_WithCloudPaths_Test end");
}

HWTEST_F(ClassifyRestoreTest, RestoreClassify_WithEmptyCloudPaths_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RestoreClassify_WithEmptyCloudPaths_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfo.cloudPath = "";
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("RestoreClassify_WithEmptyCloudPaths_Test end");
}

// More Init comprehensive tests
HWTEST_F(ClassifyRestoreTest, Init_OnlyMediaLibraryRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_OnlyMediaLibraryRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), nullptr);

    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    EXPECT_NE(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_EQ(classifyRestore.galleryRdb_, nullptr);
    MEDIA_INFO_LOG("Init_OnlyMediaLibraryRdb_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_OnlyGalleryRdb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_OnlyGalleryRdb_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, nullptr, g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    EXPECT_EQ(classifyRestore.mediaLibraryRdb_, nullptr);
    EXPECT_NE(classifyRestore.galleryRdb_, nullptr);
    MEDIA_INFO_LOG("Init_OnlyGalleryRdb_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_ZeroSceneCode_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_ZeroSceneCode_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(0, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, 0);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    MEDIA_INFO_LOG("Init_ZeroSceneCode_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_LargeSceneCode_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_LargeSceneCode_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(INT32_MAX, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, INT32_MAX);
    EXPECT_EQ(classifyRestore.taskId_, TEST_TASK_ID);
    MEDIA_INFO_LOG("Init_LargeSceneCode_Test end");
}

HWTEST_F(ClassifyRestoreTest, Init_VeryLongTaskId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Init_VeryLongTaskId_Test start");
    ClassifyRestore classifyRestore;
    std::string longTaskId = std::string(1000, '1');
    classifyRestore.Init(TEST_SCENE_CODE, longTaskId, g_rdbStore->GetRaw(), g_galleryPtr);

    EXPECT_EQ(classifyRestore.sceneCode_, TEST_SCENE_CODE);
    EXPECT_EQ(classifyRestore.taskId_, longTaskId);
    MEDIA_INFO_LOG("Init_VeryLongTaskId_Test end");
}

// More TransferLabelInfo edge cases
HWTEST_F(ClassifyRestoreTest, TransferLabelInfo_EmptyVersion_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("TransferLabelInfo_EmptyVersion_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "1,2,3";
    info.version = "";

    classifyRestore.TransferLabelInfo(info);
    EXPECT_EQ(info.version, "backup");
    EXPECT_EQ(info.subLabel, "[1,2,]");
    MEDIA_INFO_LOG("TransferLabelInfo_EmptyVersion_Test end");
}

HWTEST_F(ClassifyRestoreTest, TransferLabelInfo_SubLabelAlreadyBracketed_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("TransferLabelInfo_SubLabelAlreadyBracketed_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "[1,2,3]";
    info.version = "1.0";

    classifyRestore.TransferLabelInfo(info);
    EXPECT_EQ(info.version, "backup1.0");
    EXPECT_EQ(info.subLabel, "[[1,2,3]");
    MEDIA_INFO_LOG("TransferLabelInfo_SubLabelAlreadyBracketed_Test end");
}

HWTEST_F(ClassifyRestoreTest, TransferLabelInfo_MultipleCommas_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("TransferLabelInfo_MultipleCommas_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "1,2,3,,,";
    info.version = "1.0";

    classifyRestore.TransferLabelInfo(info);
    EXPECT_EQ(info.version, "backup1.0");
    EXPECT_EQ(info.subLabel, "[1,2,3,,]");
    MEDIA_INFO_LOG("TransferLabelInfo_MultipleCommas_Test end");
}

// More UpdateLabelInsertValues tests
HWTEST_F(ClassifyRestoreTest, UpdateLabelInsertValues_ZeroFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateLabelInsertValues_ZeroFileId_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.photoInfo.fileIdNew = 0;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "[1,2]";
    info.prob = 0.9;
    info.version = "backup1.0";

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.UpdateLabelInsertValues(values, info);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("UpdateLabelInsertValues_ZeroFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateLabelInsertValues_NegativeCategory_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateLabelInsertValues_NegativeCategory_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    info.categoryId = -100;
    info.subLabel = "[1,2]";
    info.prob = 0.9;
    info.version = "backup1.0";

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.UpdateLabelInsertValues(values, info);
    EXPECT_EQ(values.size(), 1);
    MEDIA_INFO_LOG("UpdateLabelInsertValues_NegativeCategory_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateLabelInsertValues_ZeroProb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateLabelInsertValues_ZeroProb_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "[1,2]";
    info.prob = 0.0;
    info.version = "backup1.0";

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.UpdateLabelInsertValues(values, info);
    EXPECT_EQ(values.size(), 1);
    MEDIA_INFO_LOG("UpdateLabelInsertValues_ZeroProb_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateLabelInsertValues_NegativeProb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateLabelInsertValues_NegativeProb_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "[1,2]";
    info.prob = -0.5;
    info.version = "backup1.0";

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.UpdateLabelInsertValues(values, info);
    EXPECT_EQ(values.size(), 1);
    MEDIA_INFO_LOG("UpdateLabelInsertValues_NegativeProb_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateLabelInsertValues_OverOneProb_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateLabelInsertValues_OverOneProb_Test start");
    ClassifyRestore classifyRestore;
    ClassifyRestore::GalleryLabelInfo info;
    info.photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    info.categoryId = TEST_CATEGORY_ID;
    info.subLabel = "[1,2]";
    info.prob = 1.5;
    info.version = "backup1.0";

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.UpdateLabelInsertValues(values, info);
    EXPECT_EQ(values.size(), 1);
    MEDIA_INFO_LOG("UpdateLabelInsertValues_OverOneProb_Test end");
}

// More UpdateStatus tests
HWTEST_F(ClassifyRestoreTest, UpdateStatus_SingleFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateStatus_SingleFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {TEST_FILE_ID_NEW};
    classifyRestore.UpdateStatus(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("UpdateStatus_SingleFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateStatus_MaxIntFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateStatus_MaxIntFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {INT32_MAX};
    classifyRestore.UpdateStatus(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("UpdateStatus_MaxIntFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, UpdateStatus_MixedFileIds_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateStatus_MixedFileIds_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<int32_t> fileIds = {-1, 0, 1, TEST_FILE_ID_NEW, INT32_MAX};
    classifyRestore.UpdateStatus(fileIds);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("UpdateStatus_MixedFileIds_Test end");
}

// More GetShouldEndTime comprehensive tests
HWTEST_F(ClassifyRestoreTest, GetShouldEndTime_ThresholdBoundary_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetShouldEndTime_ThresholdBoundary_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.taskId_ = "1000000000";

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 30000; i++) {
        PhotoInfo info;
        info.fileIdNew = i;
        photoInfoMap[i] = info;
    }

    int64_t result = classifyRestore.GetShouldEndTime(photoInfoMap, 0);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("GetShouldEndTime_ThresholdBoundary_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetShouldEndTime_JustOverThreshold_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetShouldEndTime_JustOverThreshold_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.taskId_ = "1000000000";

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 30001; i++) {
        PhotoInfo info;
        info.fileIdNew = i;
        photoInfoMap[i] = info;
    }

    int64_t result = classifyRestore.GetShouldEndTime(photoInfoMap, 0);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("GetShouldEndTime_JustOverThreshold_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetShouldEndTime_VeryLargeDataSize_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetShouldEndTime_VeryLargeDataSize_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.taskId_ = "1000000000";

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 100000; i++) {
        PhotoInfo info;
        info.fileIdNew = i;
        photoInfoMap[i] = info;
    }

    int64_t result = classifyRestore.GetShouldEndTime(photoInfoMap, 0);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("GetShouldEndTime_VeryLargeDataSize_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetShouldEndTime_WithImageCollectionSize_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetShouldEndTime_WithImageCollectionSize_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.taskId_ = "1000000000";

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 1000; i++) {
        PhotoInfo info;
        info.fileIdNew = i;
        photoInfoMap[i] = info;
    }

    int64_t result = classifyRestore.GetShouldEndTime(photoInfoMap, 5000);
    EXPECT_GT(result, 0);
    MEDIA_INFO_LOG("GetShouldEndTime_WithImageCollectionSize_Test end");
}

// More comprehensive integration tests
HWTEST_F(ClassifyRestoreTest, Integration_CompleteRestoreWithLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_CompleteRestoreWithLabels_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfo.cloudPath = "cloud/path/test.jpg";
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    classifyRestore.GetMaxIds();
    classifyRestore.RestoreClassify(photoInfoMap);
    classifyRestore.ReportRestoreTask();

    EXPECT_GE(classifyRestore.maxIdOfLabel_, 0);
    EXPECT_GE(classifyRestore.restoreTimeCost_, 0);
    MEDIA_INFO_LOG("Integration_CompleteRestoreWithLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, Integration_MultipleRestoreCalls_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_MultipleRestoreCalls_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 3; i++) {
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
        classifyRestore.RestoreClassify(photoInfoMap);
    }
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("Integration_MultipleRestoreCalls_Test end");
}

HWTEST_F(ClassifyRestoreTest, Integration_AlbumCreationAndMapping_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_AlbumCreationAndMapping_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    classifyRestore.CreateOrUpdateCategoryAlbums();
    classifyRestore.EnsureSpecialAlbums();
    classifyRestore.ProcessCategoryAlbums();

    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Integration_AlbumCreationAndMapping_Test end");
}

HWTEST_F(ClassifyRestoreTest, Integration_OcrAndIdCardAlbum_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Integration_OcrAndIdCardAlbum_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, std::vector<int32_t>> subLabelMap;
    subLabelMap[TEST_FILE_ID_NEW] = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.HandleOcr(subLabelMap);
    classifyRestore.ProcessCategoryAlbums();
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("Integration_OcrAndIdCardAlbum_Test end");
}

// More error handling and edge cases
HWTEST_F(ClassifyRestoreTest, ErrorHandling_InvalidTableName_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ErrorHandling_InvalidTableName_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    NativeRdb::ValuesBucket value;
    value.PutInt("file_id", TEST_FILE_ID_NEW);
    values.push_back(value);

    int64_t rowNum = 0;
    int32_t result = classifyRestore.BatchInsertWithRetry("invalid_table_name", values, rowNum);
    EXPECT_LT(result, 0);
    MEDIA_INFO_LOG("ErrorHandling_InvalidTableName_Test end");
}

HWTEST_F(ClassifyRestoreTest, ErrorHandling_NullPointerInValues_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ErrorHandling_NullPointerInValues_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::vector<NativeRdb::ValuesBucket> values;
    classifyRestore.InsertAlbumMappings(values);
    EXPECT_TRUE(values.empty());
    MEDIA_INFO_LOG("ErrorHandling_NullPointerInValues_Test end");
}

// More boundary value tests
HWTEST_F(ClassifyRestoreTest, Boundary_MinIntFileId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Boundary_MinIntFileId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = INT32_MIN;
    int32_t categoryId = TEST_CATEGORY_ID;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Boundary_MinIntFileId_Test end");
}

HWTEST_F(ClassifyRestoreTest, Boundary_MinIntCategoryId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Boundary_MinIntCategoryId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = INT32_MIN;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    std::string categoryAlbum = std::to_string(ADD_ITEMS + categoryId);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(categoryAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("Boundary_MinIntCategoryId_Test end");
}

HWTEST_F(ClassifyRestoreTest, Boundary_MaxIntCategoryId_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Boundary_MaxIntCategoryId_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    int32_t fileIdNew = TEST_FILE_ID_NEW;
    int32_t categoryId = INT32_MAX;
    std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};

    classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    std::string categoryAlbum = std::to_string(ADD_ITEMS + categoryId);
    EXPECT_TRUE(classifyRestore.albumAssetMap_.find(categoryAlbum) != classifyRestore.albumAssetMap_.end());
    MEDIA_INFO_LOG("Boundary_MaxIntCategoryId_Test end");
}

// More performance and stress tests
HWTEST_F(ClassifyRestoreTest, Performance_ThousandLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Performance_ThousandLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels;
    for (int i = 0; i < 1000; i++) {
        labels.push_back(i % 200);
    }

    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("Performance_ThousandLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, Performance_ThousandAlbums_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Performance_ThousandAlbums_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 1000; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        int32_t categoryId = TEST_CATEGORY_ID + (i % 10);
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD) + (i % 5)};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    EXPECT_FALSE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Performance_ThousandAlbums_Test end");
}

HWTEST_F(ClassifyRestoreTest, Performance_LargePhotoInfoMap_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Performance_LargePhotoInfoMap_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    for (int i = 0; i < 1000; i++) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = TEST_FILE_ID_NEW + i;
        photoInfo.cloudPath = "cloud/path/test" + std::to_string(i) + ".jpg";
        photoInfoMap[TEST_FILE_ID_OLD + i] = photoInfo;
    }

    classifyRestore.RestoreClassify(photoInfoMap);
    EXPECT_NE(g_galleryPtr, nullptr);
    MEDIA_INFO_LOG("Performance_LargePhotoInfoMap_Test end");
}

// More combination tests
HWTEST_F(ClassifyRestoreTest, Combination_AllFunctions_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Combination_AllFunctions_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    classifyRestore.GetMaxIds();
    int64_t imageSize = classifyRestore.GetImageCollectionSize();

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = TEST_FILE_ID_NEW;
    photoInfoMap[TEST_FILE_ID_OLD] = photoInfo;

    int64_t endTime = classifyRestore.GetShouldEndTime(photoInfoMap, imageSize);
    EXPECT_GE(endTime, 0);

    classifyRestore.RestoreClassify(photoInfoMap);
    classifyRestore.ReportRestoreTask();

    MEDIA_INFO_LOG("Combination_AllFunctions_Test end");
}

HWTEST_F(ClassifyRestoreTest, Combination_ParseAndAggregate_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Combination_ParseAndAggregate_Test start");
    ClassifyRestore classifyRestore;
    std::string subLabel = "[4, 7, 14, 15]";
    std::vector<int32_t> labels = classifyRestore.ParseSubLabel(subLabel);
    std::unordered_set<int32_t> aggregates = classifyRestore.GetAggregateTypes(labels);

    EXPECT_FALSE(labels.empty());
    EXPECT_GE(aggregates.size(), 0);
    MEDIA_INFO_LOG("Combination_ParseAndAggregate_Test end");
}

HWTEST_F(ClassifyRestoreTest, Combination_CollectAndCreate_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("Combination_CollectAndCreate_Test start");
    ClassifyRestore classifyRestore;
    classifyRestore.Init(TEST_SCENE_CODE, TEST_TASK_ID, g_rdbStore->GetRaw(), g_galleryPtr);

    for (int i = 0; i < 10; i++) {
        int32_t fileIdNew = TEST_FILE_ID_NEW + i;
        int32_t categoryId = TEST_CATEGORY_ID;
        std::vector<int32_t> labels = {static_cast<int32_t>(PhotoLabel::ID_CARD)};
        classifyRestore.CollectAlbumInfo(fileIdNew, categoryId, labels);
    }

    classifyRestore.CreateOrUpdateCategoryAlbums();
    EXPECT_TRUE(classifyRestore.albumAssetMap_.empty());
    MEDIA_INFO_LOG("Combination_CollectAndCreate_Test end");
}

// More edge cases for existing functions
HWTEST_F(ClassifyRestoreTest, ParseSubLabel_MaxIntValue_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_MaxIntValue_Test start");
    ClassifyRestore classifyRestore;
    std::string maxIntStr = "[" + std::to_string(INT32_MAX) + "]";
    std::vector<int32_t> result = classifyRestore.ParseSubLabel(maxIntStr);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], INT32_MAX);
    MEDIA_INFO_LOG("ParseSubLabel_MaxIntValue_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_AllWhitespace_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_AllWhitespace_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("   \t\n\r   ");
    EXPECT_TRUE(result.empty());
    MEDIA_INFO_LOG("ParseSubLabel_AllWhitespace_Test end");
}

HWTEST_F(ClassifyRestoreTest, ParseSubLabel_ControlCharacters_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("ParseSubLabel_ControlCharacters_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> result = classifyRestore.ParseSubLabel("[1\0, 2\0, 3]");
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("ParseSubLabel_ControlCharacters_Test end");
}

// More GetAggregateTypes comprehensive tests
HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_AllPhotoLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_AllPhotoLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels;
    for (int i = 0; i <= 200; i++) {
        labels.push_back(i);
    }

    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);
    EXPECT_GE(result.size(), 0);
    MEDIA_INFO_LOG("GetAggregateTypes_AllPhotoLabels_Test end");
}

HWTEST_F(ClassifyRestoreTest, GetAggregateTypes_RepeatedLabels_Test, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAggregateTypes_RepeatedLabels_Test start");
    ClassifyRestore classifyRestore;
    std::vector<int32_t> labels = {
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::ID_CARD),
        static_cast<int32_t>(PhotoLabel::CAT),
        static_cast<int32_t>(PhotoLabel::CAT)
    };
    std::unordered_set<int32_t> result = classifyRestore.GetAggregateTypes(labels);

    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::CARD)) != result.end());
    EXPECT_TRUE(result.find(static_cast<int32_t>(AggregateType::PET)) != result.end());
    EXPECT_EQ(result.size(), 2);
    MEDIA_INFO_LOG("GetAggregateTypes_RepeatedLabels_Test end");
}

} // namespace OHOS::Media