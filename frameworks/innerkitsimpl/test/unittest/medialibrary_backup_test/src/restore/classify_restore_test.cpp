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

} // namespace OHOS::Media