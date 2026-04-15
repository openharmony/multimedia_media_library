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

#define MLOG_TAG "AssetMapCloneTest"

#include <memory>
#include "asset_map_clone.h"
#include "medialibrary_unistore_manager.h"
#define private public
#include "asset_map_clone_test.h"
#include "medialibrary_rdbstore.h"
#undef private

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void AssetMapCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("AssetMapCloneTest SetUpTestCase");
}

void AssetMapCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("AssetMapCloneTest TearDownTestCase");
}

void AssetMapCloneTest::SetUp(void)
{
    MEDIA_INFO_LOG("AssetMapCloneTest SetUp");
}

void AssetMapCloneTest::TearDown(void)
{
    MEDIA_INFO_LOG("AssetMapCloneTest TearDown");
}

HWTEST_F(AssetMapCloneTest, Constructor_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Constructor_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;

    PhotoInfo info1;
    info1.fileIdNew = 1;
    info1.cloudPath = "/test/path1";
    photoInfoMap[1] = info1;

    PhotoInfo info2;
    info2.fileIdNew = 2;
    info2.cloudPath = "/test/path2";
    photoInfoMap[2] = info2;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Constructor_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 100; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Constructor_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[INT32_MAX] = {INT32_MAX, 0, "", "/test/path/max"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Constructor_test_005, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, CloneAssetMapInfo_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, CloneAssetMapInfo_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    PhotoInfo info1;
    info1.fileIdNew = 1;
    info1.cloudPath = "/test/path1";
    photoInfoMap[1] = info1;

    PhotoInfo info2;
    info2.fileIdNew = 2;
    info2.cloudPath = "/test/path2";
    photoInfoMap[2] = info2;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, CloneAssetMapInfo_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, CloneAssetMapInfo_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 5; i++) {
        bool result = clone.CloneAssetMapInfo();
        EXPECT_TRUE(result);
    }
}

HWTEST_F(AssetMapCloneTest, CloneAssetMapInfo_test_005, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    PhotoInfo info1;
    info1.fileIdNew = 1;
    info1.cloudPath = "/test/path1";
    photoInfoMap[1] = info1;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, GetMigratedCount_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count = clone.GetMigratedCount();
    
    EXPECT_GE(count, 0);
}

HWTEST_F(AssetMapCloneTest, GetMigratedCount_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    PhotoInfo info1;
    info1.fileIdNew = 1;
    info1.cloudPath = "/test/path1";
    photoInfoMap[1] = info1;

    PhotoInfo info2;
    info2.fileIdNew = 2;
    info2.cloudPath = "/test/path2";
    photoInfoMap[2] = info2;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count1 = clone.GetMigratedCount();
    int64_t count2 = clone.GetMigratedCount();
    
    EXPECT_EQ(count1, count2);
}

HWTEST_F(AssetMapCloneTest, GetMigratedCount_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 100; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count = clone.GetMigratedCount();
    
    EXPECT_GE(count, 0);
}

HWTEST_F(AssetMapCloneTest, GetInsertNum_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count = clone.GetInsertNum();
    
    EXPECT_GE(count, 0);
}

HWTEST_F(AssetMapCloneTest, GetInsertNum_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count1 = clone.GetInsertNum();
    int64_t count2 = clone.GetInsertNum();
    
    EXPECT_EQ(count1, count2);
}

HWTEST_F(AssetMapCloneTest, GetInsertNum_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t count = clone.GetInsertNum();
    
    EXPECT_GE(count, 0);
}

HWTEST_F(AssetMapCloneTest, GetTotalTimeCost_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, GetTotalTimeCost_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t timeCost1 = clone.GetTotalTimeCost();
    int64_t timeCost2 = clone.GetTotalTimeCost();
    
    EXPECT_EQ(timeCost1, timeCost2);
}

HWTEST_F(AssetMapCloneTest, GetTotalTimeCost_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 25; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, Integration_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_TRUE(result);
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, Integration_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 10; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
}

HWTEST_F(AssetMapCloneTest, Integration_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    bool result = clone.CloneAssetMapInfo();
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_TRUE(result);
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, Integration_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 5; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Integration_test_005, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 20; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
}

HWTEST_F(AssetMapCloneTest, Stress_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 100; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, Stress_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 50; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Stress_test_003, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 20; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 10; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (auto& clone : clones) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Stress_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 200; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, EdgeCase_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, EdgeCase_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[0] = {0, 0, "test0", "/test/path0"};
    photoInfoMap[INT32_MAX] = {INT32_MAX, 0, "test1", "/test/path/max"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, EdgeCase_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[-1] = {-1, 0, "test", "/test/path/neg"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, EdgeCase_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "", ""};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, EdgeCase_test_005, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 1000; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t migratedCount = clone.GetMigratedCount();
    
    EXPECT_GE(migratedCount, 0);
}

HWTEST_F(AssetMapCloneTest, Performance_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    auto start = std::chrono::high_resolution_clock::now();
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 1000);
}

HWTEST_F(AssetMapCloneTest, Performance_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 2000);
}

HWTEST_F(AssetMapCloneTest, Performance_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);
}

HWTEST_F(AssetMapCloneTest, Performance_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 20; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        EXPECT_GE(migratedCount, 0);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 1000);
}

HWTEST_F(AssetMapCloneTest, Memory_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 100; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Memory_test_002, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 50; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 10; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    EXPECT_EQ(clones.size(), 50);
}

HWTEST_F(AssetMapCloneTest, Memory_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 1000; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    EXPECT_EQ(clone.sourceRdb_, sourceRdb);
    EXPECT_EQ(clone.destRdb_, destRdb);
}

HWTEST_F(AssetMapCloneTest, Memory_test_004, TestSize.Level1)
{
    std::vector<std::unique_ptr<AssetMapClone>> clones;
    
    for (int i = 0; i < 20; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
        
        clones.push_back(std::make_unique<AssetMapClone>(sourceRdb, destRdb, photoInfoMap));
    }
    
    EXPECT_EQ(clones.size(), 20);
}

HWTEST_F(AssetMapCloneTest, Robustness_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 50; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Robustness_test_002, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 10; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 20; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (auto& clone : clones) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Robustness_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 25; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 25; i++) {
        bool result = clone.CloneAssetMapInfo();
        EXPECT_TRUE(result);
    }
}

HWTEST_F(AssetMapCloneTest, Robustness_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 100; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Sequence_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 10; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 10; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Sequence_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 20; i++) {
        bool result = clone.CloneAssetMapInfo();
        EXPECT_TRUE(result);
    }
}

HWTEST_F(AssetMapCloneTest, Sequence_test_003, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 5; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 10; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (size_t i = 0; i < clones.size(); i++) {
        int64_t migratedCount = clones[i].GetMigratedCount();
        int64_t insertNum = clones[i].GetInsertNum();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Boundary_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    
    EXPECT_TRUE(result);
}

HWTEST_F(AssetMapCloneTest, Boundary_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
}

HWTEST_F(AssetMapCloneTest, Boundary_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[INT32_MAX] = {INT32_MAX, 0, "test", "/test/path/max"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    int64_t migratedCount = clone.GetMigratedCount();
    
    EXPECT_GE(migratedCount, 0);
}

HWTEST_F(AssetMapCloneTest, Boundary_test_004, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 2; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 2; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Random_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 30; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 30; i++) {
        if (i % 3 == 0) {
            int64_t migratedCount = clone.GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        } else if (i % 3 == 1) {
            int64_t insertNum = clone.GetInsertNum();
            EXPECT_GE(insertNum, 0);
        } else {
            int64_t timeCost = clone.GetTotalTimeCost();
            EXPECT_GE(timeCost, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Random_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 25; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 25; i++) {
        if (i % 2 == 0) {
            bool result = clone.CloneAssetMapInfo();
            EXPECT_TRUE(result);
        } else {
            int64_t migratedCount = clone.GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Random_test_003, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 10; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 15; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (size_t i = 0; i < clones.size(); i++) {
        if (i % 2 == 0) {
            int64_t migratedCount = clones[i].GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, LongRunning_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 100; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 100; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, LongRunning_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 50; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 50; i++) {
        bool result = clone.CloneAssetMapInfo();
        EXPECT_TRUE(result);
    }
}

HWTEST_F(AssetMapCloneTest, LongRunning_test_003, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 10; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 20; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (auto& clone : clones) {
        for (int i = 0; i < 20; i++) {
            int64_t migratedCount = clone.GetMigratedCount();
            int64_t insertNum = clone.GetInsertNum();
            
            EXPECT_GE(migratedCount, 0);
            EXPECT_GE(insertNum, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Alternating_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 20; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 20; i++) {
        if (i % 2 == 0) {
            bool result = clone.CloneAssetMapInfo();
            EXPECT_TRUE(result);
        } else {
            int64_t migratedCount = clone.GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Alternating_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 15; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Alternating_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 30; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 30; i++) {
        if (i % 3 == 0) {
            int64_t migratedCount = clone.GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        } else if (i % 3 == 1) {
            int64_t insertNum = clone.GetInsertNum();
            EXPECT_GE(insertNum, 0);
        } else {
            int64_t timeCost = clone.GetTotalTimeCost();
            EXPECT_GE(timeCost, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount1 = clone.GetMigratedCount();
    int64_t migratedCount2 = clone.GetMigratedCount();
    
    EXPECT_EQ(migratedCount1, migratedCount2);
}

HWTEST_F(AssetMapCloneTest, Consistency_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 10; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount1 = clone.GetMigratedCount();
    int64_t insertNum1 = clone.GetInsertNum();
    int64_t timeCost1 = clone.GetTotalTimeCost();
    
    int64_t migratedCount2 = clone.GetMigratedCount();
    int64_t insertNum2 = clone.GetInsertNum();
    int64_t timeCost2 = clone.GetTotalTimeCost();
    
    EXPECT_EQ(migratedCount1, migratedCount2);
    EXPECT_EQ(insertNum1, insertNum2);
    EXPECT_EQ(timeCost1, timeCost2);
}

HWTEST_F(AssetMapCloneTest, Consistency_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 20; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_004, TestSize.Level1)
{
    std::vector<AssetMapClone> clones;
    
    for (int i = 0; i < 5; i++) {
        auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
        std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
        
        for (int j = 0; j < 10; j++) {
            photoInfoMap[j] = {j, 0, "test", "/test/path" + std::to_string(j)};
        }
        
        clones.emplace_back(sourceRdb, destRdb, photoInfoMap);
    }
    
    for (size_t i = 0; i < clones.size(); i++) {
        int64_t migratedCount1 = clones[i].GetMigratedCount();
        int64_t migratedCount2 = clones[i].GetMigratedCount();
        
        EXPECT_EQ(migratedCount1, migratedCount2);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_005, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 15; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 15; i++) {
        if (i % 3 == 0) {
            int64_t migratedCount = clone.GetMigratedCount();
            EXPECT_GE(migratedCount, 0);
        } else if (i % 3 == 1) {
            int64_t insertNum = clone.GetInsertNum();
            EXPECT_GE(insertNum, 0);
        }
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_006, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    std::vector<int64_t> migratedCounts;
    for (int i = 0; i < 10; i++) {
        migratedCounts.push_back(clone.GetMigratedCount());
    }
    
    for (size_t i = 1; i < migratedCounts.size(); i++) {
        EXPECT_EQ(migratedCounts[i], migratedCounts[0]);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_007, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 20; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 20; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_008, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 10; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        int64_t timeCost = clone.GetTotalTimeCost();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
        EXPECT_GE(timeCost, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_009, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 25; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 25; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        EXPECT_GE(migratedCount, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Consistency_test_010, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 30; i++) {
        int64_t migratedCount = clone.GetMigratedCount();
        int64_t insertNum = clone.GetInsertNum();
        
        EXPECT_GE(migratedCount, 0);
        EXPECT_GE(insertNum, 0);
    }
}

HWTEST_F(AssetMapCloneTest, Final_test_001, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    photoInfoMap[2] = {2, 0, "test2", "/test/path2"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    bool result = clone.CloneAssetMapInfo();
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_TRUE(result);
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, Final_test_002, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    for (int i = 0; i < 10; i++) {
        photoInfoMap[i] = {i, 0, "test" + std::to_string(i), "/test/path" + std::to_string(i)};
    }
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    int64_t migratedCount = clone.GetMigratedCount();
    int64_t insertNum = clone.GetInsertNum();
    int64_t timeCost = clone.GetTotalTimeCost();
    
    EXPECT_GE(migratedCount, 0);
    EXPECT_GE(insertNum, 0);
    EXPECT_GE(timeCost, 0);
}

HWTEST_F(AssetMapCloneTest, Final_test_003, TestSize.Level1)
{
    auto sourceRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    auto destRdb = MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->GetRaw();
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    
    photoInfoMap[1] = {1, 0, "test1", "/test/path1"};
    
    AssetMapClone clone(sourceRdb, destRdb, photoInfoMap);
    
    for (int i = 0; i < 20; i++) {
        bool result = clone.CloneAssetMapInfo();
        EXPECT_TRUE(result);
    }
}

} // namespace Media
} // namespace OHOS
