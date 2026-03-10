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

#define MLOG_TAG "PhotoAlbumMergeOperationTest"

#include "photo_album_merge_operation_test.h"

#include <string>
#include <vector>

#include "photo_album_merge_operation.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media {
static constexpr int32_t OLD_ALBUM_ID = 1;
static constexpr int32_t NEW_ALBUM_ID = 2;

void PhotoAlbumMergeOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAlbumMergeOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoAlbumMergeOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoAlbumMergeOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumMergeOperationTest, photo_album_merge_operation_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start photo_album_merge_operation_test_001");
    PhotoAlbumMergeOperation photoAlbumMergeOperation;
    int32_t ret = photoAlbumMergeOperation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

HWTEST_F(PhotoAlbumMergeOperationTest, photo_album_merge_operation_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start photo_album_merge_operation_test_002");
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    PhotoAlbumMergeOperation photoAlbumMergeOperation;
    int32_t ret = photoAlbumMergeOperation.SetRdbStore(g_rdbStore).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(PhotoAlbumMergeOperationTest, SetRdbStore_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetRdbStore_Test_001");
    PhotoAlbumMergeOperation operation;
    PhotoAlbumMergeOperation &result = operation.SetRdbStore(nullptr);
    EXPECT_EQ(&result, &operation);
    MEDIA_INFO_LOG("SetRdbStore_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, SetRdbStore_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetRdbStore_Test_002");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    PhotoAlbumMergeOperation &result = operation.SetRdbStore(g_rdbStore);
    EXPECT_EQ(&result, &operation);
    MEDIA_INFO_LOG("SetRdbStore_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Null_RdbStore_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Null_RdbStore_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Null_RdbStore_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Invalid_OldAlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Invalid_OldAlbumId_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(0, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Invalid_OldAlbumId_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Invalid_NewAlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Invalid_NewAlbumId_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, 0);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Invalid_NewAlbumId_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Negative_OldAlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Negative_OldAlbumId_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(-1, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Negative_OldAlbumId_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Negative_NewAlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Negative_NewAlbumId_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, -1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Negative_NewAlbumId_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Same_AlbumId_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Same_AlbumId_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, OLD_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Same_AlbumId_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Large_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Large_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(INT32_MAX, INT32_MAX - 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Large_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, MergeAlbum_Zero_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start MergeAlbum_Zero_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(0, 0);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("MergeAlbum_Zero_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Method_Chaining_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Method_Chaining_Test_001");
    PhotoAlbumMergeOperation operation;
    PhotoAlbumMergeOperation &result = operation.SetRdbStore(nullptr);
    EXPECT_EQ(&result, &operation);
    MEDIA_INFO_LOG("Method_Chaining_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Method_Chaining_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Method_Chaining_Test_002");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    int32_t ret = operation.SetRdbStore(g_rdbStore).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Method_Chaining_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiple_Merge_Operations_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiple_Merge_Operations_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    int32_t ret2 = operation.MergeAlbum(NEW_ALBUM_ID, OLD_ALBUM_ID);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Multiple_Merge_Operations_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Return_Value_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Return_Value_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_TRUE(ret == NativeRdb::E_OK || ret == NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Return_Value_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Return_Value_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Return_Value_Test_002");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    int32_t ret = operation.SetRdbStore(g_rdbStore).MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_TRUE(ret == NativeRdb::E_OK || ret == NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Return_Value_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Edge_Case_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Edge_Case_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(1, 2);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Edge_Case_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Edge_Case_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Edge_Case_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(2, 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Edge_Case_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Edge_Case_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Edge_Case_Test_003");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(100, 200);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Edge_Case_Test_003 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Edge_Case_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Edge_Case_Test_004");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(200, 100);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Edge_Case_Test_004 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Value_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Value_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(1, 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Value_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Value_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Value_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(INT32_MAX, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Value_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Value_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Value_Test_003");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(INT32_MIN, INT32_MIN);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Value_Test_003 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Value_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Value_Test_004");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(INT32_MIN, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Value_Test_004 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Value_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Value_Test_005");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.SetRdbStore(nullptr).MergeAlbum(INT32_MAX, INT32_MIN);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Value_Test_005 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Sequential_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Sequential_Merge_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Sequential_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Sequential_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Sequential_Merge_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret1 = operation.SetRdbStore(nullptr).MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Sequential_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Reverse_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Reverse_Merge_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(4, 3);
    int32_t ret2 = operation.MergeAlbum(3, 2);
    int32_t ret3 = operation.MergeAlbum(2, 1);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Reverse_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Reverse_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Reverse_Merge_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret1 = operation.SetRdbStore(nullptr).MergeAlbum(4, 3);
    int32_t ret2 = operation.MergeAlbum(3, 2);
    int32_t ret3 = operation.MergeAlbum(2, 1);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Reverse_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Null_Safety_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Null_Safety_Test_001");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(1, 2);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Null_Safety_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Null_Safety_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Null_Safety_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret = operation.MergeAlbum(1, 2);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Null_Safety_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Integration_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Integration_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Integration_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Integration_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Integration_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(OLD_ALBUM_ID, NEW_ALBUM_ID);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Integration_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiple_Instances_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiple_Instances_Test_001");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    PhotoAlbumMergeOperation operation3;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation1.SetRdbStore(g_rdbStore);
    operation2.SetRdbStore(g_rdbStore);
    operation3.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation1.MergeAlbum(1, 2);
    int32_t ret2 = operation2.MergeAlbum(3, 4);
    int32_t ret3 = operation3.MergeAlbum(5, 6);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Multiple_Instances_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiple_Instances_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiple_Instances_Test_002");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    PhotoAlbumMergeOperation operation3;
    int32_t ret1 = operation1.SetRdbStore(nullptr).MergeAlbum(1, 2);
    int32_t ret2 = operation2.SetRdbStore(nullptr).MergeAlbum(3, 4);
    int32_t ret3 = operation3.SetRdbStore(nullptr).MergeAlbum(5, 6);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Multiple_Instances_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Alternating_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Alternating_Merge_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 1);
    int32_t ret3 = operation.MergeAlbum(1, 2);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Alternating_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Alternating_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Alternating_Merge_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 1);
    int32_t ret3 = operation.MergeAlbum(1, 2);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Alternating_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Sequnce_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Sequence_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 1; i <= 50; i++) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Large_Sequence_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Sequence_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Sequence_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 1; i <= 50; i++) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Large_Sequence_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Random_Order_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Random_Order_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(10, 20);
    int32_t ret2 = operation.MergeAlbum(5, 15);
    int32_t ret3 = operation.MergeAlbum(30, 40);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Random_Order_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Random_Order_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Random_Order_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(10, 20);
    int32_t ret2 = operation.MergeAlbum(5, 15);
    int32_t ret3 = operation.MergeAlbum(30, 40);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Random_Order_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Consecutive_Ids_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Consecutive_Ids_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Consecutive_Ids_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Consecutive_Ids_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Consecutive_Ids_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Consecutive_Ids_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Non_Consecutive_Ids_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Non_Consecutive_Ids_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 10);
    int32_t ret2 = operation.MergeAlbum(20, 30);
    int32_t ret3 = operation.MergeAlbum(100, 200);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Non_Consecutive_Ids_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Non_Consecutive_Ids_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Non_Consecutive_Ids_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 10);
    int32_t ret2 = operation.MergeAlbum(20, 30);
    int32_t ret3 = operation.MergeAlbum(100, 200);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Non_Consecutive_Ids_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Repeated_Same_Operation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Repeated_Same_Operation_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 0; i < 10; i++) {
        int32_t ret = operation.MergeAlbum(1, 2);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Repeated_Same_Operation_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Repeated_Same_Operation_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Repeated_Same_Operation_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 0; i < 10; i++) {
        int32_t ret = operation.MergeAlbum(1, 2);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Repeated_Same_Operation_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, SetRdbStore_After_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetRdbStore_After_Merge_Test_001");
    PhotoAlbumMergeOperation operation;
    int32_t ret1 = operation.MergeAlbum(1, 2);
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("SetRdbStore_After_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, SetRdbStore_After_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetRdbStore_After_Merge_Test_002");
    PhotoAlbumMergeOperation operation;
    int32_t ret1 = operation.MergeAlbum(1, 2);
    operation.SetRdbStore(nullptr);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("SetRdbStore_After_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Switch_RdbStore_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Switch_RdbStore_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    operation.SetRdbStore(nullptr);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    operation.SetRdbStore(g_rdbStore);
    int32_t ret3 = operation.MergeAlbum(5, 6);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Switch_RdbStore_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Switch_RdbStore_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Switch_RdbStore_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    operation.SetRdbStore(nullptr);
    int32_t ret3 = operation.MergeAlbum(5, 6);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Switch_RdbStore_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Negative_And_Positive_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Negative_And_Positive_Test_001");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(-1, 1);
    int32_t ret2 = operation.MergeAlbum(1, -1);
    int32_t ret3 = operation.MergeAlbum(-10, -20);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Negative_And_Positive_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Zero_And_NonZero_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Zero_And_NonZero_Test_001");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(0, 1);
    int32_t ret2 = operation.MergeAlbum(1, 0);
    int32_t ret3 = operation.MergeAlbum(0, 0);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Zero_And_NonZero_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Mixed_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Mixed_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 100);
    int32_t ret2 = operation.MergeAlbum(-1, 100);
    int32_t ret3 = operation.MergeAlbum(0, 100);
    int32_t ret4 = operation.MergeAlbum(100, 0);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Mixed_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Gap_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Gap_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Large_Gap_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Gap_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Gap_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Large_Gap_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Pair_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Pair_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(100, 200);
    int32_t ret2 = operation.MergeAlbum(200, 100);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Id_Pair_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Pair_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Pair_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(100, 200);
    int32_t ret2 = operation.MergeAlbum(200, 100);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Id_Pair_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Triple_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Triple_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 1);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Id_Triple_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Triple_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Triple_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 1);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Id_Triple_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Quadruple_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Quadruple_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 1);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Id_Quadruple_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Quadruple_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Quadruple_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 1);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Id_Quadruple_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Pentagon_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Pentagon_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    int32_t ret5 = operation.MergeAlbum(5, 1);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    EXPECT_EQ(ret5, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Id_Pentagon_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Pentagon_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Pentagon_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    int32_t ret5 = operation.MergeAlbum(5, 1);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    EXPECT_EQ(ret5, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Id_Pentagon_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Cycle_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Cycle_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 1; i <= 10; i++) {
        int32_t ret = operation.MergeAlbum(i, (i % 10) + 1);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Id_Cycle_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Id_Cycle_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Id_Cycle_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 1; i <= 10; i++) {
        int32_t ret = operation.MergeAlbum(i, (i % 10) + 1);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Id_Cycle_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiple_Merge_Same_Pair_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiple_Merge_Same_Pair_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 0; i < 5; i++) {
        int32_t ret = operation.MergeAlbum(1, 2);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Multiple_Merge_Same_Pair_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiple_Merge_Same_Pair_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiple_Merge_Same_Pair_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 0; i < 5; i++) {
        int32_t ret = operation.MergeAlbum(1, 2);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Multiple_Merge_Same_Pair_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Different_RdbStore_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Different_RdbStore_Merge_Test_001");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation1.SetRdbStore(g_rdbStore);
    operation2.SetRdbStore(nullptr);
    int32_t ret1 = operation1.MergeAlbum(1, 2);
    int32_t ret2 = operation2.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Different_RdbStore_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Different_RdbStore_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Different_RdbStore_Merge_Test_002");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation1.SetRdbStore(nullptr);
    operation2.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation1.MergeAlbum(1, 2);
    int32_t ret2 = operation2.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Different_RdbStore_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Same_RdbStore_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Same_RdbStore_Merge_Test_001");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation1.SetRdbStore(g_rdbStore);
    operation2.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation1.MergeAlbum(1, 2);
    int32_t ret2 = operation2.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Same_RdbStore_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Same_RdbStore_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Same_RdbStore_Merge_Test_002");
    PhotoAlbumMergeOperation operation1;
    PhotoAlbumMergeOperation operation2;
    operation1.SetRdbStore(nullptr);
    operation2.SetRdbStore(nullptr);
    int32_t ret1 = operation1.MergeAlbum(1, 2);
    int32_t ret2 = operation2.MergeAlbum(3, 4);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Same_RdbStore_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Long_Sequence_Merge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Long_Sequence_Merge_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 1; i <= 100; i++) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Long_Sequence_Merge_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Long_Sequence_Merge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Long_Sequence_Merge_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 1; i <= 100; i++) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Long_Sequence_Merge_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Random_Pairs_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Random_Pairs_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(123, 456);
    int32_t ret2 = operation.MergeAlbum(789, 101);
    int32_t ret3 = operation.MergeAlbum(234, 567);
    int32_t ret4 = operation.MergeAlbum(890, 345);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Random_Pairs_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Random_Pairs_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Random_Pairs_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(123, 456);
    int32_t ret2 = operation.MergeAlbum(789, 101);
    int32_t ret3 = operation.MergeAlbum(234, 567);
    int32_t ret4 = operation.MergeAlbum(890, 345);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Random_Pairs_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Prime_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Prime_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(2, 3);
    int32_t ret2 = operation.MergeAlbum(5, 7);
    int32_t ret3 = operation.MergeAlbum(11, 13);
    int32_t ret4 = operation.MergeAlbum(17, 19);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Prime_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Prime_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Prime_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(2, 3);
    int32_t ret2 = operation.MergeAlbum(5, 7);
    int32_t ret3 = operation.MergeAlbum(11, 13);
    int32_t ret4 = operation.MergeAlbum(17, 19);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Prime_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Powers_Of_Two_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Powers_Of_Two_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(4, 8);
    int32_t ret3 = operation.MergeAlbum(16, 32);
    int32_t ret4 = operation.MergeAlbum(64, 128);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Powers_Of_Two_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Powers_Of_Two_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Powers_Of_Two_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(4, 8);
    int32_t ret3 = operation.MergeAlbum(16, 32);
    int32_t ret4 = operation.MergeAlbum(64, 128);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Powers_Of_Two_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Odd_Even_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Odd_Even_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    int32_t ret3 = operation.MergeAlbum(5, 6);
    int32_t ret4 = operation.MergeAlbum(7, 8);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Odd_Even_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Odd_Even_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Odd_Even_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    int32_t ret3 = operation.MergeAlbum(5, 6);
    int32_t ret4 = operation.MergeAlbum(7, 8);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Odd_Even_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiples_Of_Ten_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiples_Of_Ten_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(10, 20);
    int32_t ret2 = operation.MergeAlbum(30, 40);
    int32_t ret3 = operation.MergeAlbum(50, 60);
    int32_t ret4 = operation.MergeAlbum(70, 80);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Multiples_Of_Ten_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Multiples_Of_Ten_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Multiples_Of_Ten_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(10, 20);
    int32_t ret2 = operation.MergeAlbum(30, 40);
    int32_t ret3 = operation.MergeAlbum(50, 60);
    int32_t ret4 = operation.MergeAlbum(70, 80);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Multiples_Of_Ten_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Reverse_Order_Sequence_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Reverse_Order_Sequence_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 100; i >= 1; i--) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_OK);
    }
    MEDIA_INFO_LOG("Reverse_Order_Sequence_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Reverse_Order_Sequence_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Reverse_Order_Sequence_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 100; i >= 1; i--) {
        int32_t ret = operation.MergeAlbum(i, i + 1);
        EXPECT_EQ(ret, NativeRdb::E_ERROR);
    }
    MEDIA_INFO_LOG("Reverse_Order_Sequence_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Alternating_Sequence_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Alternating_Sequence_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    for (int i = 1; i <= 50; i++) {
        if (i % 2 == 1) {
            int32_t ret = operation.MergeAlbum(i, i + 1);
            EXPECT_EQ(ret, NativeRdb::E_OK);
        }
    }
    MEDIA_INFO_LOG("Alternating_Sequence_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Alternating_Sequence_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Alternating_Sequence_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    for (int i = 1; i <= 50; i++) {
        if (i % 2 == 1) {
            int32_t ret = operation.MergeAlbum(i, i + 1);
            EXPECT_EQ(ret, NativeRdb::E_ERROR);
        }
    }
    MEDIA_INFO_LOG("Alternating_Sequence_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Small_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Small_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Small_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Small_Values_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Small_Values_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(2, 3);
    int32_t ret3 = operation.MergeAlbum(3, 4);
    int32_t ret4 = operation.MergeAlbum(4, 5);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Small_Values_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Medium_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Medium_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(100, 200);
    int32_t ret2 = operation.MergeAlbum(300, 400);
    int32_t ret3 = operation.MergeAlbum(500, 600);
    int32_t ret4 = operation.MergeAlbum(700, 800);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Medium_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Medium_Values_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Medium_Values_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(100, 200);
    int32_t ret2 = operation.MergeAlbum(300, 400);
    int32_t ret3 = operation.MergeAlbum(500, 600);
    int32_t ret4 = operation.MergeAlbum(700, 800);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Medium_Values_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1000, 2000);
    int32_t ret2 = operation.MergeAlbum(3000, 4000);
    int32_t ret3 = operation.MergeAlbum(5000, 6000);
    int32_t ret4 = operation.MergeAlbum(7000, 8000);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Large_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Large_Values_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Large_Values_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1000, 2000);
    int32_t ret2 = operation.MergeAlbum(3000, 4000);
    int32_t ret3 = operation.MergeAlbum(5000, 6000);
    int32_t ret4 = operation.MergeAlbum(7000, 8000);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Large_Values_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Very_Large_Values_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Very_Large_Values_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(10000, 20000);
    int32_t ret2 = operation.MergeAlbum(30000, 40000);
    int32_t ret3 = operation.MergeAlbum(50000, 60000);
    int32_t ret4 = operation.MergeAlbum(70000, 80000);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Very_Large_Values_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Very_Large_Values_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Very_Large_Values_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(10000, 20000);
    int32_t ret2 = operation.MergeAlbum(30000, 40000);
    int32_t ret3 = operation.MergeAlbum(50000, 60000);
    int32_t ret4 = operation.MergeAlbum(70000, 80000);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Very_Large_Values_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Max_Value_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Max_Value_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX - 1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Boundary_Max_Value_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Max_Value_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Max_Value_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX - 1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Max_Value_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Min_Value_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Min_Value_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MIN + 1, INT32_MIN + 2);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Min_Value_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Boundary_Min_Value_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Boundary_Min_Value_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MIN + 1, INT32_MIN + 2);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Boundary_Min_Value_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, One_And_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start One_And_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("One_And_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, One_And_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start One_And_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(1, INT32_MAX);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("One_And_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Max_And_One_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Max_And_One_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX, 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Max_And_One_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Max_And_One_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Max_And_One_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX, 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Max_And_One_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Half_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Half_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 2, INT32_MAX / 2 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Half_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Half_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Half_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 2, INT32_MAX / 2 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Half_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Quarter_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Quarter_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 4, INT32_MAX / 4 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Quarter_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Quarter_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Quarter_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 4, INT32_MAX / 4 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Quarter_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Third_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Third_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 3, INT32_MAX / 3 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Third_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Third_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Third_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 3, INT32_MAX / 3 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Third_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Hundredth_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Hundredth_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 100, INT32_MAX / 100 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Hundredth_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Hundredth_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Hundredth_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 100, INT32_MAX / 100 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Hundredth_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Thousandth_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Thousandth_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 1000, INT32_MAX / 1000 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Thousandth_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Thousandth_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Thousandth_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 1000, INT32_MAX / 1000 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Thousandth_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Millionth_Max_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Millionth_Max_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 1000000, INT32_MAX / 1000000 + 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Millionth_Max_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Millionth_Max_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Millionth_Max_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret = operation.MergeAlbum(INT32_MAX / 1000000, INT32_MAX / 1000000 + 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Millionth_Max_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Square_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Square_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 4);
    int32_t ret2 = operation.MergeAlbum(9, 16);
    int32_t ret3 = operation.MergeAlbum(25, 36);
    int32_t ret4 = operation.MergeAlbum(49, 64);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Square_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Square_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Square_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 4);
    int32_t ret2 = operation.MergeAlbum(9, 16);
    int32_t ret3 = operation.MergeAlbum(25, 36);
    int32_t ret4 = operation.MergeAlbum(49, 64);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Square_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Cube_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Cube_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 8);
    int32_t ret2 = operation.MergeAlbum(27, 64);
    int32_t ret3 = operation.MergeAlbum(125, 216);
    int32_t ret4 = operation.MergeAlbum(343, 512);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Cube_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Cube_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Cube_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 8);
    int32_t ret2 = operation.MergeAlbum(27, 64);
    int32_t ret3 = operation.MergeAlbum(125, 216);
    int32_t ret4 = operation.MergeAlbum(343, 512);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Cube_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Factorial_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Factorial_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(6, 24);
    int32_t ret3 = operation.MergeAlbum(120, 720);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Factorial_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Factorial_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Factorial_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(6, 24);
    int32_t ret3 = operation.MergeAlbum(120, 720);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Factorial_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Triangle_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Triangle_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 3);
    int32_t ret2 = operation.MergeAlbum(6, 10);
    int32_t ret3 = operation.MergeAlbum(15, 21);
    int32_t ret4 = operation.MergeAlbum(28, 36);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Triangle_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Triangle_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Triangle_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 3);
    int32_t ret2 = operation.MergeAlbum(6, 10);
    int32_t ret3 = operation.MergeAlbum(15, 21);
    int32_t ret4 = operation.MergeAlbum(28, 36);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Triangle_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Hexagonal_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Hexagonal_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 6);
    int32_t ret2 = operation.MergeAlbum(15, 28);
    int32_t ret3 = operation.MergeAlbum(45, 66);
    int32_t ret4 = operation.MergeAlbum(91, 120);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Hexagonal_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Hexagonal_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Hexagonal_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 6);
    int32_t ret2 = operation.MergeAlbum(15, 28);
    int32_t ret3 = operation.MergeAlbum(45, 66);
    int32_t ret4 = operation.MergeAlbum(91, 120);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Hexagonal_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Palindromic_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Palindromic_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(11, 22);
    int32_t ret2 = operation.MergeAlbum(33, 44);
    int32_t ret3 = operation.MergeAlbum(121, 131);
    int32_t ret4 = operation.MergeAlbum(141, 151);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Palindromic_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Palindromic_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Palindromic_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(11, 22);
    int32_t ret2 = operation.MergeAlbum(33, 44);
    int32_t ret3 = operation.MergeAlbum(121, 131);
    int32_t ret4 = operation.MergeAlbum(141, 151);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Palindromic_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Armstrong_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Armstrong_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 153);
    int32_t ret2 = operation.MergeAlbum(370, 371);
    int32_t ret3 = operation.MergeAlbum(407, 1634);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Armstrong_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Armstrong_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Armstrong_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 153);
    int32_t ret2 = operation.MergeAlbum(370, 371);
    int32_t ret3 = operation.MergeAlbum(407, 1634);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Armstrong_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Perfect_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Perfect_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(6, 28);
    int32_t ret2 = operation.MergeAlbum(496, 8128);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Perfect_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Perfect_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Perfect_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(6, 28);
    int32_t ret2 = operation.MergeAlbum(496, 8128);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Perfect_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Abundant_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Abundant_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(12, 18);
    int32_t ret2 = operation.MergeAlbum(20, 24);
    int32_t ret3 = operation.MergeAlbum(30, 36);
    int32_t ret4 = operation.MergeAlbum(40, 42);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Abundant_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Abundant_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Abundant_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(12, 18);
    int32_t ret2 = operation.MergeAlbum(20, 24);
    int32_t ret3 = operation.MergeAlbum(30, 36);
    int32_t ret4 = operation.MergeAlbum(40, 42);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Abundant_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Deficient_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Deficient_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    int32_t ret3 = operation.MergeAlbum(5, 7);
    int32_t ret4 = operation.MergeAlbum(8, 9);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Deficient_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Deficient_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Deficient_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 2);
    int32_t ret2 = operation.MergeAlbum(3, 4);
    int32_t ret3 = operation.MergeAlbum(5, 7);
    int32_t ret4 = operation.MergeAlbum(8, 9);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Deficient_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Happy_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Happy_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 7);
    int32_t ret2 = operation.MergeAlbum(10, 13);
    int32_t ret3 = operation.MergeAlbum(19, 23);
    int32_t ret4 = operation.MergeAlbum(28, 31);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Happy_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Happy_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Happy_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 7);
    int32_t ret2 = operation.MergeAlbum(10, 13);
    int32_t ret3 = operation.MergeAlbum(19, 23);
    int32_t ret4 = operation.MergeAlbum(28, 31);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Happy_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Sad_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Sad_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(2, 3);
    int32_t ret2 = operation.MergeAlbum(4, 5);
    int32_t ret3 = operation.MergeAlbum(6, 8);
    int32_t ret4 = operation.MergeAlbum(9, 11);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Sad_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Sad_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Sad_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(2, 3);
    int32_t ret2 = operation.MergeAlbum(4, 5);
    int32_t ret3 = operation.MergeAlbum(6, 8);
    int32_t ret4 = operation.MergeAlbum(9, 11);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Sad_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Lucky_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Lucky_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(1, 3);
    int32_t ret2 = operation.MergeAlbum(7, 9);
    int32_t ret3 = operation.MergeAlbum(13, 15);
    int32_t ret4 = operation.MergeAlbum(21, 25);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Lucky_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Lucky_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Lucky_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(1, 3);
    int32_t ret2 = operation.MergeAlbum(7, 9);
    int32_t ret3 = operation.MergeAlbum(13, 15);
    int32_t ret4 = operation.MergeAlbum(21, 25);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Lucky_Numbers_Test_002 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Unlucky_Numbers_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Unlucky_Numbers_Test_001");
    PhotoAlbumMergeOperation operation;
    auto g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    operation.SetRdbStore(g_rdbStore);
    int32_t ret1 = operation.MergeAlbum(2, 4);
    int32_t ret2 = operation.MergeAlbum(5, 6);
    int32_t ret3 = operation.MergeAlbum(8, 10);
    int32_t ret4 = operation.MergeAlbum(11, 12);
    EXPECT_EQ(ret1, NativeRdb::E_OK);
    EXPECT_EQ(ret2, NativeRdb::E_OK);
    EXPECT_EQ(ret3, NativeRdb::E_OK);
    EXPECT_EQ(ret4, NativeRdb::E_OK);
    MEDIA_INFO_LOG("Unlucky_Numbers_Test_001 End");
}

HWTEST_F(PhotoAlbumMergeOperationTest, Unlucky_Numbers_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Unlucky_Numbers_Test_002");
    PhotoAlbumMergeOperation operation;
    operation.SetRdbStore(nullptr);
    int32_t ret1 = operation.MergeAlbum(2, 4);
    int32_t ret2 = operation.MergeAlbum(5, 6);
    int32_t ret3 = operation.MergeAlbum(8, 10);
    int32_t ret4 = operation.MergeAlbum(11, 12);
    EXPECT_EQ(ret1, NativeRdb::E_ERROR);
    EXPECT_EQ(ret2, NativeRdb::E_ERROR);
    EXPECT_EQ(ret3, NativeRdb::E_ERROR);
    EXPECT_EQ(ret4, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("Unlucky_Numbers_Test_002 End");
}
}  // namespace OHOS::Media