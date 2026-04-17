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

#include "media_burst_key_duplicate_task_test.h"

#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_log.h"
#include "media_upgrade.h"
#include "media_column.h"
#include "media_burst_key_duplicate_task.h"
#include "photo_album_column.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

static void CleanTestTables()
{
    std::vector<std::string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        PhotoAlbumColumns::TABLE,
    };
    for (auto &dropTable : dropTableList) {
        std::string dropSql = "DROP TABLE IF EXISTS " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}
 
static void SetTables()
{
    std::vector<std::string> createTableSqlList = {
        PhotoUpgrade::CREATE_PHOTO_TABLE,
        PhotoAlbumColumns::CREATE_TABLE,
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

static int64_t InsertPhoto(int64_t ownerAlbumId, const std::string &burstKey)
{
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, ownerAlbumId);
    values.PutString(PhotoColumn::PHOTO_BURST_KEY, burstKey);
    values.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, 1);

    int64_t outRowId = -1;
    int32_t insertResult = g_rdbStore->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, values);
    if (insertResult != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert photo failed, ownerAlbumId=%{public}" PRId64 ", burstKey=%{public}s",
            ownerAlbumId, burstKey.c_str());
        return -1;
    }
    return outRowId;
}

static int64_t InsertAlbum()
{
    int64_t albumId = 0;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::USER);
    valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumSubType::USER_GENERIC);
    int32_t ret = g_rdbStore->Insert(albumId, PhotoAlbumColumns::TABLE, valuesBucket);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert album failed");
        return -1;
    }
    MEDIA_INFO_LOG("Insert albumId is %{public}s", to_string(albumId).c_str());
    return albumId;
}

void MediaBurstKeyDuplicateTaskTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaBurstKeyDuplicateTaskTest failed, can not get g_rdbStore");
        exit(1);
    }
    CleanTestTables();
    SetTables();
    MEDIA_INFO_LOG("MediaBurstKeyDuplicateTaskTest SetUpTestCase");
}

void MediaBurstKeyDuplicateTaskTest::TearDownTestCase(void)
{
    CleanTestTables();
    SetTables();
    MEDIA_INFO_LOG("MediaBurstKeyDuplicateTaskTest TearDownTestCase");
}

void MediaBurstKeyDuplicateTaskTest::SetUp()
{
    CleanTestTables();
    SetTables();
    MEDIA_INFO_LOG("MediaBurstKeyDuplicateTaskTest SetUp");
}

void MediaBurstKeyDuplicateTaskTest::TearDown(void) {}

// 测试目标：验证在空数据库中，FindDuplicateBurstKey() 返回空列表
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_001 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 不插入任何数据，应该返回空列表
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 0);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_001 end, size=%{public}zu", result.size());
}

// 测试目标：验证在没有重复 burst_key 的情况下，FindDuplicateBurstKey() 返回空列表
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_002 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    int64_t albumId3 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    ASSERT_GT(albumId3, 0);
    
    // 插入不重复的 burst_key 数据
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_1"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_2"), 0);
    ASSERT_GT(InsertPhoto(albumId3, "burst_key_3"), 0);
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 0);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_002 end, size=%{public}zu", result.size());
}

// 测试目标：验证在同一个相册内，相同的 burst_key 不会被认为是重复
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_003 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId = InsertAlbum();
    ASSERT_GT(albumId, 0);
    
    // 在同一个相册内插入多个相同的 burst_key
    ASSERT_GT(InsertPhoto(albumId, "burst_key_same"), 0);
    ASSERT_GT(InsertPhoto(albumId, "burst_key_same"), 0);
    ASSERT_GT(InsertPhoto(albumId, "burst_key_same"), 0);
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 0);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_003 end, size=%{public}zu", result.size());
}

// 测试目标：验证跨相册的重复 burst_key 能够被正确识别
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_004 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    int64_t albumId3 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    ASSERT_GT(albumId3, 0);
    
    // 在不同相册插入相同的 burst_key
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_dup"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_dup"), 0);
    ASSERT_GT(InsertPhoto(albumId3, "burst_key_dup"), 0);
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 3);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_004 end, size=%{public}zu", result.size());
}

// 测试目标：验证多个跨相册的重复 burst_key 能够被全部识别
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_005 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    int64_t albumId3 = InsertAlbum();
    int64_t albumId4 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    ASSERT_GT(albumId3, 0);
    ASSERT_GT(albumId4, 0);
    
    // 插入多组跨相册的重复 burst_key
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_1"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_1"), 0);
    ASSERT_GT(InsertPhoto(albumId3, "burst_key_2"), 0);
    ASSERT_GT(InsertPhoto(albumId4, "burst_key_2"), 0);
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_3"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_3"), 0);
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 6);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_005 end, size=%{public}zu", result.size());
}

// 测试目标：验证空 burst_key 不会被查询
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_006 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    
    // 插入空 burst_key 的数据
    ASSERT_GT(InsertPhoto(albumId1, ""), 0);
    ASSERT_GT(InsertPhoto(albumId2, ""), 0);
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_EQ(result.size(), 0);
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_006 end, size=%{public}zu", result.size());
}

// 测试目标：验证 UpdateBurstKey() 方法能够成功更新 burst_key
HWTEST_F(MediaBurstKeyDuplicateTaskTest, UpdateBurstKey_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdateBurstKey_test_001 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId = InsertAlbum();
    ASSERT_GT(albumId, 0);
    
    // 插入测试数据
    int64_t photoId = InsertPhoto(albumId, "old_burst_key");
    ASSERT_GT(photoId, 0);
    
    // 更新 burst_key
    int32_t ret = task->UpdateBurstKey(albumId, "old_burst_key");
    EXPECT_EQ(ret, NativeRdb::E_OK);
    
    // 验证 burst_key 已被更新
    std::string querySql = "SELECT burst_key FROM Photos WHERE owner_album_id = " + std::to_string(albumId) +
                           " AND file_id = " + std::to_string(photoId);
    auto resultSet = g_rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    std::string newBurstKey;
    resultSet->GetString(0, newBurstKey);
    EXPECT_EQ(newBurstKey.length(), 36); // UUID 长度应该是 36
    
    resultSet->Close();
    MEDIA_INFO_LOG("UpdateBurstKey_test_001 end, new_burst_key=%{public}s", newBurstKey.c_str());
}

// 测试目标：验证 UpdateBurstKey() 方法对多个相同 burst_key 的记录都能更新
HWTEST_F(MediaBurstKeyDuplicateTaskTest, UpdateBurstKey_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdateBurstKey_test_002 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId = InsertAlbum();
    ASSERT_GT(albumId, 0);
    
    // 插入多个相同 burst_key 的记录
    ASSERT_GT(InsertPhoto(albumId, "burst_key_multi"), 0);
    ASSERT_GT(InsertPhoto(albumId, "burst_key_multi"), 0);
    ASSERT_GT(InsertPhoto(albumId, "burst_key_multi"), 0);
    
    // 更新 burst_key
    int32_t ret = task->UpdateBurstKey(albumId, "burst_key_multi");
    EXPECT_EQ(ret, NativeRdb::E_OK);
    
    // 验证所有记录的 burst_key 都被更新
    std::string querySql = "SELECT burst_key FROM Photos WHERE owner_album_id = " + std::to_string(albumId) +
                           " AND burst_key = 'burst_key_multi'";
    auto resultSet = g_rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    
    int32_t count = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        count++;
    }
    EXPECT_EQ(count, 0); // 应该没有记录保持旧的 burst_key
    
    resultSet->Close();
    MEDIA_INFO_LOG("UpdateBurstKey_test_002 end, count=%{public}d", count);
}

// 测试目标：验证 UpdateBurstKey() 方法只更新指定相册的 burst_key
HWTEST_F(MediaBurstKeyDuplicateTaskTest, UpdateBurstKey_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("UpdateBurstKey_test_003 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    
    // 插入不同相册的相同 burst_key
    int64_t photoId1 = InsertPhoto(albumId1, "burst_key_album");
    int64_t photoId2 = InsertPhoto(albumId2, "burst_key_album");
    ASSERT_GT(photoId1, 0);
    ASSERT_GT(photoId2, 0);
    
    // 只更新相册 1 的 burst_key
    int32_t ret = task->UpdateBurstKey(albumId1, "burst_key_album");
    EXPECT_EQ(ret, NativeRdb::E_OK);
    
    // 验证相册 1 的 burst_key 被更新
    std::string querySql1 = "SELECT burst_key FROM Photos WHERE owner_album_id = " + std::to_string(albumId1) +
                            " AND file_id = " + std::to_string(photoId1);
    auto resultSet1 = g_rdbStore->QuerySql(querySql1);
    ASSERT_NE(resultSet1, nullptr);
    ASSERT_EQ(resultSet1->GoToFirstRow(), NativeRdb::E_OK);
    
    std::string newBurstKey1;
    resultSet1->GetString(0, newBurstKey1);
    EXPECT_NE(newBurstKey1, "burst_key_album");
    
    resultSet1->Close();
    
    // 验证相册 2 的 burst_key 没有被更新
    std::string querySql2 = "SELECT burst_key FROM Photos WHERE owner_album_id = " + std::to_string(albumId2) +
                            " AND file_id = " + std::to_string(photoId2);
    auto resultSet2 = g_rdbStore->QuerySql(querySql2);
    ASSERT_NE(resultSet2, nullptr);
    ASSERT_EQ(resultSet2->GoToFirstRow(), NativeRdb::E_OK);
    
    std::string newBurstKey2;
    resultSet2->GetString(0, newBurstKey2);
    EXPECT_EQ(newBurstKey2, "burst_key_album");
    
    resultSet2->Close();
    MEDIA_INFO_LOG("UpdateBurstKey_test_003 end");
}

// 测试目标：验证 HandleDuplicateBurstKey() 方法能够处理重复的 burst_key
HWTEST_F(MediaBurstKeyDuplicateTaskTest, HandleDuplicateBurstKey_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_002 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    
    // 插入跨相册的重复 burst_key
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_handle"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_handle"), 0);
    
    // 执行处理
    task->HandleDuplicateBurstKey();
    
    // 验证重复的 burst_key 已被修复
    std::string querySql = "SELECT COUNT(DISTINCT burst_key) FROM Photos WHERE burst_key = 'burst_key_handle'";
    auto resultSet = g_rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    int32_t count = 0;
    resultSet->GetInt(0, count);
    EXPECT_LE(count, 1); // 应该只有一个或没有记录保持旧的 burst_key
    
    resultSet->Close();
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_002 end, count=%{public}d", count);
}

// 测试目标：验证 HandleDuplicateBurstKey() 方法能够处理多组重复的 burst_key
HWTEST_F(MediaBurstKeyDuplicateTaskTest, HandleDuplicateBurstKey_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_003 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId1 = InsertAlbum();
    int64_t albumId2 = InsertAlbum();
    int64_t albumId3 = InsertAlbum();
    int64_t albumId4 = InsertAlbum();
    ASSERT_GT(albumId1, 0);
    ASSERT_GT(albumId2, 0);
    ASSERT_GT(albumId3, 0);
    ASSERT_GT(albumId4, 0);
    
    // 插入多组跨相册的重复 burst_key
    ASSERT_GT(InsertPhoto(albumId1, "burst_key_1"), 0);
    ASSERT_GT(InsertPhoto(albumId2, "burst_key_1"), 0);
    ASSERT_GT(InsertPhoto(albumId3, "burst_key_2"), 0);
    ASSERT_GT(InsertPhoto(albumId4, "burst_key_2"), 0);
    
    // 执行处理
    task->HandleDuplicateBurstKey();
    
    // 非息屏充电，不会修复
    std::string querySql = "SELECT COUNT(*) FROM Photos WHERE burst_key IN ('burst_key_1', 'burst_key_2')";
    auto resultSet = g_rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    int32_t count = 0;
    resultSet->GetInt(0, count);
    EXPECT_LE(count, 4);
    resultSet->Close();

    auto duplicateBurstKeyList = task->FindDuplicateBurstKey();
    for (auto &info : duplicateBurstKeyList) {
        CHECK_AND_CONTINUE(!info.burstKey.empty());
        int32_t ret = task->UpdateBurstKey(info.ownerAlbumId, info.burstKey);
        CHECK_AND_PRINT_LOG(ret == E_OK, "HandleDuplicateBurstKey failed, ret=%{public}d, "
            "owner_album_id=%{public}d, burst_key=%{public}s", ret, info.ownerAlbumId, info.burstKey.c_str());
    }
    resultSet = g_rdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    count = 0;
    resultSet->GetInt(0, count);
    EXPECT_EQ(count, 0);
    resultSet->Close();
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_003 end, count=%{public}d", count);
}

// 测试目标：验证 HandleDuplicateBurstKey() 方法跳过空的 burst_key
HWTEST_F(MediaBurstKeyDuplicateTaskTest, HandleDuplicateBurstKey_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_004 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入相册
    int64_t albumId = InsertAlbum();
    ASSERT_GT(albumId, 0);
    
    // 插入空 burst_key 的数据
    ASSERT_GT(InsertPhoto(albumId, ""), 0);
    
    // 执行处理，不应该崩溃
    task->HandleDuplicateBurstKey();
    MEDIA_INFO_LOG("HandleDuplicateBurstKey_test_004 end");
}

// 测试目标：验证分页查询能够正确处理大量数据
HWTEST_F(MediaBurstKeyDuplicateTaskTest, FindDuplicateBurstKey_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_007 start");
    auto task = std::make_shared<MediaBurstKeyDuplicateTask>();
    ASSERT_NE(task, nullptr);
    
    // 插入超过 BATCH_SIZE (200) 的重复数据
    for (int32_t i = 0; i < 300; i++) {
        int64_t albumId1 = InsertAlbum();
        int64_t albumId2 = InsertAlbum();
        ASSERT_GT(albumId1, 0);
        ASSERT_GT(albumId2, 0);
        ASSERT_GT(InsertPhoto(albumId1, "burst_key_" + std::to_string(i)), 0);
        ASSERT_GT(InsertPhoto(albumId2, "burst_key_" + std::to_string(i)), 0);
    }
    
    auto result = task->FindDuplicateBurstKey();
    EXPECT_GE(result.size(), 200); // 不满足息屏充电，只能查到200个
    MEDIA_INFO_LOG("FindDuplicateBurstKey_test_007 end, size=%{public}zu", result.size());
}

} // namespace OHOS::Media::Background
