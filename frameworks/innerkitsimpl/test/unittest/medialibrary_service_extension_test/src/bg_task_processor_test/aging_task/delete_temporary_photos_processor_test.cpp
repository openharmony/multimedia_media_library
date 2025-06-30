/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "bg_task_processor_test.h"

#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "media_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"
#include "result_set_utils.h"

#define private public
#include "delete_temporary_photos_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int32_t STOP_FLAG = 10;

static constexpr int64_t TIME_22_HOURS = 22 * 60 * 60 * 1000;
static constexpr int64_t TIME_24_HOURS = 24 * 60 * 60 * 1000;
static constexpr int64_t TIME_26_HOURS = 26 * 60 * 60 * 1000;

static constexpr int32_t INSERT_0_DATA = 0;
static constexpr int32_t INSERT_1_DATA = 1;
static constexpr int32_t INSERT_100_DATA = 100;
static constexpr int32_t INSERT_101_DATA = 101;
static constexpr int32_t INSERT_201_DATA = 201;

static constexpr int32_t QUERY_0_DATA = 0;
static constexpr int32_t QUERY_1_DATA = 1;
static constexpr int32_t QUERY_2_DATA = 2;
static constexpr int32_t QUERY_50_DATA = 50;
static constexpr int32_t QUERY_100_DATA = 100;

int32_t InsertTempAsset(std::string dateAdded, int32_t count, int64_t &outRowId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    value.Put(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    return ret;
}

int32_t QueryTempPhotoCount(int32_t &count)
{
    vector<string> columns = { PhotoColumn::PHOTO_IS_TEMP };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY, MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, "1");
    cmd.GetAbsRdbPredicates()->OrderByAsc(MediaColumn::MEDIA_ID);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_ERR;
    }
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to GetRowCount");
        return E_ERR;
    }
    resultSet->Close();
    return E_OK;
}

/**
 * @tc.name: QueryAllTempPhoto_test_001
 * @tc.desc: 停止后台任务时, 会在QueryAllTempPhoto中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, QueryAllTempPhoto_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("QueryAllTempPhoto_test_001 start");
    auto processor = DeleteTemporaryPhotosProcessor();
    auto ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    auto result = processor.QueryAllTempPhoto(count, true);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(count, -1);

    count = -1;
    result = processor.QueryAllTempPhoto(count, false);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(count, -1);
    MEDIA_INFO_LOG("QueryAllTempPhoto_test_001 end");
}

/**
 * @tc.name: QueryAllTempPhoto_test_002
 * @tc.desc: QueryAllTempPhoto查询24小时之前的所有临时数据
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, QueryAllTempPhoto_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("QueryAllTempPhoto_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    // 插入一条24小时之前的数据
    dateAdded = to_string(current - TIME_26_HOURS);
    outRow = -1;
    ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    int32_t count = -1;
    auto processor = DeleteTemporaryPhotosProcessor();
    auto resultSet = processor.QueryAllTempPhoto(count, true);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(count, QUERY_1_DATA);

    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    int64_t dateAddedQuery = GetInt64Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);
    ret = dateAddedQuery < (current - TIME_24_HOURS);
    EXPECT_EQ(ret, true);

    MEDIA_INFO_LOG("QueryAllTempPhoto_test_002 end");
}

/**
 * @tc.name: QueryAllTempPhoto_test_003
 * @tc.desc: QueryAllTempPhoto查询所有临时数据, 并基于file_id降序排序
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, QueryAllTempPhoto_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("QueryAllTempPhoto_test_003 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    // 插入一条24小时之前的数据
    dateAdded = to_string(current - TIME_26_HOURS);
    outRow = -1;
    ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    int32_t count = -1;
    auto processor = DeleteTemporaryPhotosProcessor();
    auto resultSet = processor.QueryAllTempPhoto(count, false);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(count, QUERY_2_DATA);

    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    int32_t fileIdQueryFirst = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    EXPECT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);
    int32_t fileIdQuerySecond = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    EXPECT_EQ(fileIdQueryFirst > fileIdQuerySecond, true);
    MEDIA_INFO_LOG("QueryAllTempPhoto_test_003 end");
}

/**
 * @tc.name: DeleteAllTempPhotoOverOneDay_test_001
 * @tc.desc: 存在24小时以内的临时数据, DeleteAllTempPhotoOverOneDay 不会删除对应数据
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteAllTempPhotoOverOneDay_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_001 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteAllTempPhotoOverOneDay();

    int32_t count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, INSERT_1_DATA);
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_001 end");
}

/**
 * @tc.name: DeleteAllTempPhotoOverOneDay_test_002
 * @tc.desc: 24小时以前的临时数据超过200条, 则会循环执行 Delete, 进行分批删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteAllTempPhotoOverOneDay_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入24小时之前的数据
    std::string dateAdded = to_string(current - TIME_26_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_201_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_201_DATA);

    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteAllTempPhotoOverOneDay();

    int32_t count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_0_DATA);
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_002 end");
}

/**
 * @tc.name: DeleteTempPhotoMoreThanHundred_test_001
 * @tc.desc: 存在临时数据, 不超过100条, 则不会执行 DeleteTempPhotoMoreThanHundred
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoMoreThanHundred_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_001 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_100_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_100_DATA);

    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteTempPhotoMoreThanHundred();

    int32_t count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_100_DATA);
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_001 end");
}

/**
 * @tc.name: DeleteTempPhotoMoreThanHundred_test_002
 * @tc.desc: 存在临时数据, 超过100条, 则会执行 DeleteTempPhotoMoreThanHundred, 剩余最近的50条
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoMoreThanHundred_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_101_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_101_DATA);

    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteTempPhotoMoreThanHundred();

    int32_t count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_50_DATA);
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_002 end");
}

/**
 * @tc.name: DeleteTempPhotoExecute_test_001
 * @tc.desc: 停止后台任务时, 会在DeleteTempPhotoExecute中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoExecute_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_001 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    int32_t count = -1;
    auto processor = DeleteTemporaryPhotosProcessor();
    auto resultSet = processor.QueryAllTempPhoto(count, false);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(count, QUERY_1_DATA);
    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    int32_t fileIdQueryFirst = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    std::vector<std::string> fileIds = { std::to_string(fileIdQueryFirst) };

    ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);
    ret = processor.DeleteTempPhotoExecute(fileIds);
    EXPECT_EQ(ret, STOP_FLAG);

    count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, INSERT_1_DATA);
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_001 end");
}

/**
 * @tc.name: DeleteTempPhotoExecute_test_001
 * @tc.desc: 入参为空时, 会在DeleteTempPhotoExecute中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoExecute_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = DeleteTemporaryPhotosProcessor();
    std::vector<std::string> fileIds;
    ret = processor.DeleteTempPhotoExecute(fileIds);
    EXPECT_EQ(ret, STOP_FLAG);

    int32_t count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, INSERT_1_DATA);
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_002 end");
}

/**
 * @tc.name: DeleteTempPhotoExecute_test_003
 * @tc.desc: 入参为空时, 会在DeleteTempPhotoExecute中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoExecute_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_003 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    // 插入一条24小时以内的数据
    std::string dateAdded = to_string(current - TIME_22_HOURS);
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(dateAdded, INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    int32_t count = -1;
    auto processor = DeleteTemporaryPhotosProcessor();
    auto resultSet = processor.QueryAllTempPhoto(count, false);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(count, QUERY_1_DATA);
    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    int32_t fileIdQueryFirst = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    std::vector<std::string> fileIds = { std::to_string(fileIdQueryFirst) };

    ret = processor.DeleteTempPhotoExecute(fileIds);
    EXPECT_EQ(ret, E_OK);

    count = -1;
    ret = QueryTempPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_0_DATA);
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_003 end");
}
} // namespace Media
} // namespace OHOS
