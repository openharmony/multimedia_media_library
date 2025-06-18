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

int32_t InsertTempAsset(std::string dateAdded, int32_t count, int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    value.Put(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    fileId = static_cast<int32_t>(outRowId);
    return E_OK;
}

int32_t QueryTemp(int32_t fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
 
    vector<string> columns = { PhotoColumn::PHOTO_IS_TEMP };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file is_temp");
        return E_ERR;
    }
    int32_t isTemp = GetInt32Val(PhotoColumn::PHOTO_IS_TEMP, resultSet);
    resultSet->Close();
    return isTemp;
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteAllTempPhotoOverOneDay_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_001 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 22 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 1, fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteAllTempPhotoOverOneDay();
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, 1);
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteAllTempPhotoOverOneDay_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 26 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 1, fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteAllTempPhotoOverOneDay();
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, E_ERR);
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_002 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteAllTempPhotoOverOneDay_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_003 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 26 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 210, fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteAllTempPhotoOverOneDay();
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, E_ERR);
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay_test_003 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoMoreThanHundred_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_001 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 22 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 1, fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteTempPhotoMoreThanHundred();
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, 1);
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoMoreThanHundred_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 22 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 210, fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = DeleteTemporaryPhotosProcessor();
    processor.DeleteTempPhotoMoreThanHundred();
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, 1);
    isTemp = QueryTemp(fileId - 200);
    EXPECT_EQ(isTemp, E_ERR);
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred_test_002 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoExecute_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_001 start");
    std::vector<std::string> fileIds;
    auto processor = DeleteTemporaryPhotosProcessor();
    int32_t ret = processor.DeleteTempPhotoExecute(fileIds);
    EXPECT_EQ(ret, STOP_FLAG);
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, DeleteTempPhotoExecute_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_002 start");
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::string dateAdded = to_string(current - 22 * 60 * 60 * 1000);
    int32_t fileId = -1;
    int32_t ret = InsertTempAsset(dateAdded, 1, fileId);
    EXPECT_EQ(ret, E_OK);
    std::vector<std::string> fileIds;
    fileIds.push_back(to_string(fileId));
    auto processor = DeleteTemporaryPhotosProcessor();
    ret = processor.DeleteTempPhotoExecute(fileIds);
    EXPECT_EQ(ret, E_OK);
    int32_t isTemp = QueryTemp(fileId);
    EXPECT_EQ(isTemp, E_ERR);
    MEDIA_INFO_LOG("DeleteTempPhotoExecute_test_002 end");
}

} // namespace Media
} // namespace OHOS
