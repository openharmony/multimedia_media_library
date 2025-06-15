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

#include "utime.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "media_column.h"

#define private public
#include "trash_aging_operation_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static const int32_t BATCH_INSERT_COUNT = 100;
static const int32_t HOURS_26 = 26 * 60 * 60;    // 26 hours

const std::string MEDIA_CACHE_FILE = "/storage/cloud/files/.cache/test.jpg";
int32_t InsertInvalidDeletedAlbum(int32_t dirty, int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket value;
    value.Put(PhotoAlbumColumns::ALBUM_DIRTY, dirty);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < BATCH_INSERT_COUNT; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoAlbumColumns::TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    fileId = static_cast<int32_t>(outRowId);
    return ret;
}

void modifyFileTime(const std::string& filePath)
{
    time_t currentTime = time(nullptr);
    if (currentTime == -1) {
        return;
    }
    struct utimbuf newTime;
    newTime.modtime = currentTime - HOURS_26;
    CHECK_AND_RETURN_INFO_LOG(utime(filePath.c_str(), &newTime) != E_OK, "modifyFileTime success");
}

int32_t QueryFileId(int32_t fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
 
    vector<string> columns = { PhotoColumn::MEDIA_ID };
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
        MEDIA_ERR_LOG("Can not get fileId");
        return E_ERR;
    }
    resultSet->Close();
    return E_OK;
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_001 start");
    auto processor = TrashAgingOperationProcessor();
    processor.CacheAging();
    EXPECT_EQ(MediaFileUtils::IsDirectory(MEDIA_CACHE_DIR), false);
    MEDIA_INFO_LOG("cache file dir not exist");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_002 start");
    EXPECT_EQ(MediaFileUtils::CreateDirectory(MEDIA_CACHE_DIR), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(MEDIA_CACHE_FILE), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    modifyFileTime(MEDIA_CACHE_FILE);
    auto processor = TrashAgingOperationProcessor();
    processor.CacheAging();
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), false);
    MEDIA_INFO_LOG("cache file clear");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearInvalidDeletedAlbum_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_002 start");
    auto processor = TrashAgingOperationProcessor();
    int32_t fileId = -1;
    int32_t dirty = 4;
    int32_t ret = InsertInvalidDeletedAlbum(dirty, fileId);
    EXPECT_EQ(ret, E_OK);
    processor.ClearInvalidDeletedAlbum();
    ret = QueryFileId(fileId);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("CacheAging_test_002 end");
}


} // namespace Media
} // namespace OHOS
