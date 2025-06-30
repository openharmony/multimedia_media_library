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
static constexpr int64_t TIME_22_HOURS = 22 * 60 * 60;
static constexpr int64_t TIME_26_HOURS = 26 * 60 * 60;

static constexpr int32_t INSERT_1_DATA = 1;

static constexpr int32_t QUERY_0_DATA = 0;
static constexpr int32_t QUERY_1_DATA = 1;

const std::string MEDIA_CACHE_FILE = "/storage/cloud/files/.cache/test.jpg";

int32_t InsertInvalidDeletedAlbum(const std::string &albumName, int32_t dirty, const std::string &cloudId,
    int64_t &outRowId, int32_t count)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    NativeRdb::ValuesBucket value;
    value.Put(PhotoAlbumColumns::ALBUM_NAME, albumName);
    value.Put(PhotoAlbumColumns::ALBUM_DIRTY, dirty);
    if (!cloudId.empty()) {
        value.Put(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);
    }
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoAlbumColumns::TABLE, insertValues);
    return ret;
}

void modifyFileTime(const std::string& filePath, int64_t timeValue)
{
    time_t currentTime = time(nullptr);
    if (currentTime == -1) {
        return;
    }
    struct utimbuf newTime;
    newTime.modtime = currentTime - timeValue;
    CHECK_AND_RETURN_INFO_LOG(utime(filePath.c_str(), &newTime) != E_OK, "modifyFileTime success");
}

int32_t QueryDeletedAlbumCount(int32_t &count, const std::string &albumName)
{
    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    NativeRdb::AbsRdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }
    auto resultSet = rdbStore->Query(predicates, columns);
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
 * @tc.name: CacheAging_test_001
 * @tc.desc: /storage/cloud/files/.cache/ 路径不存在时, CacheAging不会执行
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_001 start");
    auto processor = TrashAgingOperationProcessor();
    processor.CacheAging();
    EXPECT_EQ(MediaFileUtils::IsDirectory(MEDIA_CACHE_DIR), false);
    MEDIA_INFO_LOG("CacheAging_test_001 end");
}

/**
 * @tc.name: CacheAging_test_002
 * @tc.desc: 停止后台任务时, 会在CacheAging中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_002 start");
    EXPECT_EQ(MediaFileUtils::CreateDirectory(MEDIA_CACHE_DIR), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(MEDIA_CACHE_FILE), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    auto processor = TrashAgingOperationProcessor();
    auto ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);

    processor.CacheAging();
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    MEDIA_INFO_LOG("CacheAging_test_002 end");
}

/**
 * @tc.name: CacheAging_test_003
 * @tc.desc: 24小时以内的文件不会被删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_003 start");
    EXPECT_EQ(MediaFileUtils::CreateDirectory(MEDIA_CACHE_DIR), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(MEDIA_CACHE_FILE), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    modifyFileTime(MEDIA_CACHE_FILE, TIME_22_HOURS);

    auto processor = TrashAgingOperationProcessor();
    processor.CacheAging();

    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    MEDIA_INFO_LOG("CacheAging_test_003 end");
}

/**
 * @tc.name: CacheAging_test_004
 * @tc.desc: 24小时之前的文件会被删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, CacheAging_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("CacheAging_test_004 start");
    EXPECT_EQ(MediaFileUtils::CreateDirectory(MEDIA_CACHE_DIR), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(MEDIA_CACHE_FILE), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), true);
    modifyFileTime(MEDIA_CACHE_FILE, TIME_26_HOURS);

    auto processor = TrashAgingOperationProcessor();
    processor.CacheAging();

    EXPECT_EQ(MediaFileUtils::IsFileExists(MEDIA_CACHE_FILE), false);
    MEDIA_INFO_LOG("CacheAging_test_004 end");
}

/**
 * @tc.name: ClearInvalidDeletedAlbum_test_001
 * @tc.desc: 仅 dirty = 4 不会被删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearInvalidDeletedAlbum_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_001 start");
    int64_t outRow = -1;
    std::string albumName = "ClearInvalidDeletedAlbum_test_001";
    int32_t dirty = static_cast<int32_t>(DirtyTypes::TYPE_DELETED);
    std::string cloudId = "test123456";
    int32_t ret = InsertInvalidDeletedAlbum(albumName, dirty, cloudId, outRow, INSERT_1_DATA);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = TrashAgingOperationProcessor();
    processor.ClearInvalidDeletedAlbum();
    
    int32_t count = -1;
    ret = QueryDeletedAlbumCount(count, albumName);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_1_DATA);
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_001 end");
}

/**
 * @tc.name: ClearInvalidDeletedAlbum_test_002
 * @tc.desc: 仅 cloud_id = null 不会被删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearInvalidDeletedAlbum_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_002 start");
    int64_t outRow = -1;
    std::string albumName = "ClearInvalidDeletedAlbum_test_002";
    int32_t dirty = static_cast<int32_t>(DirtyTypes::TYPE_NEW);
    std::string cloudId = "test123456";
    int32_t ret = InsertInvalidDeletedAlbum(albumName, dirty, cloudId, outRow, INSERT_1_DATA);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = TrashAgingOperationProcessor();
    processor.ClearInvalidDeletedAlbum();

    int32_t count = -1;
    ret = QueryDeletedAlbumCount(count, albumName);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_1_DATA);
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_002 end");
}

/**
 * @tc.name: ClearInvalidDeletedAlbum_test_003
 * @tc.desc: dirty = 4 && cloud_id = null 会被删除
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearInvalidDeletedAlbum_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_003 start");
    int64_t outRow = -1;
    std::string albumName = "ClearInvalidDeletedAlbum_test_003";
    int32_t dirty = static_cast<int32_t>(DirtyTypes::TYPE_DELETED);
    std::string cloudId = "";
    int32_t ret = InsertInvalidDeletedAlbum(albumName, dirty, cloudId, outRow, INSERT_1_DATA);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = TrashAgingOperationProcessor();
    processor.ClearInvalidDeletedAlbum();

    int32_t count = -1;
    ret = QueryDeletedAlbumCount(count, albumName);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_0_DATA);
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_003 end");
}

/**
 * @tc.name: ClearInvalidDeletedAlbum_test_004
 * @tc.desc: 停止后台任务时, 会在ClearInvalidDeletedAlbum中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearInvalidDeletedAlbum_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_004 start");
    int64_t outRow = -1;
    std::string albumName = "ClearInvalidDeletedAlbum_test_004";
    int32_t dirty = static_cast<int32_t>(DirtyTypes::TYPE_DELETED);
    std::string cloudId = "";
    int32_t ret = InsertInvalidDeletedAlbum(albumName, dirty, cloudId, outRow, INSERT_1_DATA);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = TrashAgingOperationProcessor();
    ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);
    processor.ClearInvalidDeletedAlbum();

    int32_t count = -1;
    ret = QueryDeletedAlbumCount(count, albumName);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_1_DATA);
    MEDIA_INFO_LOG("ClearInvalidDeletedAlbum_test_004 end");
}
} // namespace Media
} // namespace OHOS
