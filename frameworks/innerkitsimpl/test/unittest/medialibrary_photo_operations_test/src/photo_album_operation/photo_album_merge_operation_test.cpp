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
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int32_t OLD_ALBUM_ID = 1;
static constexpr int32_t NEW_ALBUM_ID = 2;

void PhotoAlbumMergeOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAlbumMergeOperationTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
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
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}
}  // namespace OHOS::Media