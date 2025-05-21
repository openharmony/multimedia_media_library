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

#include "medialibrary_thumbnail_generation_post_process_test.h"

#include "thumbnail_generation_post_process.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "vision_db_sqls.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {

shared_ptr<MediaLibraryRdbStore> store = nullptr;
string dataId;

void MediaLibraryThumbnailSourceLoadingTest::SetUpTestCase()
{
    const string dbPath = "/data/test/medialibrary_thumbnail_generation_post_process_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    EXPECT_EQ(ret, E_OK);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(storePtr, nullptr);

    ret = storePtr->ExecuteSql(PhotoColumn::CREATE_PHOTO_TABLE);
    ASSERT_EQ(ret, NativeRdb::E_OK);

    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, 0);
    ret = store->insert(dataId, PhotoColumn::PHOTOS_TABLE, values);
    ASSERT_EQ(ret, NativeRdb::E_OK);
}

void MediaLibraryThumbnailSourceLoadingTest::TearDownTestCase()
{
    string dropSql = "DROP TABLE " + PhotoColumn::CREATE_PHOTO_TABLE + ";";
    ret = storePtr->ExecuteSql(dropSql);
    MEDIA_INFO_LOG("Drop photos table success: ", ret == NativeRdb::E_OK);
    MediaLibraryUnitTestUtils::StopUnistore();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaLibraryThumbnailSourceLoadingTest::SetUp() {}

void MediaLibraryThumbnailSourceLoadingTest::TearDown(void) {}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, PostProcess_test_001, TestSize.Level0)
{
    ValuesBucket values;
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, ThumbnailReady::GENERATE_THUMB_LATER);
    ThumbnailData data;
    data.rdbUpdateCache = values;
    data.id = dataId;
    ThumbRdbOpt opts;
    opts.store = store;
    opts.table = PhotoColumn::PHOTOS_TABLE;

    int ret = ThumbnailGenerationPostProcess::PostProcess(data, opts);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryThumbnailImageFrameworkTest, PostProcess_test_002, TestSize.Level0)
{
    ValuesBucket values;
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, ThumbnailReady::GENERATE_THUMB_RETRY);
    ThumbnailData data;
    data.rdbUpdateCache = values;
    data.id = dataId;
    ThumbRdbOpt opts;
    opts.store = store;
    opts.table = PhotoColumn::PHOTOS_TABLE;

    int ret = ThumbnailGenerationPostProcess::PostProcess(data, opts);
    EXPECT_EQ(ret, E_OK);
}

} // namespace Media
} // namespace OHOS