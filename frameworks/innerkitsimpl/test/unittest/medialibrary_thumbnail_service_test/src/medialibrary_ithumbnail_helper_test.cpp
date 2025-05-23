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

#include "medialibrary_ithumbnail_helper_test.h"

#include <thread>

#include "foundation/ability/form_fwk/test/mock/include/mock_single_kv_store.h"
#include "highlight_column.h"
#include "kvstore.h"
#include "vision_db_sqls.h"

#define private public
#include "thumbnail_service.h"
#include "ithumbnail_helper.h"
#include "thumbnail_generate_helper.h"
#undef private
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"

 
using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

void MediaLibraryIthumbnailHelperTest::SetUpTestCase(void) {}

void MediaLibraryIthumbnailHelperTest::TearDownTestCase(void) {}
    
void MediaLibraryIthumbnailHelperTest::SetUp() {}
    
void MediaLibraryIthumbnailHelperTest::TearDown(void) {}

HWTEST_F(MediaLibraryIthumbnailHelperTest, TrySaveCurrentPixelMap_test_001, TestSize.Level0)
{
    ThumbnailData data;
    data.id = "test_id";
    data.path = "test_path";
    data.dateModified = "test_date";
    ThumbnailType type = ThumbnailType::LCD;
    ThumbnailWait thumbnailWait(true);
    auto res = thumbnailWait.TrySaveCurrentPixelMap(data, type);
    EXPECT_EQ(res, false);
    type = ThumbnailType::THUMB;
    res = thumbnailWait.TrySaveCurrentPixelMap(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, TrySaveCurrentPicture_test_001, TestSize.Level0)
{
    ThumbnailData data;
    data.id = "123";
    data.path = "/path/to/image";
    data.dateModified = "2025-04-14";
    bool isSourceEx = false;
    string tempOutputPath = "/path/to/temp";
    ThumbnailWait thumbnailWait(true);
    auto res = thumbnailWait.TrySaveCurrentPicture(data, isSourceEx, tempOutputPath);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, UpdateSavedFileMap_test_001, TestSize.Level0)
{
    ThumbnailSyncStatus syncStatus;
    string id = "testId";
    ThumbnailType type = ThumbnailType::THUMB;
    string dateModified = "2025-04-14";
    bool isSourceEx = false;
    syncStatus.latestSavedFileMap_[id + "THM"] = "2025-04-15";
    auto res = syncStatus.UpdateSavedFileMap(id, type, dateModified);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, TrySavePixelMap_test_001, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::TrySavePixelMap(data, type);
    EXPECT_EQ(res, false);
    data.needCheckWaitStatus = true;
    res = IThumbnailHelper::TrySavePixelMap(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, TrySavePicture_test_001, TestSize.Level0)
{
    ThumbnailData data;
    bool isSourceEx = false;
    const string tempOutputPath = "/path/to/temp";
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::TrySavePicture(data, isSourceEx, tempOutputPath);
    EXPECT_EQ(res, false);
    data.needCheckWaitStatus = true;
    res = IThumbnailHelper::TrySavePicture(data, isSourceEx, tempOutputPath);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, CacheSuccessState_test_001, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.id = "";
    opts.row = "";
    auto res = IThumbnailHelper::CacheSuccessState(opts, data);
    EXPECT_EQ(res, false);
    data.id = "validId";
    opts.row = "validRow";
    res = IThumbnailHelper::CacheSuccessState(opts, data);
    EXPECT_EQ(res, false);
    opts.store = ThumbnailService::GetInstance()->rdbStorePtr_;
    res = IThumbnailHelper::CacheSuccessState(opts, data);
    EXPECT_EQ(res, false);
}
} // namespace Media
} // namespace OHOS