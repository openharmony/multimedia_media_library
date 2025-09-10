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
#include "medialibrary_mocksinglekvstore.h"
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
#include "thumbnail_source_loading.h"

 
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

const int32_t TEST_PIXELMAP_WIDTH_AND_HEIGHT = 100;
const string TEST_IMAGE_PATH = "/storage/cloud/files/Photo/1/CreateImageThumbnailTest_001.jpg";

static std::shared_ptr<PixelMap> CreateTestPixelMap(PixelFormat format, bool useDMA)
{
    InitializationOptions opts;
    opts.size.width = TEST_PIXELMAP_WIDTH_AND_HEIGHT;
    opts.size.height = TEST_PIXELMAP_WIDTH_AND_HEIGHT;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDMA;
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    return pixelMap;
}

static std::shared_ptr<Picture> CreateTestPicture(std::shared_ptr<PixelMap> pixelMap,
    std::shared_ptr<PixelMap> gainMap)
{
    if (pixelMap == nullptr) {
        return nullptr;
    }

    auto sourcePtr = Picture::Create(pixelMap);
    std::shared_ptr<Picture> picture = std::move(sourcePtr);
    if (gainMap == nullptr) {
        return picture;
    }

    Size gainMapSize = {gainMap->GetWidth(), gainMap->GetHeight()};
    auto auxiliaryPicturePtr = AuxiliaryPicture::Create(gainMap, AuxiliaryPictureType::GAINMAP, gainMapSize);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = std::move(auxiliaryPicturePtr);
    CHECK_AND_RETURN_RET_LOG(auxiliaryPicture != nullptr, nullptr, "Create auxiliaryPicture failed");
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    return picture;
}

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

HWTEST_F(MediaLibraryIthumbnailHelperTest, StorePicture_test_001, TestSize.Level0)
{
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<PixelMap> gainMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<Picture> picture = CreateTestPicture(pixelMap, gainMap);
    bool ret = IThumbnailHelper::StorePicture(data, picture, false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, StorePictureLowQuality_test_001, TestSize.Level0)
{
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<PixelMap> gainMap = CreateTestPixelMap(PixelFormat::RGBA_8888, false);
    std::shared_ptr<Picture> picture = CreateTestPicture(pixelMap, gainMap);
    bool ret = IThumbnailHelper::StorePictureLowQuality(data, picture, false, LCD_UPLOAD_LIMIT_SIZE);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, GetLcdDesiredSize_test_001, TestSize.Level0)
{
    ThumbnailData data;
    data.lcdDesiredSize.height = 1080;
    data.lcdDesiredSize.width = 1920;
    data.orientation = 90;
    Size ret = IThumbnailHelper::GetLcdDesiredSize(data, true);
    bool res = ret.width == data.lcdDesiredSize.width && ret.height == data.lcdDesiredSize.height;
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryIthumbnailHelperTest, DoCreatetLcdAndThumbnail_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DoCreatetLcdAndThumbnail_test_001");
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.id = "1234";
    data.path = TEST_IMAGE_PATH;
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    
    IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcd,
        opts, data, ThumbnailTaskType::FOREGROUND, ThumbnailTaskPriority::HIGH);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bool ret = IThumbnailHelper::DoCreateLcdAndThumbnail(opts, data);
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("DoCreatetLcdAndThumbnail_test_001 end");
}

} // namespace Media
} // namespace OHOS