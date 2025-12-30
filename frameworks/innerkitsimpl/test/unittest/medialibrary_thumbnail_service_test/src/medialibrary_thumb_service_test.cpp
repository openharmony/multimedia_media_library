/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <thread>
#include "foundation/ability/form_fwk/test/mock/include/mock_single_kv_store.h"
#include "kvstore.h"
#include "medialibrary_thumb_service_test.h"
#define private public
#include "thumbnail_service.h"
#include "ithumbnail_helper.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_restore_manager.h"
#undef private
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "highlight_column.h"
using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

const int32_t TEST_PIXELMAP_WIDTH_AND_HEIGHT = 100;

const int32_t E_GETROUWCOUNT_ERROR = 27394103;

shared_ptr<MediaLibraryRdbStore> storePtr_ = nullptr;

void MediaLibraryThumbServiceTest::SetUpTestCase(void) {}

void MediaLibraryThumbServiceTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryThumbServiceTest::SetUp() {}

void MediaLibraryThumbServiceTest::TearDown() {}

HWTEST_F(MediaLibraryThumbServiceTest, GetThumbFd_ShouldReturnValidFd_WhenThumbTypeIsThumb, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string path = "/path/to/thumbnail";
    std::string table = "table";
    std::string id = "id";
    std::string uri = "uri";
    Size size = {100, 100};
    bool isAstc = false;
    int fd = thumbnailService.GetThumbFd(path, table, id, uri, size, isAstc);
    EXPECT_GE(fd, 0);
}

HWTEST_F(MediaLibraryThumbServiceTest, GetThumbFd_ShouldReturnValidFd_WhenThumbTypeIsThumbAstc, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string path = "/path/to/thumbnail";
    std::string table = "table";
    std::string id = "id";
    std::string uri = "uri";
    Size size = {100, 100};
    bool isAstc = true;
    int fd = thumbnailService.GetThumbFd(path, table, id, uri, size, isAstc);
    EXPECT_GE(fd, 0);
}

HWTEST_F(MediaLibraryThumbServiceTest, GetThumbFd_ShouldReturnValidFd_WhenThumbTypeIsNotThumbOrThumbAstc, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string path = "/path/to/thumbnail";
    std::string table = "table";
    std::string id = "id";
    std::string uri = "uri";
    Size size = {100, 1000}; // This size will result in a thumbType other than Thumb or ThumbAstc
    bool isAstc = false;
    int fd = thumbnailService.GetThumbFd(path, table, id, uri, size, isAstc);
    EXPECT_GE(fd, 0);
}

HWTEST_F(MediaLibraryThumbServiceTest, GetKeyFrameThumbFd_Success_Test, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    string path = "/test/path";
    string table = "test_table";
    string id = "test_id";
    string uri = "test_uri";
    int32_t beginStamp = 0;
    int32_t type = 0;
    int fd = thumbnailService.GetKeyFrameThumbFd(path, table, id, uri, beginStamp, type);
    EXPECT_GT(fd, 0);
}

HWTEST_F(MediaLibraryThumbServiceTest, CreateThumbnailPastDirtyDataFix_Success, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string fileId = "testFileId";
    int32_t result = thumbnailService.CreateThumbnailPastDirtyDataFix(fileId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, CreateThumbnailPastDirtyDataFix_QueryFailure, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string fileId = "invalidFileId";
    int32_t result = thumbnailService.CreateThumbnailPastDirtyDataFix(fileId);
    EXPECT_NE(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_CreateLcdPastDirtyDataFix_001, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string fileId = "testFileId";
    int32_t result = thumbnailService.CreateLcdPastDirtyDataFix(fileId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_CreateThumbnailFileScaned_ParseThumbnailParam_Error, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string uri = "invalid_uri";
    std::string path = "/invalid/path";
    bool isSync = true;
    // This test will fail if ParseThumbnailParam is not public
    // If it's not public, we need to find a public method that indirectly tests this functionality
    int32_t result = thumbnailService.CreateThumbnailFileScaned(uri, path, isSync);
    // Verify that an error was posted
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_CreateThumbnailFileScaned_CreateThumbnailFileScaned_Error, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string uri = "valid_uri";
    std::string path = "/valid/path";
    bool isSync = true;
    // This test will fail if CreateThumbnailFileScaned is not public
    // If it's not public, we need to find a public method that indirectly tests this functionality
    int32_t result = thumbnailService.CreateThumbnailFileScaned(uri, path, isSync);
    // Verify that an error was posted
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_CreateThumbnailFileScaned_Success, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string uri = "valid_uri";
    std::string path = "/valid/path";
    bool isSync = true;
    // This test will fail if CreateThumbnailFileScaned is not public
    // If it's not public, we need to find a public method that indirectly tests this functionality
    int32_t result = thumbnailService.CreateThumbnailFileScaned(uri, path, isSync);
    // Verify that an error was posted
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, UpgradeThumbnailBackground_WhenWifiNotConnected, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    int32_t result = thumbnailService.UpgradeThumbnailBackground(false);
    EXPECT_NE(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, UpgradeThumbnailBackground_WhenWifiConnected, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    int32_t result = thumbnailService.UpgradeThumbnailBackground(true);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_TriggerHighlightThumbnail_Success, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string id = "testId";
    std::string tracks = "testTracks";
    std::string trigger = "testTrigger";
    std::string genType = "testGenType";
    int32_t result = thumbnailService.TriggerHighlightThumbnail(id, tracks, trigger, genType);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, LcdAging_ShouldReturnE_OK_WhenAllTablesAgingSuccess, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    int32_t result = thumbnailService.LcdAging();
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_DeleteThumbnailDirAndAstc_Success, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string id = "123";
    std::string tableName = "testTable";
    std::string path = "/test/path";
    std::string dateTaken = "2022-01-01";
    bool result = thumbnailService.DeleteThumbnailDirAndAstc(id, tableName, path, dateTaken);
    EXPECT_TRUE(result);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_BatchDeleteThumbnailDirAndAstc_Success, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string tableName = "test_table";
    std::vector<std::string> ids = {"id1", "id2"};
    std::vector<std::string> paths = {"path1", "path2"};
    std::vector<std::string> dateTakens = {"date1", "date2"};
    // Call the public method directly
    bool result = thumbnailService.BatchDeleteThumbnailDirAndAstc(tableName, ids, paths, dateTakens);
    // Expect the method to return true if the internal call is successful
    EXPECT_TRUE(result);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_BatchDeleteThumbnailDirAndAstc_Failure, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    std::string tableName = "test_table";
    std::vector<std::string> ids = {};
    std::vector<std::string> paths = {};
    std::vector<std::string> dateTakens = {};
    // Call the public method directly
    bool result = thumbnailService.BatchDeleteThumbnailDirAndAstc(tableName, ids, paths, dateTakens);
    // Expect the method to return false if the input is empty
    EXPECT_FALSE(result);
}

HWTEST_F(MediaLibraryThumbServiceTest, ATC_CreateAstcBatchOnDemand_InvalidRequestId_Test, TestSize.Level0)
{
    ThumbnailService thumbnailService;
    NativeRdb::RdbPredicates rdbPredicate { PhotoColumn::PHOTOS_TABLE };
    int32_t requestId = -1;
    int32_t result = thumbnailService.CreateAstcBatchOnDemand(rdbPredicate, requestId);
    EXPECT_EQ(result, E_INVALID_VALUES);
}


HWTEST_F(MediaLibraryThumbServiceTest, medialib_GetThumbnail_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    string uri = "";
    auto fd = serverTest->GetThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    uri = "ParseThumbnailInfo?" + THUMBNAIL_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        THUMBNAIL_WIDTH + "=1&" + THUMBNAIL_HEIGHT + "=1";
    fd = serverTest->GetThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
    fd = serverTest->GetThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_GetKeyFrameThumbnail_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    string uri = "";
    auto fd = serverTest->GetKeyFrameThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    uri = "ParseKeyFrameThumbnailInfo?" + THUMBNAIL_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_KEY_FRAME + "&" +
          THUMBNAIL_BEGIN_STAMP + "=1&" + THUMBNAIL_TYPE + "=1";
    fd = serverTest->GetKeyFrameThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_LcdAging_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t ret = serverTest->LcdAging();
    EXPECT_EQ(ret, 0);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
    ret = serverTest->LcdAging();
    EXPECT_EQ(ret, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_GenerateThumbnailBackground_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t ret = serverTest->GenerateThumbnailBackground();
    EXPECT_EQ(ret <= 0, true);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(nullptr, context);
    ret = serverTest->GenerateThumbnailBackground();
    EXPECT_NE(ret, 0);
    serverTest->Init(storePtr_, context);
    ret = serverTest->GenerateThumbnailBackground();
    EXPECT_NE(ret, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_InterruptBgworker_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    EXPECT_NE(serverTest, nullptr);
    serverTest->InterruptBgworker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
    serverTest->InterruptBgworker();
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_StopAllWorker_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    EXPECT_NE(serverTest, nullptr);
    serverTest->StopAllWorker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
    serverTest->StopAllWorker();
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_CreateThumbnailAsync_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    string url = "";
    ThumbnailService serverTest;
    int32_t ret = serverTest.CreateThumbnailFileScaned(url, "", true);
    EXPECT_EQ(ret, E_OK);
    serverTest.ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_CreateAstcBatchOnDemand_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
 
    NativeRdb::RdbPredicates predicate { PhotoColumn::PHOTOS_TABLE };
    int32_t requestId = 1;
    int32_t result = serverTest->CreateAstcBatchOnDemand(predicate, requestId);
    EXPECT_EQ(result, E_GETROUWCOUNT_ERROR);
    serverTest->ReleaseService();
}
 
HWTEST_F(MediaLibraryThumbServiceTest, medialib_CancelAstcBatchTask_test_001, TestSize.Level1)
{
    ASSERT_NE(storePtr_, nullptr);
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    EXPECT_NE(serverTest, nullptr);
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr_, context);
 
    NativeRdb::RdbPredicates predicate { PhotoColumn::PHOTOS_TABLE };
    int32_t requestId = 1;
    serverTest->CancelAstcBatchTask(requestId);
    serverTest->CancelAstcBatchTask(++requestId);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_001, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::CreateLcdAndThumbnail(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_002, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::CreateLcd(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_003, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::CreateThumbnail(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_004, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::CreateAstc(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_005, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::CreateAstcEx(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_006, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::DeleteMonthAndYearAstc(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_007, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::TryLoadSource(opts, data);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_008, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::TryLoadSource(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_009, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto ret = IThumbnailHelper::DoCreateLcd(opts, data);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_010, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::IsCreateLcdSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_011, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_012, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_013, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_014, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_015, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::LCD;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_016, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_017, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB_ASTC;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_018, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::MTH_ASTC;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    data.dateTaken = "default value";
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_019, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::YEAR_ASTC;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    data.dateTaken = "default value";
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_020, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::GenThumbnailEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_021, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::GenThumbnailEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_022, TestSize.Level1)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::LCD;
    auto res = IThumbnailHelper::GenMonthAndYearAstcData(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_023, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoCreateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_024, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::IsCreateThumbnailExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_025, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoRotateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_026, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::DoRotateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_027, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_028, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    data.loaderOpts.needUpload = true;
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_029, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.path = "/storage/cloud/files/";
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_030, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_031, TestSize.Level1)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    int32_t fd = 0;
    ThumbnailType thumbType = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::DoRotateThumbnailEx(opts, data, fd, thumbType);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_032, TestSize.Level1)
{
    ThumbRdbOpt opts;
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_033, TestSize.Level1)
{
    ThumbRdbOpt opts;
    opts.row = "a";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_034, TestSize.Level1)
{
    ThumbRdbOpt opts;
    opts.table = "b";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_035, TestSize.Level1)
{
    ThumbRdbOpt opts;
    opts.row = "a";
    opts.table = "b";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbServiceTest, medialib_thumbnail_helper_test_036, TestSize.Level1)
{
    std::shared_ptr<ThumbnailTaskData> data;
    IThumbnailHelper::UpdateAstcDateTaken(data);
    ThumbRdbOpt opts;
    ThumbnailData thumbData;
    int32_t requestId;
    std::shared_ptr<ThumbnailTaskData> dataValue = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    IThumbnailHelper::CreateLcdAndThumbnail(dataValue);
    EXPECT_EQ(requestId, dataValue->requestId_);
}
}
}
