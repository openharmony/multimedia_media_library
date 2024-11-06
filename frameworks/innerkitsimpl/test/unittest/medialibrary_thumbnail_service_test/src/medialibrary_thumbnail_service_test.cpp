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

#include "foundation/ability/form_fwk/test/mock/include/mock_single_kv_store.h"
#include "kvstore.h"
#include "medialibrary_thumbnail_service_test.h"
#define private public
#include "thumbnail_service.h"
#include "ithumbnail_helper.h"
#include "thumbnail_generate_helper.h"
#undef private
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
class ConfigTestOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const string CREATE_TABLE_TEST;
};

const string ConfigTestOpenCall::CREATE_TABLE_TEST = string("CREATE TABLE IF NOT EXISTS test ") +
    "(file_id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL, media_type INTEGER," +
    " date_added TEXT, display_name TEXT, thumbnail_ready TEXT, position TEXT)";

const int32_t E_GETROUWCOUNT_ERROR = 27394103;

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<MediaLibraryRdbStore> storePtr = nullptr;

void MediaLibraryThumbnailServiceTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_thumbnail_service_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    EXPECT_EQ(ret, E_OK);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(storePtr, nullptr);
}

void MediaLibraryThumbnailServiceTest::TearDownTestCase(void)
{
    MediaLibraryUnitTestUtils::StopUnistore();
}

// SetUp:Execute before each test case
void MediaLibraryThumbnailServiceTest::SetUp() {}

void MediaLibraryThumbnailServiceTest::TearDown(void) {}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_GetThumbnail_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
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
#ifdef DISTRIBUTED
    serverTest->Init(storePtr, kvStorePtr, context);
#else
    serverTest->Init(storePtr, context);
#endif
    fd = serverTest->GetThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_GetKeyFrameThumbnail_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_LcdAging_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t ret = serverTest->LcdAging();
    EXPECT_EQ(ret, 0);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
#ifdef DISTRIBUTED
    serverTest->Init(storePtr, kvStorePtr, context);
#else
    serverTest->Init(storePtr, context);
#endif
    ret = serverTest->LcdAging();
    EXPECT_EQ(ret, 0);
    serverTest->ReleaseService();
}

#ifdef DISTRIBUTED
HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_LcdDistributeAging_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    string udid = "";
    int32_t ret = serverTest->LcdDistributeAging(udid);
    EXPECT_EQ(ret, -1);
    udid = "/storage/cloud/files/";
    ret = serverTest->LcdDistributeAging(udid);
    EXPECT_EQ(ret, -1);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr, kvStorePtr, context);
    ret = serverTest->LcdDistributeAging(udid);
    EXPECT_EQ(ret, 0);
    serverTest->ReleaseService();
}
#endif

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_GenerateThumbnailBackground_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t ret = serverTest->GenerateThumbnailBackground();
    EXPECT_EQ(ret, -1);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
#ifdef DISTRIBUTED
    serverTest->Init(nullptr, kvStorePtr, context);
#else
    serverTest->Init(nullptr, context);
#endif
    ret = serverTest->GenerateThumbnailBackground();
    EXPECT_EQ(ret, -1);
#ifdef DISTRIBUTED
    serverTest->Init(storePtr, kvStorePtr, context);
#else
    serverTest->Init(storePtr, context);
#endif
    ret = serverTest->GenerateThumbnailBackground();
    EXPECT_EQ(ret, E_GETROUWCOUNT_ERROR);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_InterruptBgworker_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    serverTest->InterruptBgworker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
#ifdef DISTRIBUTED
    serverTest->Init(storePtr, kvStorePtr, context);
#else
    serverTest->Init(storePtr, context);
#endif
    serverTest->InterruptBgworker();
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_StopAllWorker_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    serverTest->StopAllWorker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
#ifdef DISTRIBUTED
    serverTest->Init(storePtr, kvStorePtr, context);
#else
    serverTest->Init(storePtr, context);
#endif
    serverTest->StopAllWorker();
    serverTest->ReleaseService();
}

#ifdef DISTRIBUTED
HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_InvalidateDistributeThumbnail_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string udid = "";
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t ret = serverTest->InvalidateDistributeThumbnail(udid);
    EXPECT_EQ(ret, -1);
    udid = "/storage/cloud/files/";
    ret = serverTest->InvalidateDistributeThumbnail(udid);
    EXPECT_EQ(ret, -1);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr, kvStorePtr, context);
    ret = serverTest->InvalidateDistributeThumbnail(udid);
    EXPECT_EQ(ret, 0);
    serverTest->ReleaseService();
}
#endif

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_CreateThumbnailAsync_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string url = "";
    ThumbnailService serverTest;
    int32_t ret = serverTest.CreateThumbnailFileScaned(url, "", true);
    EXPECT_EQ(ret, E_OK);
    serverTest.ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_CreateAstcBatchOnDemand_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr, context);

    NativeRdb::RdbPredicates predicate { PhotoColumn::PHOTOS_TABLE };
    int32_t requestId = 1;
    int32_t result = serverTest->CreateAstcBatchOnDemand(predicate, requestId);
    EXPECT_EQ(result, E_GETROUWCOUNT_ERROR);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_CancelAstcBatchTask_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr, context);

    NativeRdb::RdbPredicates predicate { PhotoColumn::PHOTOS_TABLE };
    int32_t requestId = 1;
    serverTest->CancelAstcBatchTask(requestId);
    serverTest->CancelAstcBatchTask(++requestId);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_001, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_002, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_003, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_004, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_005, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_006, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_007, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::TryLoadSource(opts, data);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_008, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::TryLoadSource(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_009, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    IThumbnailHelper::DoCreateLcd(opts, data);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_010, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::IsCreateLcdSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_011, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_012, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_013, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.sourceEx = make_shared<PixelMap>();
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_014, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_015, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::LCD;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_016, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_017, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB_ASTC;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_018, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::MTH_ASTC;
    data.source = make_shared<PixelMap>();
    data.dateTaken = "default value";
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_019, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::YEAR_ASTC;
    data.source = make_shared<PixelMap>();
    data.dateTaken = "default value";
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_020, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::GenThumbnailEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_021, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::GenThumbnailEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_022, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::LCD;
    auto res = IThumbnailHelper::GenMonthAndYearAstcData(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_023, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoCreateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_024, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.isLocalFile = false;
    auto res = IThumbnailHelper::IsCreateThumbnailExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_025, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoRotateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_026, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::DoRotateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_027, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_028, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    data.loaderOpts.needUpload = true;
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_029, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.path = "/storage/cloud/files/";
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_030, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_031, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    int32_t fd = 0;
    ThumbnailType thumbType = ThumbnailType::THUMB;
    auto res = IThumbnailHelper::DoRotateThumbnailEx(opts, data, fd, thumbType);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_032, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_033, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.row = "a";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_034, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.table = "b";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_035, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.row = "a";
    opts.table = "b";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_036, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_001, TestSize.Level0)
{
    ThumbnailType type = ThumbnailType::MTH;
    auto res = ThumbnailUtils::GetThumbnailSuffix(type);
    EXPECT_EQ(res, "");
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_002, TestSize.Level0)
{
    ThumbnailType type = ThumbnailType::LCD;
    ThumbnailData data;
    auto res = ThumbnailUtils::DeleteThumbFile(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_003, TestSize.Level0)
{
    ThumbnailType type = ThumbnailType::LCD;
    ThumbnailData data;
    data.path = "/storage/cloud/files/";
    auto res = ThumbnailUtils::DeleteThumbFile(data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_004, TestSize.Level0)
{
    ThumbnailData data;
    auto res = ThumbnailUtils::DeleteThumbExDir(data);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_005, TestSize.Level0)
{
    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    ThumbnailData data;
    Size desiredSize;
    uint32_t errCode = 0;
    auto res = ThumbnailUtils::LoadAudioFileInfo(avMetadataHelper, data, desiredSize, errCode);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_006, TestSize.Level0)
{
    ThumbnailData data;
    Size desiredSize;
    auto res = ThumbnailUtils::LoadAudioFile(data, desiredSize);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_007, TestSize.Level0)
{
    string path = "";
    string suffix;
    string fileName;
    auto res = ThumbnailUtils::SaveFileCreateDir(path, suffix, fileName);
    EXPECT_EQ(res, 0);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_008, TestSize.Level0)
{
    ThumbnailData data;
    data.thumbnail.push_back(0x12);
    string fileName;
    uint8_t *output = data.thumbnail.data();
    int writeSize = 0;
    auto res = ThumbnailUtils::ToSaveFile(data, fileName, output, writeSize);
    EXPECT_EQ(res<0, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_009, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::MTH;
    auto res = ThumbnailUtils::TrySaveFile(data, type);
    EXPECT_EQ(res, -223);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_010, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::MTH_ASTC;
    data.monthAstc.push_back(1);
    data.monthAstc.resize(1);
    auto res = ThumbnailUtils::TrySaveFile(data, type);
    EXPECT_EQ(res, -1);
    ThumbnailType type2 = ThumbnailType::YEAR_ASTC;
    data.yearAstc.push_back(1);
    data.yearAstc.resize(1);
    auto res2 = ThumbnailUtils::TrySaveFile(data, type2);
    EXPECT_EQ(res2, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_011, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = ThumbnailUtils::TrySaveFile(data, type);
    EXPECT_EQ(res, -2302);
    ThumbnailType type2 = ThumbnailType::THUMB_ASTC;
    auto res2 = ThumbnailUtils::TrySaveFile(data, type2);
    EXPECT_EQ(res2, -2302);
    ThumbnailType type3 = ThumbnailType::LCD;
    auto res3 = ThumbnailUtils::TrySaveFile(data, type3);
    EXPECT_EQ(res3, -2302);
    ThumbnailType type4 = ThumbnailType::LCD_EX;
    auto res4 = ThumbnailUtils::TrySaveFile(data, type4);
    EXPECT_EQ(res4, -2302);
    ThumbnailType type5 = ThumbnailType::THUMB_EX;
    auto res5 = ThumbnailUtils::TrySaveFile(data, type5);
    EXPECT_EQ(res5, -2302);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_012, TestSize.Level0)
{
    ThumbnailData data;
    data.thumbnail.push_back(0x12);
    std::string suffix;
    uint8_t *output = data.thumbnail.data();
    int writeSize = 0;
    auto res = ThumbnailUtils::SaveThumbDataToLocalDir(data, suffix, output, writeSize);
    EXPECT_EQ(res<0, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_013, TestSize.Level0)
{
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    auto res = ThumbnailUtils::SaveAstcDataToKvStore(data, type);
    EXPECT_EQ(res, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_014, TestSize.Level0)
{
    ThumbnailData data;
    data.id = "a";
    data.dateTaken = "b";
    ThumbnailType type = ThumbnailType::MTH_ASTC;
    auto res = ThumbnailUtils::SaveAstcDataToKvStore(data, type);
    EXPECT_EQ(res >= 0, true);
    const ThumbnailType type2 = ThumbnailType::YEAR_ASTC;
    auto res2 = ThumbnailUtils::SaveAstcDataToKvStore(data, type2);
    EXPECT_EQ(res2 >= 0, true);
    const ThumbnailType type3 = ThumbnailType::LCD;
    auto res3 = ThumbnailUtils::SaveAstcDataToKvStore(data, type3);
    EXPECT_EQ(res3, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_015, TestSize.Level0)
{
    const std::string fieldId = "a";
    const std::string dateAdded;
    std::string key;
    auto res = ThumbnailUtils::GenerateKvStoreKey(fieldId, dateAdded, key);
    EXPECT_EQ(res, false);
    const std::string fieldId2 = "aaaaaaaaaa";
    const std::string dateAdded2 = "b";
    auto res2 = ThumbnailUtils::GenerateKvStoreKey(fieldId2, dateAdded2, key);
    EXPECT_EQ(res2, false);
    const std::string fieldId3 = "a";
    const std::string dateAdded3 = "bbbbbbbbbbbbbb";
    auto res3 = ThumbnailUtils::GenerateKvStoreKey(fieldId3, dateAdded3, key);
    EXPECT_EQ(res3, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_016, TestSize.Level0)
{
    const std::string fieldId = "a";
    const std::string dateAdded;
    std::string key;
    auto res = ThumbnailUtils::GenerateOldKvStoreKey(fieldId, dateAdded, key);
    EXPECT_EQ(res, false);
    const std::string fieldId2;
    const std::string dateAdded2 = "b";
    auto res2 = ThumbnailUtils::GenerateOldKvStoreKey(fieldId2, dateAdded2, key);
    EXPECT_EQ(res2, false);
    const std::string fieldId3;
    const std::string dateAdded3;
    auto res3 = ThumbnailUtils::GenerateOldKvStoreKey(fieldId3, dateAdded3, key);
    EXPECT_EQ(res3, false);
    const std::string fieldId4 = "aaaaaaaaaa";
    const std::string dateAdded4 = "b";
    auto res4 = ThumbnailUtils::GenerateOldKvStoreKey(fieldId4, dateAdded4, key);
    EXPECT_EQ(res4, false);
    const std::string fieldId5 = "a";
    const std::string dateAdded5 = "bbbbbbbbbbbbbb";
    auto res5 = ThumbnailUtils::GenerateOldKvStoreKey(fieldId5, dateAdded5, key);
    EXPECT_EQ(res5, false);
    const std::string fieldId6 = "a";
    const std::string dateAdded6 = "b";
    auto res6 = ThumbnailUtils::GenerateOldKvStoreKey(fieldId6, dateAdded6, key);
    EXPECT_EQ(res6, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_017, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    data.dateTaken = "a";
    auto res = ThumbnailUtils::CheckDateTaken(opts, data);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_018, TestSize.Level0)
{
    ThumbRdbOpt opts;
    const ThumbnailType type = ThumbnailType::LCD;
    auto res = ThumbnailUtils::DeleteAstcDataFromKvStore(opts, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_019, TestSize.Level0)
{
    ThumbnailData data;
    data.source = make_shared<PixelMap>();
    bool isSourceEx = false;
    auto res = ThumbnailUtils::ScaleThumbnailFromSource(data, isSourceEx);
    EXPECT_EQ(res, false);
    bool isSourceEx2 = true;
    auto res2 = ThumbnailUtils::ScaleThumbnailFromSource(data, isSourceEx2);
    EXPECT_EQ(res2, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_020, TestSize.Level0)
{
    NativeRdb::ValuesBucket values;
    Size size;
    size.height = 1;
    size.width = 0;
    const std::string column;
    ThumbnailUtils::SetThumbnailSizeValue(values, size, column);
    NativeRdb::ValuesBucket values2;
    Size size2;
    size2.height = 0;
    size2.width = 1;
    ThumbnailUtils::SetThumbnailSizeValue(values2, size2, column);
    EXPECT_NE(size.height, size2.height);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_021, TestSize.Level0)
{
    ThumbnailData data;
    auto res = ThumbnailUtils::DeleteBeginTimestampDir(data);
    EXPECT_EQ(res, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_022, TestSize.Level0)
{
    string path = "";
    string suffix;
    string fileName;
    string timeStamp = "1";
    auto res = ThumbnailUtils::SaveFileCreateDirHighlight(path, suffix, fileName, timeStamp);
    EXPECT_EQ(res, 0);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_001, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailType thumbType = ThumbnailType::LCD;
    auto res = ThumbnailGenerateHelper::GetThumbnailPixelMap(opts, thumbType);
    EXPECT_EQ(res, -2302);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_002, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, false);
    EXPECT_EQ(res, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_003, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = ThumbnailService::GetInstance()->rdbStorePtr_;
    opts.table = "test";
    auto res = ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, false);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_004, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = ThumbnailGenerateHelper::RestoreAstcDualFrame(opts);
    EXPECT_EQ(res, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, UpgradeThumbnailBackground_test_001, TestSize.Level0)
{
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    auto res = serverTest->UpgradeThumbnailBackground(false);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GenerateHighlightThumbnailBackground_test_001, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = ThumbnailGenerateHelper::GenerateHighlightThumbnailBackground(opts);
    EXPECT_EQ(res, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GenerateHighlightThumbnailBackground_test_002, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = ThumbnailService::GetInstance()->rdbStorePtr_;
    opts.table = "tab_analysis_video_label";
    auto res = ThumbnailGenerateHelper::GenerateHighlightThumbnailBackground(opts);
    EXPECT_EQ(res < 0, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GenerateHighlightThumbnailBackground_test_003, TestSize.Level0)
{
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    auto res = serverTest->GenerateHighlightThumbnailBackground();
    EXPECT_EQ(res < 0, true);
}
} // namespace Media
} // namespace OHOS