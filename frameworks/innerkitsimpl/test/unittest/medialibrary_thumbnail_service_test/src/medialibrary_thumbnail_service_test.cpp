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
#undef private

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
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

const int32_t E_THUMBNAIL_ASTC_ALL_EXIST = -2307;
const int32_t E_THUMBNAIL_LCD_ALL_EXIST = -2308;

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}
shared_ptr<NativeRdb::RdbStore> storePtr = nullptr;
void MediaLibraryThumbnailServiceTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_thumbnail_service_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    storePtr = store;
}
void MediaLibraryThumbnailServiceTest::TearDownTestCase(void) {}

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
    EXPECT_EQ(ret, E_THUMBNAIL_LCD_ALL_EXIST);
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
    EXPECT_EQ(result, E_THUMBNAIL_ASTC_ALL_EXIST);
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
    data.dateAdded = "default value";
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_019, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::YEAR_ASTC;
    data.source = make_shared<PixelMap>();
    data.dateAdded = "default value";
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

} // namespace Media
} // namespace OHOS