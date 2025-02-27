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
#include "medialibrary_thumbnail_service_test.h"
#define private public
#include "thumbnail_service.h"
#include "ithumbnail_helper.h"
#include "thumbnail_generate_helper.h"
#undef private
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "vision_db_sqls.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
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
shared_ptr<ThumbnailService> serverTest = nullptr;

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        MEDIALIBRARY_TABLE,
        VISION_VIDEO_LABEL_TABLE,
        AudioColumn::AUDIOS_TABLE,
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = storePtr->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        CREATE_TAB_ANALYSIS_VIDEO_LABEL,
        CREATE_MEDIA_TABLE,
        AudioColumn::CREATE_AUDIO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = storePtr->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void MediaLibraryThumbnailServiceTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_thumbnail_service_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    EXPECT_EQ(ret, E_OK);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(storePtr, nullptr);
    SetTables();
}

void MediaLibraryThumbnailServiceTest::TearDownTestCase(void)
{
    CleanTestTables();
    MediaLibraryUnitTestUtils::StopUnistore();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MediaLibraryThumbnailServiceTest::SetUp()
{
    if (storePtr == nullptr) {
        exit(1);
    }
    serverTest = ThumbnailService::GetInstance();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    #ifdef DISTRIBUTED
        shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
        serverTest->Init(storePtr, kvStorePtr, context);
    #else
        serverTest->Init(storePtr, context);
    #endif
}

void MediaLibraryThumbnailServiceTest::TearDown(void)
{
    serverTest->ReleaseService();
}

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
    EXPECT_EQ(ret, 0);
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
    EXPECT_NE(ret, 0);
    serverTest->ReleaseService();
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_InterruptBgworker_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    EXPECT_NE(serverTest, nullptr);
    serverTest->InterruptBgworker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
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
    EXPECT_NE(serverTest, nullptr);
    serverTest->StopAllWorker();
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    EXPECT_NE(kvStorePtr, nullptr);
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
    EXPECT_NE(serverTest, nullptr);
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
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
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
    WaitStatus status;
    auto ret = IThumbnailHelper::DoCreateLcd(opts, data, status);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_010, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
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
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
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
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_016, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_017, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType type = ThumbnailType::THUMB_ASTC;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::GenThumbnail(opts, data, type);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_018, TestSize.Level0)
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

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_019, TestSize.Level0)
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
    WaitStatus status;
    auto res = IThumbnailHelper::DoCreateThumbnail(opts, data, status);
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
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::DoRotateThumbnail(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_027, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_028, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    data.loaderOpts.needUpload = true;
    auto res = IThumbnailHelper::DoCreateAstc(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_029, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    WaitStatus status;
    data.path = "/storage/cloud/files/";
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data, status);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_030, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    WaitStatus status;
    auto res = IThumbnailHelper::DoCreateAstcEx(opts, data, status);
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
    EXPECT_EQ(res, -1);
    const ThumbnailType type2 = ThumbnailType::YEAR_ASTC;
    auto res2 = ThumbnailUtils::SaveAstcDataToKvStore(data, type2);
    EXPECT_EQ(res2, -1);
    const ThumbnailType type3 = ThumbnailType::LCD;
    auto res3 = ThumbnailUtils::SaveAstcDataToKvStore(data, type3);
    EXPECT_EQ(res3, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_utils_test_015, TestSize.Level0)
{
    ThumbnailData data;
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = PhotoColumn::PHOTOS_TABLE,
    };
    vector<ThumbnailData> infos;
    int err;
    auto res = ThumbnailUtils::QueryLocalNoThumbnailInfos(opts, infos, err);
    EXPECT_EQ(res, true);
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
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
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
    auto res = ThumbnailGenerateHelper::RestoreAstcDualFrame(opts);
    EXPECT_EQ(res, -1);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, UpgradeThumbnailBackground_test_001, TestSize.Level0)
{
    auto res = serverTest->UpgradeThumbnailBackground(false);
    EXPECT_EQ(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GenerateHighlightThumbnailBackground_test_001, TestSize.Level0)
{
    auto res = serverTest->GenerateHighlightThumbnailBackground();
    EXPECT_EQ(res, E_OK);
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
    EXPECT_EQ(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, LocalThumbnailGeneration_test_001, TestSize.Level0)
{
    auto res = serverTest->LocalThumbnailGeneration();
    EXPECT_EQ(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_023, TestSize.Level0)
{
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    bool isSourceEx = true;
    std::shared_ptr<Picture> pictureEx = Picture::Create(pixelMap);
    data.source.SetPictureEx(pictureEx);
    std::string tempOutputPath;
    auto res = ThumbnailUtils::CompressPicture(data, isSourceEx, tempOutputPath);
    EXPECT_EQ(res, false);
    bool isSourceEx2 = false;
    auto res2 = ThumbnailUtils::CompressPicture(data, isSourceEx2, tempOutputPath);
    EXPECT_EQ(res2, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_024, TestSize.Level0)
{
    ThumbnailData data;
    ThumbRdbOpt opts;
    auto res = ThumbnailUtils::DoUpdateAstcDateTaken(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_025, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = ThumbnailUtils::DoDeleteMonthAndYearAstc(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_026, TestSize.Level0)
{
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    ThumbRdbOpt opts;
    auto res = ThumbnailUtils::CheckDateTaken(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_027, TestSize.Level0)
{
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    ThumbRdbOpt opts;
    auto res = ThumbnailUtils::CheckDateTaken(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_028, TestSize.Level0)
{
    auto res = ThumbnailUtils::CheckCloudThumbnailDownloadFinish(storePtr);
    EXPECT_EQ(res, false);
    const string dbPath = "/data/test/medialibrary_thumbnail_service_test_db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    auto res2 = ThumbnailUtils::CheckCloudThumbnailDownloadFinish(storePtr);
    EXPECT_EQ(res2, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_029, TestSize.Level0)
{
    const string dbPath = "/data/test/medialibrary_thumbnail_service_test_db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    vector<ThumbnailData> infos;
    const std::string table = "Photos";
    auto res = ThumbnailUtils::QueryOldKeyAstcInfos(storePtr, table, infos);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_032, TestSize.Level0)
{
    ThumbnailData data;
    ThumbRdbOpt opts;
    int32_t err = E_ERR;
    auto res = ThumbnailUtils::UpdateLcdReadyStatus(opts, data, err, LcdReady::GENERATE_LCD_COMPLETED);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_005, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    auto res = ThumbnailGenerateHelper::GenerateHighlightThumbnailBackground(opts);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_006, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    int32_t timeStamp = 100;
    int32_t type = 1;
    auto res = ThumbnailGenerateHelper::GetKeyFrameThumbnailPixelMap(opts, timeStamp, type);
    EXPECT_NE(res, E_ERR);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_007, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    ThumbnailData data;data.path = "path";
    data.timeStamp = "timeStamp";
    int32_t thumbType = 1;
    std::string fileName;
    auto res = ThumbnailGenerateHelper::GetAvailableKeyFrameFile(opts, data, thumbType, fileName);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_008, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    opts.table = "test";
    auto res = ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, false);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_009, TestSize.Level0)
{
    ThumbRdbOpt opts;
    NativeRdb::RdbPredicates predicate{PhotoColumn::PHOTOS_TABLE};
    int32_t requestId = 1;
    auto res = ThumbnailGenerateHelper::CreateAstcBatchOnDemand(opts, predicate, requestId);
    EXPECT_EQ(res, E_ERR);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_010, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    ThumbnailType thumbType = ThumbnailType::THUMB_ASTC;
    std::string fileName;
    auto res = ThumbnailGenerateHelper::GetAvailableFile(opts, data, thumbType, fileName);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_011, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    int32_t thumbType = 2;
    std::string fileName;
    auto res = ThumbnailGenerateHelper::GetAvailableKeyFrameFile(opts, data, thumbType, fileName);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_012, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    std::string id = "id";
    std::string tracks = "tracks";
    std::string trigger = "trigger";
    std::string genType = "update";
    auto res = ThumbnailGenerateHelper::TriggerHighlightThumbnail(opts, id, tracks, trigger, genType);
    EXPECT_EQ(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, thumbnail_generate_helper_test_013, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    auto res = ThumbnailGenerateHelper::RestoreAstcDualFrame(opts);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_037, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    opts.row = "row";
    opts.table = "table";
    auto res = IThumbnailHelper::IsPureCloudImage(opts);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_038, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    ThumbnailData data;
    data.path = "/storage/cloud/files/";
    auto res = IThumbnailHelper::UpdateSuccessState(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_039, TestSize.Level0)
{
    ThumbRdbOpt opts;
    opts.store = storePtr;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::IsCreateThumbnailSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_040, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMapEX = std::make_shared<PixelMap>();
    data.source.SetPixelMapEx(pixelMapEX);
    auto res = IThumbnailHelper::GenThumbnailEx(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_041, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
    std::shared_ptr<PixelMap> pixelMapEX = std::make_shared<PixelMap>();
    data.source.SetPixelMapEx(pixelMapEX);
    res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
    std::shared_ptr<Picture> picture = Picture::Create(pixelMap);
    data.source.SetPicture(picture);
    res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_042, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    data.source.SetPixelMap(pixelMap);
    std::shared_ptr<PixelMap> pixelMapEX = std::make_shared<PixelMap>();
    data.source.SetPixelMapEx(pixelMapEX);
    auto res = IThumbnailHelper::IsCreateLcdExSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumbnail_helper_test_043, TestSize.Level0)
{
    ThumbRdbOpt opts;
    ThumbnailData data;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    std::shared_ptr<Picture> picture = Picture::Create(pixelMap);
    data.source.SetPicture(picture);
    auto res = IThumbnailHelper::IsCreateLcdSuccess(opts, data);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GetThumbFd_test_001, TestSize.Level0)
{
    string path = " ";
    string table = PhotoColumn::PHOTOS_TABLE;
    string id = "0";
    string uri = " ";
    Size desiredSize;
    bool isAstc = false;
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int res = serverTest->GetThumbFd(path, table, id, uri, desiredSize, isAstc);
    EXPECT_EQ(res < 0, true);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GetKeyFrameThumbFd_test_001, TestSize.Level0)
{
    string path = " ";
    string table = PhotoColumn::PHOTOS_TABLE;
    string id = "0";
    string uri = " ";
    int32_t beginStamp = 0;
    int32_t type = 1;
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    shared_ptr<OHOS::AbilityRuntime::Context> context;
    serverTest->Init(storePtr, context);
    int32_t res = serverTest->GetKeyFrameThumbFd(path, table, id, uri, beginStamp, type);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, GetAgingDataSize_test_001, TestSize.Level0)
{
    int64_t time = -100;
    int count = 0;
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    int32_t res = serverTest->GetAgingDataSize(time, count);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, CreateAstcCloudDownload_test_001, TestSize.Level0)
{
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    string id = "invalidId";
    bool isCloudInsertTaskPriorityHigh = false;
    int32_t res = serverTest->CreateAstcCloudDownload(id, isCloudInsertTaskPriorityHigh);
    EXPECT_NE(res, E_OK);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_031, TestSize.Level0)
{
    ThumbnailData data;
    ThumbRdbOpt opts;
    opts.store = storePtr;
    int32_t err = E_ERR;
    auto res = ThumbnailUtils::UpdateLcdReadyStatus(opts, data, err, LcdReady::GENERATE_LCD_COMPLETED);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_033, TestSize.Level0)
{
    ThumbnailData data;
    Size desiredSize;
    auto res = ThumbnailUtils::GenTargetPixelmap(data, desiredSize);
    EXPECT_EQ(res, false);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_034, TestSize.Level0)
{
    ThumbRdbOpt opts;
    auto res = ThumbnailUtils::QueryThumbnailSet(opts);
    EXPECT_EQ(res, nullptr);
}

HWTEST_F(MediaLibraryThumbnailServiceTest, medialib_thumnail_utils_test_035, TestSize.Level0)
{
    ThumbRdbOpt opts;
    int outLcdCount = 0;
    int err = E_ERR;
    auto res = ThumbnailUtils::QueryLcdCount(opts, outLcdCount, err);
    EXPECT_EQ(res, false);
}
} // namespace Media
} // namespace OHOS