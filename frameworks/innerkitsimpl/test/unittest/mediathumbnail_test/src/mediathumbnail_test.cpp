/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "data_ability_helper.h"
#include "hilog/log.h"
#include "iservice_registry.h"
#include "mediathumbnail_test_cb.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_ability.h"
#include "mediathumbnail_test.h"
#include "media_log.h"
#include "permission/permission_kit.h"
#include "system_ability_definition.h"
#include <unistd.h>

using namespace std;
using namespace OHOS::NativeRdb;
using namespace testing::ext;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace OHOS {
namespace Media {
MediaLibraryDataAbility g_rdbStoreTest;
MediaLibraryThumbnail g_mediaThumbnail;
int g_index = 0;
int uid = 5010;
std::shared_ptr<AppExecFwk::DataAbilityHelper> medialibraryDataAbilityHelper = nullptr;
static const std::string DATABASE_NAME = "/" + MEDIA_DATA_ABILITY_DB_NAME;
static const std::string ABILITY_URI = Media::MEDIALIBRARY_DATA_URI;
static const std::string TEST_PIC_NAME = "test.jpg";
static const std::string TEST_PIC_PATH = "/storage/media/100/local/files/Pictures/test.jpg";
static const std::string TEST_PIC_PATH1 = "/storage/media/local/files/Pictures/test.jpg";
static const std::string TEST_VIDEO_NAME = "test.mp4";
static const std::string TEST_VIDEO_PATH = "/storage/media/100/local/files/Videos/test.mp4";
static const std::string TEST_VIDEO_PATH1 = "/storage/media/local/files/Videos/test.mp4";
static const std::string TEST_AUDIO_NAME = "test.mp3";
static const std::string TEST_AUDIO_PATH = "/storage/media/100/local/files/Audios/test.mp3";
static const std::string TEST_AUDIO_PATH1 = "/storage/media/local/files/Audios/test.mp3";
std::shared_ptr<RdbStore> store = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> CreateDataAHelper(
    int32_t systemAbilityId, std::shared_ptr<Uri> dataAbilityUri)
{
    MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateDataAHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return AppExecFwk::DataAbilityHelper::Creator(remoteObj, dataAbilityUri);
}
std::shared_ptr<AppExecFwk::DataAbilityHelper> CreateMediaLibraryHelper()
{
    if (medialibraryDataAbilityHelper == nullptr) {
        MEDIA_INFO_LOG("CreateMediaLibraryHelper ::medialibraryDataAbilityHelper == nullptr");
        std::shared_ptr<Uri> dataAbilityUri = std::make_shared<Uri>("dataability:///media");
        medialibraryDataAbilityHelper = CreateDataAHelper(uid, dataAbilityUri);
    }
    MEDIA_INFO_LOG("CreateMediaLibraryHelper ::medialibraryDataAbilityHelper != nullptr");
    return medialibraryDataAbilityHelper;
}
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "MediaThumbnailTest"};
} // namespace

int MediaThumbnailTestCB::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_MEDIA_TABLE);
}

int MediaThumbnailTestCB::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void MediaThumbnailTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);

    RdbStoreConfig config(DATABASE_NAME);
    MediaThumbnailTestCB callback;
    config.SetBundleName("com.ohos.medialibrary.MediaLibraryDataA");
    store = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(store, nullptr);
}

void MediaThumbnailTest::TearDownTestCase(void) { }

void MediaThumbnailTest::SetUp(void) { }

void MediaThumbnailTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

static int InsertRdbStore(int64_t &id, const string path)
{
    std::shared_ptr<RdbStore> &mstore = store;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    return mstore->Insert(id, MEDIALIBRARY_TABLE, values);
}

static void BuildBucket(const string name, const string path, MediaType mediaType,
                        NativeRdb::ValuesBucket &valuesBucket)
{
    string relativePath = "";
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, name);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
}

static int32_t InsertMediaData(NativeRdb::ValuesBucket &valuesBucket)
{
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    Uri createAssetUri(ABILITY_URI);
    return helper->Insert(createAssetUri, valuesBucket);
}

static int32_t CreateThumbnailInAbility(int32_t id)
{
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    Uri closeUri(ABILITY_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, "/" + to_string(id));
    return helper->Insert(closeUri, valuesBucket);
}
static bool PrepareThumbnail(const string name, const string path, MediaType mediaType, int32_t &id)
{
    NativeRdb::ValuesBucket valuesBucket;
    BuildBucket(name, path, mediaType, valuesBucket);
    id = InsertMediaData(valuesBucket);
    EXPECT_NE((id <= 0), true);
    if (id < 0) {
        HiLog::Error(LABEL, "Insert media data error");
        return false;
    }
    int res = CreateThumbnailInAbility(id);
    EXPECT_NE((res < 0), true);
    if (res < 0) {
        HiLog::Error(LABEL, "Create thumbnail in ability failed");
        return false;
    }
    return true;
}
static bool PreparePicThumbnail(int32_t &id)
{
    return PrepareThumbnail(TEST_PIC_NAME, TEST_PIC_PATH1, MEDIA_TYPE_IMAGE, id);
}
static bool PrepareAudioThumbnail(int32_t &id)
{
    return PrepareThumbnail(TEST_AUDIO_NAME, TEST_AUDIO_PATH1, MEDIA_TYPE_AUDIO, id);
}
static bool PrepareVideoThumbnail(int32_t &id)
{
    return PrepareThumbnail(TEST_VIDEO_NAME, TEST_VIDEO_PATH1, MEDIA_TYPE_VIDEO, id);
}
static std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> QueryMediaData(Uri &uri)
{
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = CreateMediaLibraryHelper();
    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns = {
        Media::MEDIA_DATA_DB_ID, Media::MEDIA_DATA_DB_THUMBNAIL, Media::MEDIA_DATA_DB_LCD,
    };
    return helper->Query(uri, columns, predicates);
}

static std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> QueryThumbnailData(int id, Size &size)
{
    Uri queryUri(ABILITY_URI  + "/" + to_string(id) + "?" +
                 Media::MEDIA_OPERN_KEYWORD + "=" + Media::MEDIA_DATA_DB_THUMBNAIL + "&" +
                 Media::MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" +
                 Media::MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height));
    return QueryMediaData(queryUri);
}

static int ParseThumbnailResult(std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> &querySet,
                                std::string &id, std::string &thumb, std::string &lcd)
{
    int rowCount = 0;
    if (querySet == nullptr) {
        HiLog::Error(LABEL, "Query media data is empty");
        return rowCount;
    }

    querySet->GoToFirstRow();
    querySet->GetRowCount(rowCount);
    HiLog::Debug(LABEL, "Query with row %{private}d", rowCount);
    if (rowCount == 0) {
        return rowCount;
    }
    int idClumnIndex, thumbClumnIndex, lcdClumnIndex;
    int indexRet = querySet->GetColumnIndex(Media::MEDIA_DATA_DB_ID, idClumnIndex);
    indexRet = querySet->GetColumnIndex(Media::MEDIA_DATA_DB_THUMBNAIL, thumbClumnIndex);
    indexRet = querySet->GetColumnIndex(Media::MEDIA_DATA_DB_LCD, lcdClumnIndex);
    HiLog::Debug(LABEL, "Query with idClumnIndex %{public}d", idClumnIndex);
    HiLog::Debug(LABEL, "Query with thumbClumnIndex %{public}d", thumbClumnIndex);
    HiLog::Debug(LABEL, "Query with lcdClumnIndex %{public}d", lcdClumnIndex);
    int ret = querySet->GetString(idClumnIndex, id);
    ret = querySet->GetString(thumbClumnIndex, thumb);
    ret = querySet->GetString(lcdClumnIndex, lcd);
    HiLog::Debug(LABEL, "Query with id %{public}s", id.c_str());
    HiLog::Debug(LABEL, "Query with thumb %{public}s", thumb.c_str());
    HiLog::Debug(LABEL, "Query with lcd %{public}s", lcd.c_str());
    return rowCount;
}

static std::unique_ptr<PixelMap> GetThumbnail(std::string &thumb, std::string &lcd, Size &size)
{
    bool fromLcd = g_mediaThumbnail.isThumbnailFromLcd(size);
    return g_mediaThumbnail.GetThumbnail(fromLcd?lcd:thumb, size);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_NE(res, false);
    EXPECT_NE(key.empty(), true);
}


HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_1, TestSize.Level0)
{
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = store,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_NE(res, false);
    EXPECT_NE(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_2, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = "",
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_3, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(-1),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_4, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id + 1),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_5, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = "INVAIL",
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001_6, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = "",
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_NE(res, false);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_1, TestSize.Level0)
{
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(1, id);

    ThumbRdbOpt opts = {
        .store = store,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_NE(res, false);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_2, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = "",
        .row = to_string(id),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_3, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(-1),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_4, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = to_string(id + 1),
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_5, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = "INVAIL",
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002_6, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;
    int64_t id = 0;

    int ret = InsertRdbStore(id, TEST_PIC_PATH);
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(0, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = "",
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateLcd(opts, key);

    EXPECT_EQ(res, false);
    EXPECT_EQ(key.empty(), true);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003, TestSize.Level0)
{
    Size size = {
        .width = 56, .height = 56
    };
    if (!PreparePicThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003_1, TestSize.Level0)
{
    Size size = {
        .width = 300, .height = 300
    };
    if (!PreparePicThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), true);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003_2, TestSize.Level0)
{
    Size size;
    if (!PreparePicThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003_3, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 56, .height = 56
    };
    if (!PreparePicThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003_4, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 300, .height = 300
    };
    if (!PreparePicThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004, TestSize.Level0)
{
    Size size = {
        .width = 56, .height = 56
    };
    if (!PrepareAudioThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), false);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004_1, TestSize.Level0)
{
    Size size = {
        .width = 300, .height = 300
    };
    if (!PrepareAudioThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), true);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004_2, TestSize.Level0)
{
    Size size;
    if (!PrepareAudioThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004_3, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 56, .height = 56
    };
    if (!PrepareAudioThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004_4, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 300, .height = 300
    };
    if (!PrepareAudioThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_005, TestSize.Level0)
{
    Size size = {
        .width = 56, .height = 56
    };
    if (!PrepareVideoThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), false);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_005_1, TestSize.Level0)
{
    Size size = {
        .width = 300, .height = 300
    };
    if (!PrepareVideoThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
    if (thumbnailRes == nullptr) {
        HiLog::Error(LABEL, "Query thumbnail data failed");
        return;
    }
    std::string id, thumbnailKey, lcdKey;
    int count = ParseThumbnailResult(thumbnailRes, id, thumbnailKey, lcdKey);
    EXPECT_NE(count, 0);
    if (count == 0) {
        HiLog::Error(LABEL, "Query thumbnail data empty");
        return;
    }
    EXPECT_EQ(to_string(g_index), id);
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), true);

    auto pixelmap = GetThumbnail(thumbnailKey, lcdKey, size);
    if (pixelmap != nullptr) {
        EXPECT_EQ(pixelmap->GetWidth(), size.width);
        EXPECT_EQ(pixelmap->GetHeight(), size.height);
    }
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_005_2, TestSize.Level0)
{
    Size size;
    if (!PrepareVideoThumbnail(g_index)) {
        return;
    }
    auto thumbnailRes = QueryThumbnailData(g_index, size);
    EXPECT_NE(thumbnailRes, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_005_3, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 56, .height = 56
    };
    if (!PrepareVideoThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_005_4, TestSize.Level0)
{
    string empty;
    Size size = {
        .width = 300, .height = 300
    };
    if (!PrepareVideoThumbnail(g_index)) {
        return;
    }

    auto pixelmap = GetThumbnail(empty, empty, size);
    EXPECT_EQ(pixelmap, nullptr);
}
} // namespace Media
} // namespace OHOS