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
#include "thumbnail_utils.h"
#include "thumbnail_service.h"
#include "medialibrary_db_const.h"
#include "medialibrary_utils_test.h"

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

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}
shared_ptr<NativeRdb::RdbStore> storePtr = nullptr;
void MediaLibraryExtUnitTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_utils_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    storePtr = store;
}
void MediaLibraryExtUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateRemotePath_test_001, TestSize.Level0)
{
    string path = "";
    string networkId = "";
    bool ret = ThumbnailUtils::UpdateRemotePath(path, networkId);
    EXPECT_EQ(ret, false);
    path = "medialib_UpdateRemotePath_test_001";
    networkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    ret = ThumbnailUtils::UpdateRemotePath(path, networkId);
    EXPECT_EQ(ret, false);
    path = MEDIA_DATA_DEVICE_PATH;
    ret = ThumbnailUtils::UpdateRemotePath(path, networkId);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GenThumbnailKey_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    bool ret = ThumbnailUtils::GenThumbnailKey(thumbnailData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GenLcdKey_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    bool ret = ThumbnailUtils::GenLcdKey(thumbnailData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryThumbnailSet_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string row = "medialib_QueryThumbnailSet_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = MEDIALIBRARY_TABLE,
        .row = row
    };

    auto resultSetPtr = ThumbnailUtils::QueryThumbnailSet(opts);
    EXPECT_NE(resultSetPtr, nullptr);
}


HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryThumbnailInfo_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string row = "medialib_QueryThumbnailInfo_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = MEDIALIBRARY_TABLE,
        .row = row
    };
    ThumbnailData data;
    int err  = 0;
    auto resultSetPtr = ThumbnailUtils::QueryThumbnailInfo(opts, data, err);
    EXPECT_EQ(resultSetPtr, nullptr);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryLcdCount_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = MEDIALIBRARY_TABLE
    };
    int outLcdCount = 0;
    int err = 0;
    bool ret = ThumbnailUtils::QueryLcdCount(opts, outLcdCount, err);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryDistributeLcdCount_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbRdbOpt opts = {
        .store = storePtr,
    };
    int outLcdCount = 0;
    int err = 0;
    bool ret = ThumbnailUtils::QueryDistributeLcdCount(opts, outLcdCount, err);
    EXPECT_EQ(ret, true);
}


HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryHasLcdFiles_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = MEDIALIBRARY_TABLE;
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryHasLcdFiles(opts, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryHasThumbnailFiles_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_QueryHasThumbnailFiles_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryHasThumbnailFiles(opts, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryAgingDistributeLcdInfos_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string udid = "medialib_QueryAgingDistributeLcdInfos_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .udid = udid
    };
    int LcdLimit = 0;
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryAgingDistributeLcdInfos(opts, LcdLimit, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryAgingLcdInfos_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_QueryAgingLcdInfos_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    int LcdLimit = 0;
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryAgingLcdInfos(opts, LcdLimit, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryNoLcdInfos_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_QueryNoLcdInfos_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    int LcdLimit = 0;
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryNoLcdInfos(opts, LcdLimit, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryNoThumbnailInfos_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_QueryNoThumbnailInfos_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryNoThumbnailInfos(opts, infos, err);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateThumbnailInfo_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string row = "medialib_UpdateThumbnailInfo_test_001";
    string table = "medialib_UpdateThumbnailInfo_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table,
        .row = row
    };
    ThumbnailData data;
    int err = 0;
    bool ret = ThumbnailUtils::UpdateThumbnailInfo(opts, data, err);
    EXPECT_EQ(ret, false);
    data.thumbnailKey = "UpdateThumbnailInfo";
    data.lcdKey = "key";
    ret = ThumbnailUtils::UpdateThumbnailInfo(opts, data, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateVisitTime_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbRdbOpt opts = {
        .store = storePtr,
        .networkId = "",
    };
    ThumbnailData data;
    int err = 0;
    bool ret = ThumbnailUtils::UpdateVisitTime(opts, data, err);
    EXPECT_EQ(ret, false);
    opts.networkId = "UpdateVisitTime";
    ret = ThumbnailUtils::UpdateVisitTime(opts, data, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryDeviceThumbnailRecords_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string udid = "medialib_QueryDeviceThumbnailRecords_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .udid = udid
    };
    vector<ThumbnailRdbData> infos;
    int err = 0;
    bool ret = ThumbnailUtils::QueryDeviceThumbnailRecords(opts, infos, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryRemoteThumbnail_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbnailData data;
    ThumbRdbOpt opts = {
    .store = storePtr,
    };
    int err = 0;
    bool ret = ThumbnailUtils::QueryRemoteThumbnail(opts, data, err);
    EXPECT_EQ(ret, false);
    opts.networkId = "medialib_QueryRemoteThumbnail_test";
    ret = ThumbnailUtils::QueryRemoteThumbnail(opts, data, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CleanThumbnailInfo_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbRdbOpt opts = {
    .store = storePtr,
    };
    bool withThumb = true;
    bool withLcd = true;
    bool ret = ThumbnailUtils::CleanThumbnailInfo(opts, withThumb, withLcd);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPushTable_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_SyncPushTable_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    vector<string> devices;
    bool isBlock = true;
    bool ret = ThumbnailUtils::SyncPushTable(opts, devices, isBlock);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPullTable_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    string table = "medialib_SyncPullTable_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table
    };
    vector<string> devices;
    bool isBlock = true;
    bool ret = ThumbnailUtils::SyncPullTable(opts, devices, isBlock);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ResizeImage_test_001, TestSize.Level0)
{
    vector<uint8_t> data;
    Size size;
    unique_ptr<PixelMap> pixelMap = nullptr;
    bool ret = ThumbnailUtils::ResizeImage(data, size, pixelMap);
    EXPECT_EQ(ret, false);
    data.push_back(8);
    ret = ThumbnailUtils::ResizeImage(data, size, pixelMap);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_WaitFor_test_001, TestSize.Level0)
{
    MediaLibrarySyncCallback mediaLibrary;
    bool ret = mediaLibrary.WaitFor();
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteLcdData_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    ThumbRdbOpt opts;
    bool ret = ThumbnailUtils::DeleteLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, false);
    thumbnailData.lcdKey = "DeleteLcdData";
    ret = ThumbnailUtils::DeleteLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, true);
    opts.networkId = "medialib_DeleteLcdData_test_001";
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    opts.kvStore = kvStorePtr;
    ret = ThumbnailUtils::DeleteLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteDistributeLcdData_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    ThumbRdbOpt opts;
    bool ret = ThumbnailUtils::DeleteDistributeLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, false);
    thumbnailData.lcdKey = "DeleteDistributeLcdData";
    ret = ThumbnailUtils::DeleteDistributeLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, true);
    opts.networkId = "medialib_DeleteDistributeLcdData_test_001";
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    opts.kvStore = kvStorePtr;
    ret = ThumbnailUtils::DeleteDistributeLcdData(opts, thumbnailData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ClearThumbnailAllRecord_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    ThumbRdbOpt opts;
    bool ret = ThumbnailUtils::ClearThumbnailAllRecord(opts, thumbnailData);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DoUpdateRemoteThumbnail_test_001, TestSize.Level0)
{
    ThumbnailData thumbnailData;
    ThumbRdbOpt opts;
    int err = 0;
    bool ret = ThumbnailUtils::DoUpdateRemoteThumbnail(opts, thumbnailData, err);
    EXPECT_EQ(ret, false);
    opts.networkId = "medialib_DoUpdateRemoteThumbnail_test_001";
    ret = ThumbnailUtils::DoUpdateRemoteThumbnail(opts, thumbnailData, err);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteOriginImage_test_001, TestSize.Level0)
{
    if (storePtr == nullptr) {
        exit(1);
    }
    ThumbnailData thumbnailData;
    string row = "medialib_DeleteOriginImage_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = MEDIALIBRARY_TABLE,
        .row = row
    };
    bool ret = ThumbnailUtils::DeleteOriginImage(opts, thumbnailData);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPullKvstore_test_001, TestSize.Level0)
{
    string key = "SyncPullKvstore";
    auto ret = ThumbnailUtils::SyncPullKvstore(nullptr, key, "");
    EXPECT_EQ(ret, DistributedKv::Status::ERROR);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    ret = ThumbnailUtils::SyncPullKvstore(kvStorePtr, key, "");
    EXPECT_EQ(ret, DistributedKv::Status::ERROR);
    string networkId = "Kvstore";
    ret = ThumbnailUtils::SyncPullKvstore(kvStorePtr, key, networkId);
    EXPECT_EQ(ret, DistributedKv::Status::ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SyncPushKvstore_test_001, TestSize.Level0)
{
    string key = "SyncPushKvstore";
    auto ret = ThumbnailUtils::SyncPushKvstore(nullptr, key, "");
    EXPECT_EQ(ret, DistributedKv::Status::ERROR);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    ret = ThumbnailUtils::SyncPushKvstore(kvStorePtr, key, "");
    EXPECT_EQ(ret, DistributedKv::Status::ERROR);
    string networkId = "Kvstore";
    ret = ThumbnailUtils::SyncPushKvstore(kvStorePtr, key, networkId);
    EXPECT_NE(ret, DistributedKv::Status::ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetKvResultSet_test_001, TestSize.Level0)
{
    string networkId = "medialib_GetKvResultSet_test_001";
    shared_ptr<DataShare::ResultSetBridge> outResultSet = nullptr;
    bool ret = ThumbnailUtils::GetKvResultSet(nullptr, "", networkId, outResultSet);
    EXPECT_EQ(ret, false);
    string key = "GetKvResultSet";
    ret = ThumbnailUtils::GetKvResultSet(nullptr, key, networkId, outResultSet);
    EXPECT_EQ(ret, false);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    ret = ThumbnailUtils::GetKvResultSet(kvStorePtr, key, networkId, outResultSet);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_RemoveDataFromKv_test_001, TestSize.Level0)
{
    bool ret = ThumbnailUtils::RemoveDataFromKv(nullptr, "");
    EXPECT_EQ(ret, false);
    string key = "RemoveDataFromKv";
    ret = ThumbnailUtils::RemoveDataFromKv(nullptr, key);
    EXPECT_EQ(ret, false);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    ret = ThumbnailUtils::RemoveDataFromKv(kvStorePtr, key);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsImageExist_test_001, TestSize.Level0)
{
    string networkId = "medialib_IsImageExist_test_001";
    bool ret = ThumbnailUtils::IsImageExist("", networkId, nullptr);
    EXPECT_EQ(ret, false);
    string key = "IsImageExist";
    ret = ThumbnailUtils::IsImageExist(key, networkId, nullptr);
    EXPECT_EQ(ret, false);
    shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = make_shared<MockSingleKvStore>();
    ret = ThumbnailUtils::IsImageExist(key, networkId, kvStorePtr);
    EXPECT_EQ(ret, false);
}

} // namespace Media
} // namespace OHOS