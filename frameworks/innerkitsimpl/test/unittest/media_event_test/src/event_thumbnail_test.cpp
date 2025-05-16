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
#define MLOG_TAG "EventThumbTest"

#include "event_thumbnail_test.h"

#define private public
#include "thumbnail_service.h"
#include "thumbnail_utils.h"
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
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

int ConfigTestOpenCall::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCall::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

shared_ptr<MediaLibraryRdbStore> storePtr = nullptr;

void EventThumbnailTest::SetUpTestCase(void)
{
    const string dbPath = "/data/test/medialibrary_utils_test.db";
    NativeRdb::RdbStoreConfig config(dbPath);
    ConfigTestOpenCall helper;
    int32_t ret = MediaLibraryUnitTestUtils::InitUnistore(config, 1, helper);
    EXPECT_EQ(ret, E_OK);
    storePtr = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(storePtr, nullptr);
}

void EventThumbnailTest::TearDownTestCase(void)
{
    MediaLibraryUnitTestUtils::StopUnistore();
}

// SetUp:Execute before each test case
void EventThumbnailTest::SetUp() {}

void EventThumbnailTest::TearDown(void) {}

HWTEST_F(EventThumbnailTest, medialib_event_GetThumbnail_test_001, TestSize.Level1)
{
    shared_ptr<ThumbnailService> serverTest = ThumbnailService::GetInstance();
    string uri = "";
    auto fd = serverTest->GetThumbnailFd(uri);
    EXPECT_LT(fd, 0);
    serverTest->ReleaseService();
}

HWTEST_F(EventThumbnailTest, medialib_event_CacheLcdInfo_test_001, TestSize.Level1)
{
    string row = "medialib_CacheLcdInfo_test_001";
    string table = "medialib_CacheLcdInfo_test_001";
    ThumbRdbOpt opts = {
        .store = storePtr,
        .table = table,
        .row = row
    };
    ThumbnailData data;
    int err = 0;
    bool ret = ThumbnailUtils::CacheLcdInfo(opts, data);
    EXPECT_EQ(ret, false);
}

HWTEST_F(EventThumbnailTest, medialib_event_UpdateVisitTime_test_001, TestSize.Level1)
{
    ThumbRdbOpt opts = {
        .store = storePtr,
        .networkId = "",
    };
    ThumbnailData data;
    int err = 0;
    bool ret = ThumbnailUtils::UpdateVisitTime(opts, data, err);
    EXPECT_EQ(ret, false);
}
}
}