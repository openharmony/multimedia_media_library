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

#define MLOG_TAG "MediaCloudSync"

#include "cloud_media_data_client_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "media_log.h"
#include "database_data_mock.h"
#include "cloud_media_data_client.h"
#include "photos_dao.h"
#include "get_self_permissions.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {
DatabaseDataMock CloudMediaDataClientTest::dbDataMock_;
std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
void CloudMediaDataClientTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    // Get RdbStore
    int32_t errorCode = 0;
    rdbStore_ = MediaLibraryDatabase().GetRdbStore(errorCode);
    int32_t ret = dbDataMock_.SetRdbStore(rdbStore_).CheckPoint();
    ret = dbDataMock_.MockData(CloudMediaDataClientTest::GetTableMockInfoList());
    GTEST_LOG_(INFO) << "SetUpTestCase ret: " << ret;
}

void CloudMediaDataClientTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    bool ret = dbDataMock_.Rollback();
    GTEST_LOG_(INFO) << "TearDownTestCase ret: " << ret;
}

// SetUp:Execute before each test case
void CloudMediaDataClientTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    std::vector<std::string> perms;
    perms.push_back("ohos.permission.READ_ALL_PHOTO");
    perms.push_back("ohos.permission.WRITE_ALL_PHOTO");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("CloudMediaDataClientTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
}

void CloudMediaDataClientTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}
}  // namespace OHOS::Media::CloudSync