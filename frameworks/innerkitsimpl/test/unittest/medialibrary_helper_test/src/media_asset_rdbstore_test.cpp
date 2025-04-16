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

#include "media_asset_rdbstore_test.h"
#include "media_asset_rdbstore.h"

#include <unordered_set>

#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "photo_album_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaAssetRdbstoreTest::SetUpTestCase(void) {}
void MediaAssetRdbstoreTest::TearDownTestCase(void) {}
void MediaAssetRdbstoreTest::SetUp(void) {}
void MediaAssetRdbstoreTest::TearDown(void) {}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : CloudSyncTriggerFunc
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_CloudSyncTriggerFunc_Test_001, TestSize.Level0)
{
    std::vector<std::string> args;
    args.push_back("test_arg1");
    std::string ret;
    ret = MediaAssetRdbStore::CloudSyncTriggerFunc(args);
    EXPECT_EQ(ret, "true");
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : IsCallerSelfFunc
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_IsCallerSelfFunc_Test_001, TestSize.Level0)
{
    std::vector<std::string> args;
    args.push_back("test_arg1");
    args.push_back("test_arg2");
    std::string ret;
    ret = MediaAssetRdbStore::IsCallerSelfFunc(args);
    EXPECT_EQ(ret, "false");
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : PhotoAlbumNotifyFunc
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_PhotoAlbumNotifyFunc_Test_001, TestSize.Level0)
{
    std::vector<std::string> args;
    args.push_back("test_arg1");
    args.push_back("test_arg2");
    args.push_back("test_arg3");
    std::string ret;
    ret = MediaAssetRdbStore::PhotoAlbumNotifyFunc(args);
    EXPECT_EQ(ret, "");
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : TryGetRdbStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_TryGetRdbStore_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    bool test_value = true;
    int32_t ret = 0;
    ret = ptr->TryGetRdbStore(test_value);
    EXPECT_NE(ret, 0);
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : Query
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_Query_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    std::shared_ptr<DataShare::DataShareResultSet> ret = nullptr;
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    OperationObject object = OperationObject::UFM_PHOTO;
    int errCode;
    ret = ptr->Query(predicates, columns, object, errCode);
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : IsQueryAccessibleViaSandBox
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_IsQueryAccessibleViaSandBox_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    bool test_value = true;
    ptr->TryGetRdbStore(test_value);
    bool ret;
    string file = "/path/to/file";
    Uri fileUri(file);
    OperationObject object = OperationObject::UFM_PHOTO;
    DataShare::DataSharePredicates predicates;
    bool isIgnoreSELinux = true;
    ret = ptr->IsQueryAccessibleViaSandBox(fileUri, object, predicates, isIgnoreSELinux);
    EXPECT_NE(ret, true);
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : QueryRdb
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_QueryRdb_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    bool test_value = true;
    ptr->TryGetRdbStore(test_value);
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    OperationObject object = OperationObject::UFM_PHOTO;
    std::shared_ptr<NativeRdb::ResultSet> ret = ptr->QueryRdb(predicates, columns, object);
    EXPECT_EQ(ret, nullptr);
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : IsSupportSharedAssetQuery
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_IsSupportSharedAssetQuery_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    string file = "/path/to/file";
    Uri fileUri(file);
    bool test_value = true;
    ptr->TryGetRdbStore(test_value);
    OperationObject object = OperationObject::UFM_PHOTO;
    bool ret = ptr->IsSupportSharedAssetQuery(fileUri, object, test_value);
    EXPECT_NE(ret, true);
}

/*
 * Feature : MediaAssetRdbstoreTest
 * Function : QueryTimeIdBatch
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaAssetRdbstoreTest, MediaAssetRdbstoreTest_QueryTimeIdBatch_Test_001, TestSize.Level0)
{
    shared_ptr<MediaAssetRdbStore> ptr = make_shared<MediaAssetRdbStore>();
    ASSERT_NE(ptr, nullptr);
    int32_t start = 0;
    int32_t count = 1;
    std::vector<std::string> batchKeys;
    batchKeys.push_back("test");
    int32_t ret = ptr->QueryTimeIdBatch(start, count, batchKeys);
    EXPECT_NE(ret, 0);
}
} // namespace Media
} // namespace OHOS